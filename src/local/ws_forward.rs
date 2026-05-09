use crate::{
    crypto::{Cipher, default_token, package_info},
    local::build_full_url,
    options::{DEFAULT_CHUNK, LocalModeOptions},
};
use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response, Version,
    body::{Bytes, Incoming},
    http::request::Parts,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::TcpStream,
    sync::{Mutex, mpsc, oneshot},
    task::JoinHandle,
    time::sleep,
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config, tungstenite::Message, tungstenite::protocol::WebSocketConfig};
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Connected,
    Disconnected,
    Reconnecting,
}

pub(crate) struct WsConnectionManager {
    sink: Arc<Mutex<WsSink>>,
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>>,
    state: Arc<Mutex<ConnectionState>>,
    reconnect_tx: mpsc::Sender<()>,
}

impl WsConnectionManager {
    pub(crate) async fn new(remote_addr: &str, proxy: Option<&str>) -> Result<Self> {
        let (reconnect_tx, reconnect_rx) = mpsc::channel(1);

        let remote_addr = remote_addr.to_string();
        let proxy = proxy.map(|s| s.to_string());

        let state = Arc::new(Mutex::new(ConnectionState::Connected));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let ping_handle: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::new(Mutex::new(None));

        // Initial connection
        let (sink, reader) = Self::connect(&remote_addr, proxy.as_deref()).await?;
        let sink = Arc::new(Mutex::new(sink));

        // Spawn initial ping keepalive task
        *ping_handle.lock().await = Some(Self::spawn_ping_task(sink.clone()));

        {
            // Spawn reader task
            let pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>> = pending.clone();
            let state = state.clone();
            tokio::spawn(async move {
                Self::reader_loop(reader, pending, state).await;
            });
        }

        {
            // Spawn reconnection handler
            let sink_clone = sink.clone();
            let pending = pending.clone();
            let state = state.clone();
            let remote_addr = remote_addr.clone();
            let proxy = proxy.clone();
            let ping_handle_clone = ping_handle.clone();
            tokio::spawn(async move {
                Self::reconnection_handler(
                    reconnect_rx,
                    sink_clone,
                    pending,
                    state,
                    remote_addr,
                    proxy,
                    ping_handle_clone,
                )
                .await;
            });
        }

        Ok(Self {
            sink,
            pending,
            state,
            reconnect_tx,
        })
    }

    async fn connect(remote_addr: &str, proxy: Option<&str>) -> Result<(WsSink, WsReader)> {
        let ws_url = remote_addr
            .replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1);

        if remote_addr.starts_with("http://") {
            warn!(
                "Using websocket may use https:// to connect to wss://, which is necessary for dhproxy"
            );
        }

        debug!("Connecting to WebSocket: {}", ws_url);

        let ws = if let Some(proxy_url) = proxy {
            debug!("Using proxy: {}", proxy_url);
            // Connect through HTTP proxy
            Self::connect_via_proxy(&ws_url, proxy_url)
                .await
                .context("connect websocket via proxy error")?
        } else {
            // Direct connection
            if ws_url.starts_with("wss://") {
                use tokio_native_tls::{TlsConnector, native_tls};

                let ws_uri: hyper::Uri = ws_url.parse()?;
                let host = ws_uri.host().ok_or_else(|| anyhow!("no host in ws url"))?;
                let port = ws_uri.port_u16().unwrap_or(443);
                let cx = native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?;
                let cx = TlsConnector::from(cx);
                let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
                let tls_stream = cx.connect(host, stream).await?;
                let maybe_tls = MaybeTlsStream::NativeTls(tls_stream);
                let mut cfg = WebSocketConfig::default();
                cfg.max_message_size = None;
                cfg.max_frame_size = None;
                let (ws, _) = tokio_tungstenite::client_async_with_config(ws_url.clone(), maybe_tls, Some(cfg))
                    .await
                    .context("connect websocket directly error")?;
                ws
            } else {
                let mut cfg = WebSocketConfig::default();
                cfg.max_message_size = None;
                cfg.max_frame_size = None;
                let (ws, _) = connect_async_with_config(&ws_url, Some(cfg), false)
                    .await
                    .context("connect websocket directly error")?;
                ws
            }
        };

        info!("WebSocket connection established to {}", ws_url);

        Ok(ws.split())
    }

    async fn connect_via_proxy(ws_url: &str, proxy_url: &str) -> Result<WsStream> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Parse WebSocket URL
        let ws_uri: hyper::Uri = ws_url.parse()?;
        let host = ws_uri.host().ok_or_else(|| anyhow!("no host in ws url"))?;
        let port = ws_uri
            .port_u16()
            .unwrap_or(if ws_url.starts_with("wss://") {
                443
            } else {
                80
            });

        // Parse proxy URL
        let proxy_uri: hyper::Uri = proxy_url.parse()?;
        let proxy_host = proxy_uri
            .host()
            .ok_or_else(|| anyhow!("no host in proxy url"))?;
        let proxy_port = proxy_uri.port_u16().unwrap_or(8080);

        debug!("Connecting to proxy {}:{}", proxy_host, proxy_port);
        // Connect to proxy
        let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await?;
        debug!("Connected to proxy, sending CONNECT for {}:{}", host, port);

        // Send CONNECT request
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, port, host, port
        );
        stream.write_all(connect_req.as_bytes()).await?;

        // Read CONNECT response - need to consume all headers until \r\n\r\n
        let mut response_buf = Vec::new();
        let mut buf = [0u8; 1];

        // Read until we find \r\n\r\n (end of headers)
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                bail!("Connection closed while reading CONNECT response");
            }
            response_buf.push(buf[0]);

            // Check for \r\n\r\n pattern
            if response_buf.len() >= 4 {
                let len = response_buf.len();
                if &response_buf[len - 4..] == b"\r\n\r\n" {
                    break;
                }
            }
        }

        let response = String::from_utf8_lossy(&response_buf);
        trace!(
            "Proxy CONNECT full response:\n{}\n{:02x?}",
            response, response_buf
        );

        // Check for 200 status in any HTTP version
        let first_line = response.lines().next().unwrap_or("");
        if !first_line.starts_with("HTTP/1.1 200")
            && !first_line.starts_with("HTTP/1.0 200")
            && !first_line.starts_with("HTTP/2.0 200")
        {
            return Err(anyhow!("Proxy CONNECT failed: {}", first_line));
        }

        debug!("Proxy CONNECT successful, establishing WebSocket");

        // Now establish WebSocket over the tunneled connection
        if ws_url.starts_with("wss://") {
            // For wss://, wrap in TLS using native-tls
            use tokio_native_tls::{TlsConnector, native_tls};

            debug!("Establishing TLS connection");
            let cx = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()?;
            let cx = TlsConnector::from(cx);
            let tls_stream = cx.connect(host, stream).await?;

            debug!("TLS established, performing WebSocket handshake");
            // Wrap in MaybeTlsStream
            let maybe_tls = MaybeTlsStream::NativeTls(tls_stream);
            let mut cfg = WebSocketConfig::default();
            cfg.max_message_size = None;
            cfg.max_frame_size = None;
            let (ws, resp) = tokio_tungstenite::client_async_with_config(ws_url, maybe_tls, Some(cfg))
                .await
                .context("websocket tls connect error")?;
            debug!("WebSocket handshake response status: {:?}", resp.status());
            Ok(ws)
        } else {
            debug!("Performing WebSocket handshake (plain)");
            // For ws://, use plain connection wrapped in MaybeTlsStream
            let maybe_tls = MaybeTlsStream::Plain(stream);
            let mut cfg = WebSocketConfig::default();
            cfg.max_message_size = None;
            cfg.max_frame_size = None;
            let (ws, resp) = tokio_tungstenite::client_async_with_config(ws_url, maybe_tls, Some(cfg))
                .await
                .context("websocket connect error")?;
            debug!("WebSocket handshake response status: {:?}", resp.status());
            Ok(ws)
        }
    }

    async fn reader_loop(
        mut reader: WsReader,
        pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>>,
        state: Arc<Mutex<ConnectionState>>,
    ) {
        loop {
            match reader.next().await {
                Some(Ok(Message::Binary(data))) => {
                    if data.len() < 17 || data[0] != 0x03 {
                        continue;
                    }
                    let uuid_bytes: [u8; 16] = match data[1..17].try_into() {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let uuid = Uuid::from_bytes(uuid_bytes);
                    let response_data = data[17..].to_vec();

                    let mut pending = pending.lock().await;
                    if let Some(tx) = pending.remove(&uuid) {
                        let _ = tx.send(response_data);
                    }
                }
                Some(Ok(Message::Close(_))) => {
                    warn!("WebSocket closed by remote");
                    break;
                }
                Some(Err(e)) => {
                    warn!("WebSocket error: {e:?}");
                    break;
                }
                None => {
                    warn!("WebSocket stream ended (connection lost)");
                    break;
                }
                _ => {}
            }
        }

        // Connection lost — mark disconnected and fail all pending requests.
        // Reconnect will be triggered lazily by the next send_request call.
        *state.lock().await = ConnectionState::Disconnected;

        let mut pending = pending.lock().await;
        let count = pending.len();
        if count > 0 {
            warn!("Dropping {count} pending WebSocket request(s) due to disconnection");
            pending.clear(); // Dropping senders causes receivers to get RecvError
        }
    }

    /// Spawn a periodic ping task. Returns a `JoinHandle` that can be `.abort()`ed
    /// when the connection drops or is replaced. The task sends a WebSocket Ping
    /// every `PING_INTERVAL` seconds; if the send fails it triggers a reconnect and
    /// exits, so no task leak occurs even without an explicit abort.
    fn spawn_ping_task(sink: Arc<Mutex<WsSink>>) -> JoinHandle<()> {
        const PING_INTERVAL: Duration = Duration::from_secs(30);
        tokio::spawn(async move {
            loop {
                sleep(PING_INTERVAL).await;
                let mut sink = sink.lock().await;
                match sink.send(Message::Ping(vec![].into())).await {
                    Ok(()) => trace!("Sent WebSocket keepalive ping"),
                    Err(e) => {
                        // The reader loop will detect the broken connection and
                        // set the state to Disconnected; reconnect is triggered
                        // lazily by the next send_request call.
                        warn!("WebSocket ping failed ({e}), stopping ping task");
                        break;
                    }
                }
            }
        })
    }

    async fn reconnection_handler(
        mut reconnect_rx: mpsc::Receiver<()>,
        sink: Arc<Mutex<WsSink>>,
        pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>>,
        state: Arc<Mutex<ConnectionState>>,
        remote_addr: String,
        proxy: Option<String>,
        ping_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    ) {
        while reconnect_rx.recv().await.is_some() {
            // Check if already reconnecting
            {
                let current_state = *state.lock().await;
                if current_state == ConnectionState::Reconnecting {
                    continue;
                }
            }

            *state.lock().await = ConnectionState::Reconnecting;
            info!("Attempting to reconnect WebSocket...");

            const MAX_RETRIES: u32 = 3;
            const RETRY_DELAY: Duration = Duration::from_secs(1);

            for attempt in 1..=MAX_RETRIES {
                debug!("Reconnection attempt {}/{}", attempt, MAX_RETRIES);

                match Self::connect(&remote_addr, proxy.as_deref()).await {
                    Ok((new_sink, new_reader)) => {
                        // Replace the sink
                        *sink.lock().await = new_sink;

                        // Abort the stale ping task and spawn a fresh one
                        if let Some(old) = ping_handle.lock().await.take() {
                            old.abort();
                        }
                        *ping_handle.lock().await = Some(Self::spawn_ping_task(sink.clone()));

                        // Spawn new reader loop
                        let pending_clone = pending.clone();
                        let state_clone = state.clone();
                        tokio::spawn(async move {
                            Self::reader_loop(new_reader, pending_clone, state_clone).await;
                        });

                        *state.lock().await = ConnectionState::Connected;
                        info!("WebSocket reconnection successful");
                        break;
                    }
                    Err(e) => {
                        warn!("Reconnection attempt {} failed: {}", attempt, e);
                        if attempt < MAX_RETRIES {
                            sleep(RETRY_DELAY).await;
                        } else {
                            warn!("All reconnection attempts failed");
                            *state.lock().await = ConnectionState::Disconnected;
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn send_request(
        &self,
        uuid: Uuid,
        chunks: Vec<Bytes>,
    ) -> Result<oneshot::Receiver<Vec<u8>>> {
        // Wait for connection to be ready
        const MAX_WAIT_ATTEMPTS: u32 = 30; // 30 seconds total
        const WAIT_INTERVAL: Duration = Duration::from_secs(1);

        for attempt in 1..=MAX_WAIT_ATTEMPTS {
            let state = *self.state.lock().await;
            match state {
                ConnectionState::Connected => break,
                ConnectionState::Disconnected => {
                    if attempt == 1 {
                        warn!("WebSocket disconnected, triggering reconnection");
                        let _ = self.reconnect_tx.send(()).await;
                    }
                    if attempt >= MAX_WAIT_ATTEMPTS {
                        bail!(
                            "WebSocket connection failed after {} attempts",
                            MAX_WAIT_ATTEMPTS
                        );
                    }
                    sleep(WAIT_INTERVAL).await;
                }
                ConnectionState::Reconnecting => {
                    if attempt >= MAX_WAIT_ATTEMPTS {
                        bail!(
                            "WebSocket reconnection timeout after {} seconds",
                            MAX_WAIT_ATTEMPTS
                        );
                    }
                    sleep(WAIT_INTERVAL).await;
                }
            }
        }

        // Register pending response BEFORE sending frames to avoid a race
        // where the reader_loop receives the 0x03 response before the sender
        // is inserted into the map, causing the response to be silently dropped.
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(uuid, tx);

        let send_result = async {
            let total = chunks.len() as u32;
            let mut sink = self.sink.lock().await;
            let uuid_bytes = uuid.as_bytes();

            // Send frame 0x01: metadata
            let mut meta = Vec::with_capacity(1 + 16 + 4);
            meta.push(0x01u8);
            meta.extend_from_slice(uuid_bytes);
            meta.extend_from_slice(&total.to_le_bytes());
            sink.send(Message::Binary(meta.into())).await?;

            // Send frame 0x02 for each chunk
            for (i, chunk) in chunks.into_iter().enumerate() {
                let mut frame = Vec::with_capacity(1 + 16 + 4 + chunk.len());
                frame.push(0x02u8);
                frame.extend_from_slice(uuid_bytes);
                frame.extend_from_slice(&(i as u32).to_le_bytes());
                frame.extend_from_slice(&chunk);
                sink.send(Message::Binary(frame.into())).await?;
            }

            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(e) = send_result {
            // Clean up the pending entry since we failed to send
            self.pending.lock().await.remove(&uuid);
            return Err(e);
        }

        Ok(rx)
    }
}

pub(crate) struct WsForwarder {
    chunks: Vec<Bytes>,
    cipher: Cipher,
    uuid: Uuid,
    url: String,
    start: Instant,
    no_base64: bool,
}

impl WsForwarder {
    pub(crate) async fn new(
        parts: Parts,
        body: Incoming,
        opts: &LocalModeOptions,
        is_https: bool,
        addr: std::net::SocketAddr,
    ) -> Result<Self> {
        let body = body.collect().await?.to_bytes();
        let url = build_full_url(is_https, &parts)?;
        let url_str = url.to_string();

        // Serialize request as HTTP/1.1 wire format
        let mut req_bytes: Vec<u8> = Vec::new();
        let version_str = match parts.version {
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_2 => "HTTP/2.0",
            _ => "HTTP/1.1",
        };
        req_bytes
            .extend_from_slice(format!("{} {} {}\r\n", parts.method, url, version_str).as_bytes());
        for (name, value) in &parts.headers {
            req_bytes.extend_from_slice(name.as_str().as_bytes());
            req_bytes.extend_from_slice(b": ");
            req_bytes.extend_from_slice(value.as_bytes());
            req_bytes.extend_from_slice(b"\r\n");
        }
        req_bytes.extend_from_slice(b"\r\n");
        req_bytes.extend_from_slice(&body);

        // Chunk size calculation (same as Forwarder)
        let chunk_size = opts.chunk.unwrap_or(DEFAULT_CHUNK) - 12 - 16 - package_info().len();
        let chunk_size = if opts.common.no_base64.unwrap_or(false) {
            chunk_size
        } else {
            3 * (chunk_size / 4)
        };

        let mut data = Bytes::from(req_bytes);
        let chunks = if data.len() > chunk_size {
            let mut chunks = vec![];
            let low = (chunk_size as f32 * 0.5) as usize;
            loop {
                if data.is_empty() {
                    break;
                }
                let real_chunk_size = rand::random_range(low..chunk_size);
                if data.len() < chunk_size {
                    chunks.push(data);
                    break;
                } else {
                    chunks.push(data.split_to(real_chunk_size));
                }
            }
            chunks
        } else {
            vec![data]
        };

        let cipher = Cipher::new(opts.common.token.clone().unwrap_or_else(default_token));
        let no_base64 = opts.common.no_base64.unwrap_or(false);

        // Encrypt chunks and optionally encode with base64
        let encrypted_chunks: Result<Vec<Bytes>> = chunks
            .into_iter()
            .map(|chunk| {
                let encrypted = cipher.encrypt(&chunk)?;
                if no_base64 {
                    Ok(Bytes::from(encrypted))
                } else {
                    Ok(Bytes::from(Base64::encode_string(&encrypted)))
                }
            })
            .collect();
        let chunks = encrypted_chunks?;

        let uuid = Uuid::new_v4();
        let start = Instant::now();

        info!("[{uuid}] WS transaction begins ({})", addr);

        Ok(Self {
            chunks,
            cipher,
            uuid,
            url: url_str,
            start,
            no_base64,
        })
    }

    pub(crate) async fn apply(
        self,
        manager: &WsConnectionManager,
    ) -> Result<Response<Full<Bytes>>> {
        debug!(
            "[{}] WS request -> {}, chunks: {}",
            self.uuid,
            self.url,
            self.chunks.len()
        );

        let rx = manager.send_request(self.uuid, self.chunks).await?;

        // Wait for response
        let encrypted = rx.await.map_err(|_| anyhow!("Response channel closed"))?;
        let decoded = if self.no_base64 {
            encrypted
        } else {
            Base64::decode_vec(&String::from_utf8_lossy(&encrypted))?
        };
        let decrypted = self.cipher.decrypt(&decoded)?;

        let response = parse_response(decrypted).context("parse response error")?;

        info!(
            "[{}] WS transaction ends, status: {}, cost {:?}",
            self.uuid,
            response.status(),
            self.start.elapsed()
        );

        Ok(response)
    }
}

fn parse_response(data: Vec<u8>) -> Result<Response<Full<Bytes>>> {
    // Manual parsing to handle HTTP/2.0 which httparse doesn't support
    let data_str = String::from_utf8_lossy(&data);
    let mut lines = data_str.lines();

    // Parse status line
    let status_line = lines.next().ok_or_else(|| anyhow!("empty response"))?;
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        bail!("invalid status line: {}", status_line);
    }

    let status_code: u16 = parts[1]
        .parse()
        .with_context(|| format!("invalid status code: {}", parts[1]))?;

    // Parse headers until empty line
    let mut builder = Response::builder().status(status_code);
    let mut body_start = 0;

    for (i, line) in data_str.lines().enumerate() {
        if i == 0 {
            continue; // Skip status line
        }
        if line.is_empty() {
            // Find the actual byte position of the body
            let header_end = data_str[..data_str.len()]
                .find("\r\n\r\n")
                .or_else(|| data_str.find("\n\n"))
                .ok_or_else(|| anyhow!("no body separator found"))?;
            body_start = if data_str.contains("\r\n\r\n") {
                header_end + 4
            } else {
                header_end + 2
            };
            break;
        }

        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim();
            let value = line[colon_pos + 1..].trim();
            builder = builder.header(name, value);
        }
    }

    let body = Bytes::copy_from_slice(&data[body_start..]);
    Ok(builder.body(Full::new(body))?)
}
