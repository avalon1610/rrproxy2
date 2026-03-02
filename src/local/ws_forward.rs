use crate::{
    crypto::{Cipher, default_token, package_info},
    local::build_full_url,
    options::LocalModeOptions,
};
use anyhow::{Context, Result, anyhow};
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
use std::{collections::HashMap, sync::Arc};
use tokio::{
    net::TcpStream,
    sync::{Mutex, oneshot},
};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use tracing::{debug, warn};
use uuid::Uuid;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

pub(crate) struct WsConnectionManager {
    sink: Arc<Mutex<WsSink>>,
    pending: Arc<Mutex<HashMap<[u8; 16], oneshot::Sender<Vec<u8>>>>>,
}

impl WsConnectionManager {
    pub(crate) async fn new(remote_addr: &str, proxy: Option<&str>) -> Result<Self> {
        let ws_url = remote_addr
            .replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1);

        let ws = if let Some(proxy_url) = proxy {
            // Connect through HTTP proxy
            Self::connect_via_proxy(&ws_url, proxy_url)
                .await
                .context("connect websocket via proxy error")?
        } else {
            // Direct connection
            let (ws, _) = connect_async(&ws_url)
                .await
                .context("connect websocket directly error")?;
            ws
        };

        let (sink, reader) = ws.split();

        let pending = Arc::new(Mutex::new(HashMap::new()));
        let pending_clone = pending.clone();

        // Spawn reader task
        tokio::spawn(async move {
            Self::reader_loop(reader, pending_clone).await;
        });

        Ok(Self {
            sink: Arc::new(Mutex::new(sink)),
            pending,
        })
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

        // Connect to proxy
        let mut stream = TcpStream::connect(format!("{}:{}", proxy_host, proxy_port)).await?;

        // Send CONNECT request
        let connect_req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            host, port, host, port
        );
        stream.write_all(connect_req.as_bytes()).await?;

        // Read CONNECT response
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            return Err(anyhow!(
                "Proxy CONNECT failed: {}",
                response.lines().next().unwrap_or("")
            ));
        }

        // Now establish WebSocket over the tunneled connection
        if ws_url.starts_with("wss://") {
            // For wss://, wrap in TLS using native-tls
            use tokio_native_tls::{TlsConnector, native_tls};

            let cx = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()?;
            let cx = TlsConnector::from(cx);
            let tls_stream = cx.connect(host, stream).await?;

            // Wrap in MaybeTlsStream
            let maybe_tls = MaybeTlsStream::NativeTls(tls_stream);
            let (ws, _) = tokio_tungstenite::client_async(ws_url, maybe_tls).await?;
            Ok(ws)
        } else {
            // For ws://, use plain connection wrapped in MaybeTlsStream
            let maybe_tls = MaybeTlsStream::Plain(stream);
            let (ws, _) = tokio_tungstenite::client_async(ws_url, maybe_tls).await?;
            Ok(ws)
        }
    }

    async fn reader_loop(
        mut reader: WsReader,
        pending: Arc<Mutex<HashMap<[u8; 16], oneshot::Sender<Vec<u8>>>>>,
    ) {
        while let Some(msg) = reader.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    if data.len() < 17 || data[0] != 0x03 {
                        continue;
                    }
                    let uuid: [u8; 16] = match data[1..17].try_into() {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let response_data = data[17..].to_vec();

                    let mut pending = pending.lock().await;
                    if let Some(tx) = pending.remove(&uuid) {
                        let _ = tx.send(response_data);
                    }
                }
                Ok(Message::Close(_)) => {
                    warn!("WebSocket closed by remote");
                    break;
                }
                Err(e) => {
                    warn!("WebSocket error: {e:?}");
                    break;
                }
                _ => {}
            }
        }
    }

    pub(crate) async fn send_request(
        &self,
        uuid: [u8; 16],
        chunks: Vec<Bytes>,
    ) -> Result<oneshot::Receiver<Vec<u8>>> {
        let total = chunks.len() as u32;
        let mut sink = self.sink.lock().await;

        // Send frame 0x01: metadata
        let mut meta = Vec::with_capacity(1 + 16 + 4);
        meta.push(0x01u8);
        meta.extend_from_slice(&uuid);
        meta.extend_from_slice(&total.to_le_bytes());
        sink.send(Message::Binary(meta.into())).await?;

        // Send frame 0x02 for each chunk
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut frame = Vec::with_capacity(1 + 16 + 4 + chunk.len());
            frame.push(0x02u8);
            frame.extend_from_slice(&uuid);
            frame.extend_from_slice(&(i as u32).to_le_bytes());
            frame.extend_from_slice(&chunk);
            sink.send(Message::Binary(frame.into())).await?;
        }

        drop(sink);

        // Register pending response
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(uuid, tx);

        Ok(rx)
    }
}

pub(crate) struct WsForwarder {
    chunks: Vec<Bytes>,
    cipher: Cipher,
    uuid: [u8; 16],
}

impl WsForwarder {
    pub(crate) async fn new(
        parts: Parts,
        body: Incoming,
        opts: &LocalModeOptions,
        is_https: bool,
    ) -> Result<Self> {
        let body = body.collect().await?.to_bytes();
        let url = build_full_url(is_https, &parts)?;

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
        let chunk_size = opts.chunk - 12 - 16 - package_info().len();
        let chunk_size = 3 * (chunk_size / 4);

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

        // Encrypt chunks
        let encrypted_chunks: Result<Vec<Bytes>> = chunks
            .into_iter()
            .map(|chunk| cipher.encrypt(&chunk).map(Bytes::from))
            .collect();
        let chunks = encrypted_chunks?;

        let uuid = *Uuid::new_v4().as_bytes();

        Ok(Self {
            chunks,
            cipher,
            uuid,
        })
    }

    pub(crate) async fn apply(
        self,
        manager: &WsConnectionManager,
    ) -> Result<Response<Full<Bytes>>> {
        debug!("Sending WS request with uuid {:?}", self.uuid);

        let rx = manager.send_request(self.uuid, self.chunks).await?;

        // Wait for response
        let encrypted = rx.await.map_err(|_| anyhow!("Response channel closed"))?;
        let decrypted = self.cipher.decrypt(&encrypted)?;

        parse_response(decrypted)
    }
}

fn parse_response(data: Vec<u8>) -> Result<Response<Full<Bytes>>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut resp = httparse::Response::new(&mut headers);
    let status = resp.parse(&data)?;
    let code = resp.code.ok_or_else(|| anyhow!("no status code"))?;
    let body_offset = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(anyhow!("incomplete response")),
    };

    let mut builder = Response::builder().status(code);
    for h in resp.headers.iter() {
        builder = builder.header(h.name, h.value);
    }

    let body = Bytes::copy_from_slice(&data[body_offset..]);
    Ok(builder.body(Full::new(body))?)
}
