use crate::crypto::Cipher;
use anyhow::{Result, anyhow};
use base64ct::{Base64, Encoding};
use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use hyper::{Request, body::Incoming, upgrade::on};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Instant,
};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::{Role, WebSocketConfig}},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

type Transactions = HashMap<Uuid, (usize, BTreeMap<usize, Vec<u8>>, Instant)>;
type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
    Message,
>;

pub(crate) async fn handle_ws_upgrade(
    request: Request<Incoming>,
    cipher: Arc<Cipher>,
    client: Client,
    no_base64: bool,
) -> Result<()> {
    let stream = on(request).await?;
    let io = TokioIo::new(stream);

    // Create WebSocket from already-upgraded connection and split into reader/writer.
    // The writer is shared via Arc<Mutex<>> so spawned tasks can send responses
    // concurrently without blocking the read loop.
    let ws = WebSocketStream::from_raw_socket(io, Role::Server, {
        let mut cfg = WebSocketConfig::default();
        cfg.max_message_size = None;
        cfg.max_frame_size = None;
        Some(cfg)
    })
    .await;
    let (sink, mut reader) = ws.split();
    let sink: Arc<Mutex<WsSink>> = Arc::new(Mutex::new(sink));

    // Track ongoing transactions: uuid -> (total_chunks, received_chunks, start_time)
    let mut transactions: Transactions = HashMap::new();

    while let Some(msg) = reader.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if data.is_empty() {
                    continue;
                }

                match data[0] {
                    0x01 => {
                        // Metadata frame: [type][uuid][total_chunks LE]
                        if data.len() < 21 {
                            continue;
                        }
                        let uuid_bytes: [u8; 16] = match data[1..17].try_into() {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        let uuid = Uuid::from_bytes(uuid_bytes);
                        let total = u32::from_le_bytes(match data[17..21].try_into() {
                            Ok(b) => b,
                            Err(_) => continue,
                        }) as usize;

                        info!("[{}] WS transaction begins, chunks: {}", uuid, total);
                        transactions.insert(uuid, (total, BTreeMap::new(), Instant::now()));
                    }
                    0x02 => {
                        // Chunk frame: [type][uuid][chunk_index LE][encrypted chunk]
                        if data.len() < 21 {
                            continue;
                        }
                        let uuid_bytes: [u8; 16] = match data[1..17].try_into() {
                            Ok(u) => u,
                            Err(_) => continue,
                        };
                        let uuid = Uuid::from_bytes(uuid_bytes);
                        let index = u32::from_le_bytes(match data[17..21].try_into() {
                            Ok(b) => b,
                            Err(_) => continue,
                        }) as usize;

                        let decoded = if no_base64 {
                            data[21..].to_vec()
                        } else {
                            match Base64::decode_vec(&String::from_utf8_lossy(&data[21..])) {
                                Ok(d) => d,
                                Err(e) => {
                                    warn!("Failed to decode base64 chunk: {e:?}");
                                    continue;
                                }
                            }
                        };

                        let decrypted = match cipher.decrypt(&decoded) {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Failed to decrypt chunk: {e:?}");
                                continue;
                            }
                        };

                        if let Some((total, chunks, start)) = transactions.get_mut(&uuid) {
                            chunks.insert(index, decrypted);

                            // Check if all chunks received
                            if chunks.len() == *total {
                                let start = *start;

                                // Reassemble
                                let mut raw: BytesMut = BytesMut::new();
                                for (_, chunk) in chunks.iter() {
                                    raw.put_slice(chunk);
                                }

                                transactions.remove(&uuid);

                                // Spawn a task so the read loop is never blocked by
                                // the upstream HTTP request or the response write-back.
                                let cipher = cipher.clone();
                                let client = client.clone();
                                let sink = sink.clone();
                                tokio::spawn(async move {
                                    let response_bytes = match forward_request(
                                        raw.freeze().to_vec(),
                                        &client,
                                        uuid,
                                        start,
                                    )
                                    .await
                                    {
                                        Ok(r) => r,
                                        Err(e) => {
                                            warn!("Failed to forward request: {e:?}");
                                            return;
                                        }
                                    };

                                    // Encrypt and send response
                                    let encrypted = match cipher.encrypt(&response_bytes) {
                                        Ok(e) => e,
                                        Err(e) => {
                                            warn!("Failed to encrypt response: {e:?}");
                                            return;
                                        }
                                    };

                                    let encoded = if no_base64 {
                                        encrypted
                                    } else {
                                        Base64::encode_string(&encrypted).into_bytes()
                                    };

                                    let mut frame = Vec::with_capacity(1 + 16 + encoded.len());
                                    frame.push(0x03u8);
                                    frame.extend_from_slice(uuid.as_bytes());
                                    frame.extend_from_slice(&encoded);

                                    if let Err(e) =
                                        sink.lock().await.send(Message::Binary(frame.into())).await
                                    {
                                        warn!("Failed to send response: {e:?}");
                                    }
                                });
                            }
                        }
                    }
                    _ => {
                        warn!("Unknown frame type: {}", data[0]);
                    }
                }
            }
            Ok(Message::Close(_)) => {
                debug!("WebSocket closed by client");
                break;
            }
            Err(e) => {
                warn!("WebSocket error: {e:?}");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn forward_request(
    raw: Vec<u8>,
    client: &Client,
    uuid: Uuid,
    start: Instant,
) -> Result<Vec<u8>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let body_offset = match req.parse(&raw)? {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => return Err(anyhow!("incomplete request")),
    };

    let method = req.method.ok_or_else(|| anyhow!("no method"))?;
    let path = req.path.ok_or_else(|| anyhow!("no path"))?;

    debug!("[{}] WS forward {} {}", uuid, method, path);

    let mut builder = client.request(method.parse()?, path);
    for h in req.headers.iter() {
        builder = builder.header(h.name, h.value);
    }

    let body = raw[body_offset..].to_vec();
    let response = builder.body(body).send().await?;

    let status = response.status();
    let version = response.version();
    let resp_headers = response.headers().clone();
    let body_bytes = response.bytes().await?;

    info!(
        "[{}] WS transaction ends, status: {}, cost {:?}",
        uuid,
        status.as_u16(),
        start.elapsed()
    );

    // Serialize response as HTTP/1.1 wire format
    let version_str = match version {
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2.0",
        _ => "HTTP/1.1",
    };

    let mut out = Vec::new();
    out.extend_from_slice(format!("{} {} \r\n", version_str, status.as_u16()).as_bytes());
    for (name, value) in &resp_headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("content-length: {}\r\n", body_bytes.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body_bytes);

    Ok(out)
}
