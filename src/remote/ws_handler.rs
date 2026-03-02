use crate::crypto::Cipher;
use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use futures_util::{SinkExt, StreamExt};
use hyper::{Request, body::Incoming, upgrade::on};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio_tungstenite::{WebSocketStream, tungstenite::{Message, protocol::Role}};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub(crate) async fn handle_ws_upgrade(
    request: Request<Incoming>,
    cipher: Arc<Cipher>,
    client: Client,
) -> Result<()> {
    let stream = on(request).await?;
    let io = TokioIo::new(stream);

    // Create WebSocket from already-upgraded connection
    let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;

    // Track ongoing transactions: uuid -> (total_chunks, received_chunks, start_time)
    let mut transactions: BTreeMap<Uuid, (usize, BTreeMap<usize, Vec<u8>>, Instant)> = BTreeMap::new();

    while let Some(msg) = ws.next().await {
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

                        info!("[{}] WS transaction begins, total={}", uuid, total);
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

                        let decrypted = match cipher.decrypt(&data[21..]) {
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

                                // Forward request
                                let response_bytes = match forward_request(raw.freeze().to_vec(), &client, uuid, start).await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        warn!("Failed to forward request: {e:?}");
                                        transactions.remove(&uuid);
                                        continue;
                                    }
                                };

                                // Encrypt and send response
                                let encrypted = match cipher.encrypt(&response_bytes) {
                                    Ok(e) => e,
                                    Err(e) => {
                                        warn!("Failed to encrypt response: {e:?}");
                                        transactions.remove(&uuid);
                                        continue;
                                    }
                                };

                                let mut frame = Vec::with_capacity(1 + 16 + encrypted.len());
                                frame.push(0x03u8);
                                frame.extend_from_slice(uuid.as_bytes());
                                frame.extend_from_slice(&encrypted);

                                if let Err(e) = ws.send(Message::Binary(frame.into())).await {
                                    warn!("Failed to send response: {e:?}");
                                    break;
                                }

                                transactions.remove(&uuid);
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

async fn forward_request(raw: Vec<u8>, client: &Client, uuid: Uuid, start: Instant) -> Result<Vec<u8>> {
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
    out.extend_from_slice(
        format!("{} {} \r\n", version_str, status.as_u16()).as_bytes(),
    );
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
