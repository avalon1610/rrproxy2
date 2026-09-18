use crate::{
    crypto::{Cipher, WS_AUTH_PAYLOAD},
    remote::MAX_TOTAL_CHUNKS,
};
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
    time::{Duration, Instant},
};

/// Upper bound on concurrently pending transactions per WebSocket connection.
const MAX_PENDING_WS_TRANSACTIONS: usize = 256;
/// Connection-wide buffered-byte budget across all pending transactions.
const MAX_WS_CONN_BYTES: usize = 256 * 1024 * 1024;
use tokio::sync::Mutex;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// uuid -> (total_chunks, chunks, txn_start, last_activity, buffered_bytes)
type Transactions = HashMap<Uuid, (usize, BTreeMap<usize, Vec<u8>>, Instant, Instant, usize)>;
type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>,
    Message,
>;

pub(crate) async fn handle_ws_upgrade(
    request: Request<Incoming>,
    cipher: Arc<Cipher>,
    client: Client,
    no_base64: bool,
    max_frame_size: usize,
    transaction_timeout: Duration,
    // Per-transaction buffered-byte cap; derives from --max-body so a user
    // raising the body limit for large uploads raises this cap implicitly.
    max_txn_bytes: usize,
    // Keeps the remote per-IP connection slot occupied for the lifetime of
    // the WebSocket connection (the HTTP connection task ended at upgrade).
    _conn_guard: Option<crate::proxy::ConnGuard>,
) -> Result<()> {
    let stream = on(request).await?;
    let io = TokioIo::new(stream);

    // Create WebSocket from already-upgraded connection and split into reader/writer.
    // The writer is shared via Arc<Mutex<>> so spawned tasks can send responses
    // concurrently without blocking the read loop.
    let ws = WebSocketStream::from_raw_socket(io, Role::Server, {
        let mut cfg = WebSocketConfig::default();
        // Bounds incoming frames/messages: an uncapped receiver lets a single
        // malicious frame OOM the process. Sizing rule: must be >= the local
        // client's --chunk value (which the local side uses to split requests),
        // configured via remote --max-frame.
        cfg.max_frame_size = Some(max_frame_size);
        cfg.max_message_size = Some(max_frame_size);
        Some(cfg)
    })
    .await;
    let (sink, mut reader) = ws.split();
    let sink: Arc<Mutex<WsSink>> = Arc::new(Mutex::new(sink));

    // Track ongoing transactions: uuid -> (total_chunks, chunks, txn_start,
    // last_activity, buffered_bytes)
    let mut transactions: Transactions = HashMap::new();
    // Connection-wide buffered-byte budget: per-transaction caps alone allow
    // MAX_PENDING_WS_TRANSACTIONS x max_txn_bytes to accumulate.
    let mut conn_buffered_bytes: usize = 0;
    let mut last_sweep = Instant::now();
    // The connection is unauthenticated until the client proves it holds the
    // shared token via a 0x00 frame (see WS_AUTH_PAYLOAD). Unauthenticated
    // connections cannot register transactions, so anonymous peers cannot
    // allocate tracked state.
    let mut authenticated = false;

    while let Some(msg) = reader.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if data.is_empty() {
                    continue;
                }

                match data[0] {
                    0x00 => {
                        // Auth frame: [type][nonce][encrypted WS_AUTH_PAYLOAD].
                        // Decrypting to the expected constant proves the sender
                        // holds the shared token. Replies 0x05 (accepted) or
                        // 0x06 (rejected) so the local side can fail fast on a
                        // token mismatch instead of timing out later.
                        let reply = match cipher.decrypt(&data[1..]) {
                            Ok(p) if p.as_slice() == WS_AUTH_PAYLOAD => 0x05u8,
                            Ok(_) => {
                                warn!("WS auth payload mismatch");
                                0x06u8
                            }
                            Err(e) => {
                                warn!("WS auth failed: {e:?}");
                                0x06u8
                            }
                        };
                        if reply == 0x05 {
                            debug!("WS connection authenticated");
                            authenticated = true;
                        }
                        if sink
                            .lock()
                            .await
                            .send(Message::Binary(vec![reply].into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if reply == 0x06 {
                            break; // wrong token: drop the connection
                        }
                    }
                    0x01 if authenticated => {
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

                        if total == 0 || total > MAX_TOTAL_CHUNKS {
                            continue;
                        }

                        // Expire stale transactions so an attacker cannot grow the
                        // map forever by sending metadata frames that never complete.
                        if last_sweep.elapsed() >= transaction_timeout {
                            transactions.retain(|_, (_, _, _, last_active, _)| {
                                last_active.elapsed() < transaction_timeout
                            });
                            // Recompute the connection total from what survived
                            // the sweep: retained transactions keep their bytes,
                            // evicted ones are dropped from the accounting too.
                            conn_buffered_bytes = transactions
                                .values()
                                .map(|(_, _, _, _, buffered)| *buffered)
                                .sum();
                            last_sweep = Instant::now();
                        }
                        if transactions.len() >= MAX_PENDING_WS_TRANSACTIONS {
                            warn!("Too many pending WS transactions, rejecting {}", uuid);
                            continue;
                        }

                        info!("[{}] WS transaction begins, chunks: {}", uuid, total);

                        let now = Instant::now();
                        // An existing entry is a client retry/restart of the same
                        // request id: replace it and recompute the connection total
                        // so stale bytes from the old entry don't linger in the
                        // accounting until the next sweep.
                        transactions.insert(uuid, (total, BTreeMap::new(), now, now, 0));
                        conn_buffered_bytes = transactions
                            .values()
                            .map(|(_, _, _, _, buffered)| *buffered)
                            .sum();
                    }
                    0x02 if authenticated => {
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

                        if let Some((total, chunks, start, last_active, buffered)) =
                            transactions.get_mut(&uuid)
                        {
                            if index >= *total {
                                continue;
                            }
                            // Insert first, then budget-check with the exact
                            // signed delta: a re-sent (larger) chunk replaces
                            // the stored one, so a pre-insert check could
                            // falsely drop a transaction that fits after the
                            // replace. i64 delta keeps the counters exactly
                            // equal to the stored bytes (no drift either way).
                            let new_len = decrypted.len() as i64;
                            let old_len = chunks
                                .insert(index, decrypted)
                                .map(|o| o.len() as i64)
                                .unwrap_or(0);
                            let delta = new_len - old_len;
                            *buffered = (*buffered as i64 + delta) as usize;
                            conn_buffered_bytes = (conn_buffered_bytes as i64 + delta) as usize;
                            *last_active = Instant::now();
                            if *buffered > max_txn_bytes || conn_buffered_bytes > MAX_WS_CONN_BYTES
                            {
                                warn!(
                                    "[{}] WS byte budget exceeded (txn or connection), dropping",
                                    uuid
                                );
                                conn_buffered_bytes -= *buffered;
                                transactions.remove(&uuid);
                                continue;
                            }

                            // Check if all chunks received
                            if chunks.len() == *total {
                                let start = *start;

                                // Reassemble
                                let mut raw: BytesMut = BytesMut::new();
                                for (_, chunk) in chunks.iter() {
                                    raw.put_slice(chunk);
                                }

                                conn_buffered_bytes -= *buffered;
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
                    0x01 | 0x02 => {
                        warn!("transaction frame before auth, closing");
                        break;
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

    // Headers that must be stripped before forwarding via reqwest+HTTP/2:
    // - Hop-by-hop headers (forbidden in HTTP/2 per RFC 9113 §8.2.2)
    // - `host`: reqwest derives :authority from URL; forwarding host duplicates it
    // - `content-length`: reqwest recomputes; mismatch with END_STREAM = PROTOCOL_ERROR
    // - `accept-encoding`: reqwest's gzip feature auto-adds it
    const STRIP_HEADERS: &[&str] = &[
        "connection",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "host",
        "content-length",
        "accept-encoding",
    ];

    let mut builder = client.request(method.parse()?, path);
    let mut forwarded_headers: Vec<(String, String)> = Vec::new();
    for h in req.headers.iter() {
        if !STRIP_HEADERS
            .iter()
            .any(|&name| name.eq_ignore_ascii_case(h.name))
        {
            builder = builder.header(h.name, h.value);
            forwarded_headers.push((
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            ));
        }
    }
    debug!(
        "[{}] WS forward headers ({} {}): {:?}",
        uuid, method, path, forwarded_headers
    );

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
