use crate::{
    convert::{Encryptor, ResponseConverter},
    crypto::{Cipher, default_token},
    options::{DEFAULT_LISTEN, RemoteModeOptions},
    proxy::{COMMIT_INDEX_HEADER, Proxy},
    remote::{
        info::Info,
        transaction::{Transaction, TransactionState},
    },
};
use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response, Uri,
    body::{Bytes, Incoming},
    header::{CONNECTION, HeaderValue, UPGRADE},
};
use rcgen::generate_simple_self_signed;
use reqwest::{Client, ClientBuilder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, trace, warn};

/// Default maximum WebSocket frame size accepted (1 MiB). Override with
/// --max-frame; must be >= the local client's --chunk value.
pub(crate) const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Maximum accepted request body size (encrypted, base64-encoded). Real chunks
/// are bounded by the local proxy's --chunk (default 10 KiB); this cap only
/// bounds attacker-controlled allocation before any meaningful work happens.
pub(crate) const MAX_BODY_SIZE: usize = 16 * 1024 * 1024;
/// Incomplete transactions older than this are evicted on the next request.
pub(crate) const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on concurrently pending (incomplete) transactions.
pub(crate) const MAX_PENDING_TRANSACTIONS: usize = 1024;
/// Upper bound on total bytes buffered across all pending transactions.
pub(crate) const MAX_PENDING_BYTES: usize = 256 * 1024 * 1024;
/// A transaction claiming more chunks than this is rejected outright: real
/// requests split at --chunk (10 KiB default), so this bounds map size per id.
pub(crate) const MAX_TOTAL_CHUNKS: usize = 65536;

#[derive(Clone)]
pub(crate) struct RemoteProxy {
    opts: Arc<RemoteModeOptions>,
    transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    cipher: Arc<Cipher>,
    client: Client,
    no_base64: bool,
    max_frame_size: usize,
    max_body: usize,
    transaction_timeout: Duration,
}

impl Proxy for RemoteProxy {
    type Options = RemoteModeOptions;

    async fn new(opts: RemoteModeOptions) -> Result<Self> {
        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
        let client = if let Some(proxy) = &opts.common.proxy {
            client.proxy(reqwest::Proxy::all(proxy)?).build()?
        } else {
            // add no_proxy to make it not use http_proxy and https_proxy env variables
            client.no_proxy().build()?
        };

        let token = opts.common.token.clone().unwrap_or_else(default_token);
        let no_base64 = opts.common.no_base64.unwrap_or(false);
        let max_frame_size = opts
            .common
            .max_frame
            .unwrap_or(DEFAULT_MAX_FRAME_SIZE);

        let max_body = opts.common.max_body.unwrap_or(MAX_BODY_SIZE);
        let transaction_timeout = Duration::from_secs(
            opts.common
                .transaction_timeout
                .unwrap_or(TRANSACTION_TIMEOUT.as_secs()),
        );

        Ok(Self {
            transactions: Arc::new(Mutex::new(HashMap::new())),
            cipher: Arc::new(Cipher::new(token)),
            opts: Arc::new(opts),
            client,
            no_base64,
            max_frame_size,
            max_body,
            transaction_timeout,
        })
    }

    fn listen_addr(&self) -> Result<SocketAddr> {
        Ok(self
            .opts
            .common
            .listen
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN)
            .parse()?)
    }

    fn max_conns_per_ip(&self) -> Option<usize> {
        // Off by default: behind Cloudflare/reverse proxies every client shares
        // the proxy IP, so a per-IP cap would throttle all legitimate users.
        // Enable explicitly with --max-conns-per-ip N (N > 0).
        self.opts.common.max_conns_per_ip.filter(|&n| n > 0)
    }

    async fn handler(
        self,
        request: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        info!("local request from {}", addr);

        if self.opts.common.websocket.unwrap_or(false) && is_ws_upgrade(&request) {
            let (cipher, client) = (self.cipher.clone(), self.client.clone());
            // Get the Sec-WebSocket-Key header to compute the accept key
            let ws_key = request
                .headers()
                .get("Sec-WebSocket-Key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // Compute Sec-WebSocket-Accept
            let accept_key = compute_ws_accept_key(ws_key);

            let no_base64 = self.no_base64;
            let max_frame = self.max_frame_size;
            let txn_timeout = self.transaction_timeout;
            tokio::spawn(async move {
                if let Err(e) = ws_handler::handle_ws_upgrade(
                    request,
                    cipher,
                    client,
                    no_base64,
                    max_frame,
                    txn_timeout,
                )
                .await
                {
                    warn!("ws error: {e:?}");
                }
            });

            // Return 101 Switching Protocols with proper WebSocket headers
            return Ok(Response::builder()
                .status(101)
                .header(UPGRADE, "websocket")
                .header(CONNECTION, "Upgrade")
                .header("Sec-WebSocket-Accept", accept_key)
                .body(Full::default())
                .unwrap());
        }

        match self.handle_request(request).await {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("handle error: {err:?}");

                // CAUTION: Do not return details error info to client, make sure client can not detect our purpose.
                Ok(Response::builder()
                    .status(400)
                    .body("Invalid Request".into())
                    .unwrap()) // this unwrap never fails, because only set the status code
            }
        }
    }

    async fn serve(self) -> Result<()> {
        if self.opts.common.websocket.unwrap_or(false)
            && (self.opts.tls.unwrap_or(false) || self.opts.tls_cert.is_some())
        {
            let acceptor = build_tls_acceptor(&self.opts)?;
            self.serve_tls(acceptor).await
        } else {
            // default plain HTTP serve
            self.serve_http().await
        }
    }
}

impl RemoteProxy {
    async fn handle_request(
        &self,
        mut request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>> {
        let now = Instant::now();
        let info = Info::parse(&mut request, &self.cipher)?;
        let (parts, body) = request.into_parts();
        // Bound memory before touching the body: hyper gives no built-in size
        // limit on Incoming, and a plain collect() would buffer a chunked
        // (Content-Length-less) body in full before any check. Limited aborts
        // mid-stream once the cap is exceeded.
        if parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len > self.max_body)
        {
            anyhow::bail!("request body too large");
        }
        let body = match http_body_util::Limited::new(body, self.max_body).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => anyhow::bail!("request body too large"),
        };
        debug!(
            "[{}] parsed info {:?} body len: {}",
            info.id,
            info,
            body.len()
        );

        let body = if !body.is_empty() {
            let decoded_body = if self.no_base64 {
                // Body is raw binary, no base64 decoding needed
                body.to_vec()
            } else {
                // Body is base64 encoded, decode it first
                Base64::decode_vec(&String::from_utf8_lossy(&body))?
            };
            let body = self
                .cipher
                .decrypt(&decoded_body)
                .with_context(|| format!("[{}] decrypt body error", info.id))?;
            Bytes::from_owner(body)
        } else {
            debug!("[{}] empty body", info.id);
            body
        };
        let id = info.id.clone();
        let chunk_index = info.chunk_index;
        if info.total_chunks > MAX_TOTAL_CHUNKS {
            anyhow::bail!("total_chunks too large");
        }
        if chunk_index >= info.total_chunks {
            anyhow::bail!("chunk_index out of range");
        }
        let request = {
            let mut transactions = self.transactions.lock().unwrap();
            // Evict stale transactions: ids that never complete must not grow
            // the map without bound.
            transactions.retain(|_, t| t.start.elapsed() < self.transaction_timeout);

            // Global buffered-bytes budget across all pending transactions.
            // Recomputed from the map (<= MAX_PENDING_TRANSACTIONS entries,
            // cached_bytes is O(1)) so the count is always exact — no drift,
            // no underflow, no create/commit bookkeeping to get wrong.
            let pending_bytes: usize = transactions.values().map(|t| t.cached_bytes()).sum();
            let check_budget = |current: usize, incoming: usize| -> Result<()> {
                if current + incoming > MAX_PENDING_BYTES {
                    anyhow::bail!("too many pending transaction bytes");
                }
                Ok(())
            };

            // Check if transaction already exists and handle race conditions
            let transaction = if let Some(mut t) = transactions.remove(&id) {
                // old transaction, we update the body and chunk index
                debug!("[{id}] transaction updated {} bytes", body.len());

                // Validate chunk index to prevent duplicate chunks
                if t.has_chunk(info.chunk_index) {
                    warn!(
                        "[{}] Duplicate chunk received, chunk {}",
                        info.id, info.chunk_index
                    );
                    transactions.insert(id.clone(), t); // Put it back
                    return Ok(Response::builder()
                        .status(400)
                        .body("Duplicate chunk".into())
                        .unwrap()); // unwrap is safe here
                }

                // t is removed from the map, so the global total must include
                // its buffered bytes for the check; after update the map sum
                // is recomputed on the next request.
                check_budget(pending_bytes + t.cached_bytes(), body.len())?;
                t.update(info.chunk_index, body);
                t
            } else {
                // Cap pending map size so forged ids cannot balloon memory.
                if transactions.len() >= MAX_PENDING_TRANSACTIONS {
                    anyhow::bail!("too many pending transactions");
                }

                check_budget(pending_bytes, body.len())?;

                // new transaction, we use request's headers (which already removed our internal headers)
                // and body (will be store in cache)
                debug!("[{id}] new transaction created, {} bytes", body.len());
                Transaction::new(parts, body, info)?
            };

            match transaction.commit()? {
                TransactionState::Pending(t) => {
                    transactions.insert(id.clone(), t);
                    None
                }
                TransactionState::Committed(r) => Some(r),
            }
        };

        let response = if let Some((request, start)) = request {
            debug!("[{id}] transaction committed, sending to target");
            trace!("[{id}] forward request header: {:?}", request.headers());

            let mut response = self
                .client
                .execute(request)
                .await
                .context("target request error")?;
            info!("[{id}] handle whole transaction cost {:?}", start.elapsed());

            response.headers_mut().insert(
                COMMIT_INDEX_HEADER,
                HeaderValue::from_str(&chunk_index.to_string())?,
            );
            // Use the new trait to encrypt the response
            response
                .convert(Encryptor(&self.cipher), &id)
                .await
                .with_context(|| format!("[{id}] response encrypt and convert error"))?
        } else {
            info!("[{id}] handle single chunk cost {:?}", now.elapsed());
            Response::default()
        };

        trace!("[{id}] forward response header: {:?}", response.headers());
        Ok(response)
    }
}

mod info;
mod transaction;
mod ws_handler;

fn is_ws_upgrade(req: &Request<Incoming>) -> bool {
    // Check Upgrade: websocket header (required).
    // Note: Connection: Upgrade is intentionally not required here — reverse proxies
    // such as Cloudflare strip hop-by-hop headers (including Connection) before
    // forwarding to the origin, so we must not rely on it being present.
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn compute_ws_accept_key(key: &str) -> String {
    use base64ct::{Base64, Encoding};
    use sha1::{Digest, Sha1};

    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let hash = hasher.finalize();
    Base64::encode_string(&hash[..])
}

pub(crate) trait HostEx {
    fn get_host(&self) -> Result<String>;
}

impl HostEx for Uri {
    fn get_host(&self) -> Result<String> {
        let host = self.host().ok_or_else(|| anyhow!("uri has not host"))?;
        let port = self.port_u16();
        Ok(format!(
            "{host}{}",
            port.map(|p| format!(":{}", p)).unwrap_or_default()
        ))
    }
}

fn build_tls_acceptor(opts: &RemoteModeOptions) -> Result<TlsAcceptor> {
    let (cert_chain, key) = if let (Some(cert_path), Some(key_path)) =
        (&opts.tls_cert, &opts.tls_key)
    {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        debug!(
            "Loading TLS cert from {} and key from {}",
            cert_path.display(),
            key_path.display()
        );
        crate::tls::tls_parts_from_pem(&cert_pem, &key_pem).map_err(|e| {
            anyhow!(
                "{} (cert: {}, key: {})",
                e,
                cert_path.display(),
                key_path.display()
            )
        })?
    } else {
        debug!("Generating self-signed TLS certificate for WebSocket");
        let rcgen::CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        (vec![cert_der], key_der)
    };

    crate::tls::tls_acceptor_from_parts(cert_chain, key)
}
