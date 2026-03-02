use crate::{
    convert::{Encryptor, ResponseConverter},
    crypto::{Cipher, default_token},
    options::RemoteModeOptions,
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
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, trace, warn};

#[derive(Clone)]
pub(crate) struct RemoteProxy {
    opts: Arc<RemoteModeOptions>,
    transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    cipher: Arc<Cipher>,
    client: Client,
    no_base64: bool,
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
        let no_base64 = opts.common.no_base64;

        Ok(Self {
            transactions: Arc::new(Mutex::new(HashMap::new())),
            cipher: Arc::new(Cipher::new(token)),
            opts: Arc::new(opts),
            client,
            no_base64,
        })
    }

    fn listen_addr(&self) -> Result<SocketAddr> {
        Ok(self.opts.common.listen.parse()?)
    }

    async fn handler(
        self,
        request: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        info!("local request from {}", addr);

        if self.opts.common.websocket && is_ws_upgrade(&request) {
            let (cipher, client) = (self.cipher.clone(), self.client.clone());
            // Get the Sec-WebSocket-Key header to compute the accept key
            let ws_key = request
                .headers()
                .get("Sec-WebSocket-Key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            // Compute Sec-WebSocket-Accept
            let accept_key = compute_ws_accept_key(ws_key);

            // Spawn the upgrade handler
            let no_base64 = self.no_base64;
            tokio::spawn(async move {
                if let Err(e) =
                    ws_handler::handle_ws_upgrade(request, cipher, client, no_base64).await
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
        if self.opts.common.websocket && (self.opts.tls || self.opts.tls_cert.is_some()) {
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
        let body = body.collect().await?.to_bytes();
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
        let request = {
            let mut transactions = self.transactions.lock().unwrap();

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

                t.update(info.chunk_index, body);
                t
            } else {
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
    req.headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && req
            .headers()
            .get(CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
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
    let (cert_chain, key) =
        if let (Some(cert_path), Some(key_path)) = (&opts.tls_cert, &opts.tls_key) {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())?
                .into_iter()
                .map(Certificate)
                .collect::<Vec<_>>();
            let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_slice())?;
            if keys.is_empty() {
                anyhow::bail!("no private key found in {}", key_path.display());
            }
            (certs, PrivateKey(keys.remove(0)))
        } else {
            info!("Generating self-signed TLS certificate for WebSocket");
            let rcgen::CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_der = cert.der().to_vec();
            let key_der = signing_key.serialize_der();
            (vec![Certificate(cert_der)], PrivateKey(key_der))
        };

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
