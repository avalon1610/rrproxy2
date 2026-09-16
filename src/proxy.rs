use anyhow::Result;
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

/// Maximum time for a client to send complete request headers (slowloris defense).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum time for a TLS handshake to complete (client stalling mid-handshake
/// must not pin a connection-limit slot).
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub(crate) struct ConnLimiter {
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl ConnLimiter {
    pub(crate) fn new(max_per_ip: usize) -> Self {
        Self {
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }

    /// Registers a connection; returns a guard, or `None` if the IP is over the cap.
    pub(crate) fn acquire(&self, addr: SocketAddr) -> Option<ConnGuard> {
        let mut map = self.per_ip.lock().unwrap();
        let ip = addr.ip();
        let count = map.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(ConnGuard {
            limiter: self.clone(),
            ip: Some(ip),
        })
    }
}

/// Decrements the per-IP connection count on drop.
pub(crate) struct ConnGuard {
    limiter: ConnLimiter,
    ip: Option<IpAddr>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.ip.take() {
            let mut map = self.limiter.per_ip.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = map.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    map.remove(&ip);
                }
            }
        }
    }
}

fn serve_builder() -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder
}

pub(crate) trait Proxy: Clone
where
    Self: Send + Sync + 'static,
{
    type Options;

    async fn new(opts: Self::Options) -> Result<Self>;

    fn listen_addr(&self) -> Result<SocketAddr>;

    /// Per-client-IP concurrent connection cap for the listener. `None` or
    /// `Some(0)` disables the limit. Override for deployments behind reverse
    /// proxies (all clients share the proxy IP there — raise or disable).
    fn max_conns_per_ip(&self) -> Option<usize> {
        None
    }

    fn handler(
        self,
        request: Request<Incoming>,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send;

    async fn serve(self) -> Result<()> {
        self.serve_http().await
    }

    async fn serve_http(self) -> Result<()> {
        let addr = self.listen_addr()?;
        let listener = TcpListener::bind(addr).await?;
        let limiter = self.max_conns_per_ip().filter(|&n| n > 0).map(ConnLimiter::new);
        info!("Listening on {}", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let guard = match limiter.as_ref() {
                Some(l) => match l.acquire(addr) {
                    Some(g) => Some(g),
                    None => {
                        debug!("connection limit reached for {}, dropping", addr.ip());
                        continue;
                    }
                },
                None => None,
            };

            let io = TokioIo::new(stream);
            let proxy = self.clone();
            tokio::spawn(async move {
                let _guard = guard;
                if let Err(err) = serve_builder()
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(|req| {
                            let proxy = proxy.clone();
                            async move { proxy.handler(req, addr).await }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn serve_tls(self, acceptor: TlsAcceptor) -> Result<()> {
        let addr = self.listen_addr()?;
        let listener = TcpListener::bind(addr).await?;
        let limiter = self.max_conns_per_ip().filter(|&n| n > 0).map(ConnLimiter::new);
        info!("Listening on {} (TLS)", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let guard = match limiter.as_ref() {
                Some(l) => match l.acquire(addr) {
                    Some(g) => Some(g),
                    None => {
                        debug!("connection limit reached for {}, dropping", addr.ip());
                        continue;
                    }
                },
                None => None,
            };
            let proxy = self.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let tls_stream = match tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("TLS accept error from {addr}: {e:?}");
                        return;
                    }
                    Err(_) => {
                        warn!("TLS handshake timeout from {addr}");
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                if let Err(err) = serve_builder()
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(|req| {
                            let proxy = proxy.clone();
                            async move { proxy.handler(req, addr).await }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
            });
        }
    }
}

pub(crate) const CHUNK_INDEX_HEADER: &str = "X-Fetch-Id";
pub(crate) const COMMIT_INDEX_HEADER: &str = "X-Commit-Id";
pub(crate) const TRANSACTION_ID_HEADER: &str = "X-Request-Id";
/// this header should be encrypted, process is
/// 1. combine: <original method>+<original_version>+<original url> (use plus(+) sign to separate)
/// 2. encrypt the combined string
/// 3. encoded using base64
pub(crate) const ORIGINAL_URL_HEADER: &str = "X-Referer";
pub(crate) const TOTAL_CHUNKS_HEADER: &str = "X-Robots-Tag";
pub(crate) const CONTENT_TYPE_HEADER: &str = "X-Content-Type";
