use crate::geo::SharedGeoCheck;
use anyhow::{Result, anyhow, bail};
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
use ipnetwork::IpNetwork;
use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    str::FromStr,
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
            limiter: Some(self.clone()),
            ip: Some(ip),
        })
    }
}

/// Decrements the per-IP connection count on drop. A guard whose limiter was
/// detached (or released) does nothing on drop.
pub(crate) struct ConnGuard {
    limiter: Option<ConnLimiter>,
    ip: Option<IpAddr>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let (Some(limiter), Some(ip)) = (self.limiter.as_ref(), self.ip.take()) {
            let mut map = limiter.per_ip.lock().unwrap();
            if let Some(count) = map.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    map.remove(&ip);
                }
            }
        }
    }
}

/// Parsed source-address allowlist (`--allow-ips`). When configured, any
/// connection whose peer address is not covered is dropped at accept time —
/// before the connection limiter is touched, before a task is spawned and
/// before any buffer is allocated, so rejected peers cost no per-connection
/// memory.
#[derive(Debug, Clone)]
pub(crate) struct IpWhitelist {
    networks: Vec<IpNetwork>,
}

impl IpWhitelist {
    /// Parse `--allow-ips` entries. Each entry is an IP or CIDR; a bare
    /// address means a single host (`/32` for IPv4, `/128` for IPv6).
    pub(crate) fn parse(entries: &[String]) -> Result<Self> {
        let mut networks = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // ipnetwork parses "10.0.0.1/8" and "10.0.0.1"; keep the explicit
            // prefix when present so a mistyped CIDR is not silently widened.
            let network = IpNetwork::from_str(entry)
                .map_err(|e| anyhow!("invalid --allow-ips entry {entry:?}: {e}"))?;
            networks.push(network);
        }
        if networks.is_empty() {
            bail!("--allow-ips was given but contains no usable IP or CIDR entries");
        }
        Ok(Self { networks })
    }

    /// True if `ip` is covered by any entry. IPv4-mapped IPv6 peers
    /// (`::ffff:a.b.c.d`, as produced by dual-stack listeners) are compared
    /// as IPv4 so an IPv4 rule matches them.
    pub(crate) fn allows(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        self.networks.iter().any(|n| n.contains(ip))
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

    /// Shared per-client-IP connection limiter for the listener. `None`
    /// disables the limit. Implementations build it once (in `new`) so every
    /// accept path and the WebSocket upgrade path share one counter map.
    fn conn_limiter(&self) -> Option<ConnLimiter> {
        None
    }

    /// Optional source-address allowlist for the listener. `None` accepts
    /// every source; `Some` drops every peer it does not cover at accept time.
    fn ip_whitelist(&self) -> Option<IpWhitelist> {
        None
    }

    /// Optional region allowlist for the listener. `None` accepts every
    /// source; `Some` drops every peer whose address falls outside the
    /// configured regions at accept time.
    fn geo_check(&self) -> Option<SharedGeoCheck> {
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
        let limiter = self.conn_limiter();
        let whitelist = self.ip_whitelist();
        let geo = self.geo_check();
        info!("Listening on {}", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            // Allowlist first: a rejected peer is dropped here, so it never
            // consumes a limiter slot, a task or any connection buffers.
            if let Some(whitelist) = whitelist.as_ref()
                && !whitelist.allows(addr.ip())
            {
                debug!(
                    "dropping connection from {} (not in --allow-ips)",
                    addr.ip()
                );
                continue;
            }
            // Region allowlist: same accept-time drop, decided from the TCP
            // peer address only.
            if let Some(geo) = geo.as_ref() {
                match geo.allows(addr.ip()) {
                    Ok(true) => {}
                    Ok(false) => {
                        debug!(
                            "dropping connection from {} (outside --allow-region)",
                            addr.ip()
                        );
                        continue;
                    }
                    Err(e) => {
                        // Fail closed, but keep the reason visible.
                        warn!("geo lookup failed for {}: {e:#}; dropping", addr.ip());
                        continue;
                    }
                }
            }
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
            // Shared holder so the connection's per-IP slot can be transferred
            // to the WS handler task on upgrade instead of double-counting.
            let guard_holder = Arc::new(Mutex::new(guard));
            let holder_in_handler = guard_holder.clone();
            tokio::spawn(async move {
                if let Err(err) = serve_builder()
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |mut req| {
                            let proxy = proxy.clone();
                            let holder = holder_in_handler.clone();
                            async move {
                                // Share the connection's guard holder with
                                // requests that may outlive the connection
                                // (WS upgrade takes the guard out of it).
                                req.extensions_mut().insert(holder);
                                proxy.handler(req, addr).await
                            }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
                // Connection over: release the slot unless a WS task took it.
                if let Ok(mut g) = guard_holder.lock() {
                    g.take();
                }
            });
        }
    }

    async fn serve_tls(self, acceptor: TlsAcceptor) -> Result<()> {
        let addr = self.listen_addr()?;
        let listener = TcpListener::bind(addr).await?;
        let limiter = self.conn_limiter();
        let whitelist = self.ip_whitelist();
        let geo = self.geo_check();
        info!("Listening on {} (TLS)", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            // Reject before the TLS handshake: a non-whitelisted peer never
            // gets a rustls session, a limiter slot or a task.
            if let Some(whitelist) = whitelist.as_ref()
                && !whitelist.allows(addr.ip())
            {
                debug!(
                    "dropping connection from {} (not in --allow-ips)",
                    addr.ip()
                );
                continue;
            }
            // Region allowlist: same accept-time drop, before the TLS
            // handshake, decided from the TCP peer address only.
            if let Some(geo) = geo.as_ref() {
                match geo.allows(addr.ip()) {
                    Ok(true) => {}
                    Ok(false) => {
                        debug!(
                            "dropping connection from {} (outside --allow-region)",
                            addr.ip()
                        );
                        continue;
                    }
                    Err(e) => {
                        // Fail closed, but keep the reason visible.
                        warn!("geo lookup failed for {}: {e:#}; dropping", addr.ip());
                        continue;
                    }
                }
            }
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
            let guard_holder = Arc::new(Mutex::new(guard));
            let holder_in_handler = guard_holder.clone();
            tokio::spawn(async move {
                let tls_stream = match tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        warn!("TLS accept error from {addr}: {e:?}");
                        if let Ok(mut g) = guard_holder.lock() {
                            g.take();
                        }
                        return;
                    }
                    Err(_) => {
                        warn!("TLS handshake timeout from {addr}");
                        if let Ok(mut g) = guard_holder.lock() {
                            g.take();
                        }
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                if let Err(err) = serve_builder()
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(move |mut req| {
                            let proxy = proxy.clone();
                            let holder = holder_in_handler.clone();
                            async move {
                                req.extensions_mut().insert(holder);
                                proxy.handler(req, addr).await
                            }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
                // Connection over: release the slot unless a WS task took it.
                if let Ok(mut g) = guard_holder.lock() {
                    g.take();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn wl(entries: &[&str]) -> IpWhitelist {
        let entries: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        IpWhitelist::parse(&entries).expect("whitelist should parse")
    }

    #[test]
    fn allows_single_bare_address() {
        let w = wl(&["10.1.2.3"]);
        assert!(w.allows(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!w.allows(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 4))));
    }

    #[test]
    fn allows_cidr_range() {
        let w = wl(&["10.0.0.0/8"]);
        assert!(w.allows(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))));
        assert!(!w.allows(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn allows_multiple_mixed_entries() {
        let w = wl(&["192.168.1.0/24", "203.0.113.7", "2001:db8::/32"]);
        assert!(w.allows(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        assert!(w.allows(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert!(w.allows(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!w.allows(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn ipv4_mapped_v6_peer_matches_ipv4_rule() {
        // Dual-stack listeners report `::ffff:10.0.0.5`; the IPv4 rule must match.
        let w = wl(&["10.0.0.0/24"]);
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 5).to_ipv6_mapped());
        assert!(w.allows(mapped));
    }

    #[test]
    fn blank_entries_are_skipped() {
        let w = wl(&["", "  ", "10.0.0.1"]);
        assert!(w.allows(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn invalid_entry_is_rejected() {
        let entries = vec!["not-an-ip".to_string()];
        assert!(IpWhitelist::parse(&entries).is_err());
    }

    #[test]
    fn only_blank_entries_is_rejected() {
        // A configured-but-empty list must not silently become "allow all".
        let entries = vec!["".to_string(), " ".to_string()];
        assert!(IpWhitelist::parse(&entries).is_err());
    }

    #[test]
    fn default_proxy_has_no_whitelist() {
        // Trait default: a Proxy that does not override ip_whitelist accepts
        // every source — the default must be None, not deny-all.
        #[derive(Clone)]
        struct StubProxy;

        impl Proxy for StubProxy {
            type Options = ();

            async fn new(_opts: ()) -> Result<Self> {
                Ok(Self)
            }

            fn listen_addr(&self) -> Result<SocketAddr> {
                "127.0.0.1:0".parse().map_err(Into::into)
            }

            fn handler(
                self,
                _request: Request<Incoming>,
                _addr: SocketAddr,
            ) -> impl Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send
            {
                async { unreachable!("stub proxy never serves requests") }
            }
        }

        assert!(StubProxy.ip_whitelist().is_none());
    }
}
