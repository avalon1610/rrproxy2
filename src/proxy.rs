use anyhow::{Result};
use http_body_util::Full;
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{convert::Infallible, net::SocketAddr, future::Future};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub(crate) trait Proxy: Clone
where
    Self: Send + Sync + 'static,
{
    type Options;
    async fn new(opts: Self::Options) -> Result<Self>;

    fn listen_addr(&self) -> Result<SocketAddr>;

    fn handler(
        self,
        request: Request<Incoming>,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send;

    async fn serve(self) -> Result<()> {
        let addr = self.listen_addr()?;
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let proxy = self.clone();

            tokio::spawn(async move {
                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(|req| {
                            let proxy = proxy.clone();
                            async move { proxy.handler(req, addr).await }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {}", err);
                }
            });
        }
    }
}

pub(crate) const CHUNK_INDEX_HEADER: &str = "X-Fetch-Id";
pub(crate) const TRANSACTION_ID_HEADER: &str = "X-Request-Id";
/// this header should be encrypted, process is
/// 1. combine: <original method>+<original_version>+<original url> (use plus(+) sign to separate)
/// 2. encrypt the combined string
/// 3. encoded using base64
pub(crate) const ORIGINAL_URL_HEADER: &str = "X-Referer";
pub(crate) const TOTAL_CHUNKS_HEADER: &str = "X-Robots-Tag";
pub(crate) const CONTENT_TYPE_HEADER: &str = "X-Content-Type";
