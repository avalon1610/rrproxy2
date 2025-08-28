use crate::options::RemoteModeOptions;
use anyhow::Result;
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
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Proxy {
    opts: Arc<RemoteModeOptions>,
    transactions: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl Proxy {
    pub fn new(opts: RemoteModeOptions) -> Self {
        Proxy {
            opts: Arc::new(opts),
            transactions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn serve(self) -> Result<()> {
        let addr: SocketAddr = self.opts.listen.parse()?;
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on {}", addr);

        loop {
            let (stream, addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let proxy = self.clone();

            tokio::spawn(async move {
                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection(
                        io,
                        service_fn(|req| {
                            let proxy = proxy.clone();
                            async move { proxy.main_handler(req, addr).await }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {}", err);
                }
            });
        }
    }

    async fn main_handler(
        &self,
        _req: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // assume we only receiving request only from local part
        //
        info!("Accepted connection from {}", addr);

        Ok(Response::new(Full::new(Bytes::new())))
    }
}
