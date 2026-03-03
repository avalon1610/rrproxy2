use crate::local::{LocalProxy, buf::PreBuffered};
use anyhow::{Context, Result, anyhow};
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
    upgrade::on,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::{Builder, upgrade::downcast},
};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

impl LocalProxy {
    pub(crate) async fn handle_connect(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>> {
        // Extract the target host from the CONNECT request
        let target_host = req
            .uri()
            .host()
            .ok_or_else(|| anyhow!("header host not found"))?;

        // Send "Connection Established" response
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(("Connection Established").into())
            .unwrap(); // this unwrap never fails, because only set the status code

        let (cert, key) = self
            .cm
            .generate_srv_pem(target_host)
            .await
            .context("generate server certificate error")?;

        tokio::spawn({
            let proxy = self.clone();
            async move {
                if let Err(e) = proxy.handle_tls(req, &cert, &key).await {
                    warn!("Error handling TLS connection: {:?}", e);
                }
            }
        });

        Ok(response)
    }

    async fn handle_tls(self, req: Request<Incoming>, cert: &str, key: &str) -> Result<()> {
        let upgraded = on(req).await?;
        let stream =
            downcast::<TokioIo<TcpStream>>(upgraded).map_err(|_| anyhow!("Failed to downcast"))?;
        let buffer = PreBuffered::new(stream.read_buf, stream.io.into_inner());

        let tls_acceptor = create_tls_acceptor(cert, key)?;
        let tls_stream = tls_acceptor.accept(buffer).await?;

        if let Err(e) = Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(tls_stream),
                service_fn(move |req| {
                    let proxy = self.clone();
                    async move { proxy.handle_request(req, true).await }
                }),
            )
            .await
        {
            warn!("Error serve connection from TLS stream: {:?}", e);
        }

        Ok(())
    }
}

fn create_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    let (cert_chain, key) =
        crate::tls::tls_parts_from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
    crate::tls::tls_acceptor_from_parts(cert_chain, key)
}
