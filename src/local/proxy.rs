use crate::{
    local::{
        buf::PreBuffered,
        cert::CertManager,
        forward::{self},
    },
    options::LocalModeOptions,
};
use anyhow::{Context, Result, anyhow, bail};
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    service::service_fn,
    upgrade::on,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::{Builder, upgrade::downcast},
};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct Proxy {
    cm: Arc<CertManager>,
    opts: Arc<LocalModeOptions>,
}

impl Proxy {
    pub async fn new(opts: LocalModeOptions) -> Result<Self> {
        let mut cm = CertManager::new(&opts.cert, &opts.key, &opts.cache_dir).await?;

        if opts.generate_ca {
            cm.generate_ca_file(&opts.ca_common_name).await?;
        } else if !cm.has_issuer() {
            bail!(
                "No issuer found, you need use \"--generate-ca\" option to generate a CA certificate"
            );
        }

        Ok(Self {
            cm: Arc::new(cm),
            opts: Arc::new(opts),
        })
    }

    pub async fn serve(self) -> Result<()> {
        // Parse the listen address
        let addr: SocketAddr = self.opts.listen.parse()?;

        // Create TCP listener
        let listener = TcpListener::bind(addr).await?;
        info!("Listening on http://{}", addr);

        // Start the server
        loop {
            let (stream, addr) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let proxy = self.clone();

            // Spawn a task to handle the connection
            tokio::spawn(async move {
                if let Err(err) = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(
                        io,
                        service_fn(|req| {
                            let proxy = proxy.clone();
                            async move { proxy.main_handler(req, addr).await }
                        }),
                    )
                    .await
                {
                    warn!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn main_handler(
        self,
        req: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let res = match req.method() {
            &Method::CONNECT => {
                debug!("CONNECT request from {}", addr);
                // Handle HTTPS CONNECT request
                self.handle_connect(req).await
            }
            _ => {
                debug!("{} request from {}", req.method(), addr);
                // Handle regular HTTP requests
                self.handle_http_request(req).await
            }
        };

        match res {
            Ok(r) => Ok(r),
            Err(err) => {
                let err = format!("{err:?}");
                warn!("handle error: {err}");

                return Ok(Response::builder().status(400).body(err.into()).unwrap()); // this unwrap never fails, because only set the status code
            }
        }
    }

    async fn handle_connect(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
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

        let tls_acceptor = create_tls_acceptor(&cert, &key)?;
        let tls_stream = tls_acceptor.accept(buffer).await?;

        if let Err(e) = Builder::new(TokioExecutor::new())
            .serve_connection(
                TokioIo::new(tls_stream),
                service_fn(move |req| {
                    let proxy = self.clone();
                    async move { proxy.handle_http_request(req).await }
                }),
            )
            .await
        {
            warn!("Error serve connection from TLS stream: {:?}", e);
        }

        Ok(())
    }

    async fn handle_http_request(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let forwarder = forward::Forwarder::new(req, &self.opts).await?;
        let response = forwarder.apply().await?;

        Ok(response)
    }
}

fn create_tls_acceptor(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
    // Parse certificate
    let cert_chain = certs(&mut cert_pem.as_bytes())
        .map_err(|_| anyhow!("Failed to parse certificate"))?
        .into_iter()
        .map(Certificate)
        .collect();

    // Parse private key
    let mut keys = pkcs8_private_keys(&mut key_pem.as_bytes())
        .map_err(|_| anyhow!("Failed to parse private key"))?;

    let key = keys.pop().ok_or_else(|| anyhow!("No private key found"))?;

    // Create server config
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKey(key))
        .map_err(|err| anyhow!("Failed to create TLS config: {}", err))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
