use crate::{
    crypto::{Decryptor, Encryptor, default_token},
    local::{cert::CertManager, forward::Forwarder},
    options::LocalModeOptions,
    proxy::Proxy,
};
use anyhow::{Result, bail};
use http_body_util::Full;
use hyper::{
    Method, Request, Response,
    body::{Bytes, Incoming},
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tracing::{debug, warn};

#[derive(Clone)]
pub struct LocalProxy {
    cm: Arc<CertManager>,
    opts: Arc<LocalModeOptions>,
}

impl Proxy for LocalProxy {
    type Options = LocalModeOptions;

    async fn new(opts: LocalModeOptions) -> Result<Self> {
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

    async fn handler(
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

    fn listen_addr(&self) -> Result<SocketAddr> {
        Ok(self.opts.common.listen.parse()?)
    }
}

impl LocalProxy {
    async fn handle_http_request(&self, req: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let forwarder = Forwarder::new(req, &self.opts).await?;
        let response = forwarder.apply().await?;

        Ok(response)
    }
}

mod buf;
mod cert;
mod forward;
mod tls;
