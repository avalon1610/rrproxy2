use crate::{
    convert::{CipherHelper, ResponseConverter},
    local::{bypass::Bypass, cert::CertManager, forward::Forwarder},
    options::LocalModeOptions,
    proxy::Proxy,
};
use anyhow::{Context, Result, bail};
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, Uri,
    body::{Body, Bytes, Incoming},
    header::{
        CONNECTION, HOST, HeaderName, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    },
    http::request::Parts,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tracing::{info, trace, warn};

#[derive(Clone)]
pub(crate) struct LocalProxy {
    cm: Arc<CertManager>,
    opts: Arc<LocalModeOptions>,
    bypass: Arc<Option<Bypass>>,
    proxy_client: Option<reqwest::Client>,
    direct_client: reqwest::Client,
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
        let bypass = Arc::new(opts.bypass.as_deref().map(Bypass::new));

        // Create two clients: one with proxy (if configured) and one without proxy
        let proxy_client = opts
            .common
            .proxy
            .as_ref()
            .map(|proxy| new_client(Some(proxy)))
            .transpose()?;
        let direct_client = new_client(None)?;

        Ok(Self {
            cm: Arc::new(cm),
            bypass,
            opts: Arc::new(opts),
            proxy_client,
            direct_client,
        })
    }

    async fn handler(
        self,
        req: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let res = match req.method() {
            &Method::CONNECT => {
                info!("CONNECT request from {}", addr);
                // Handle HTTPS CONNECT request
                self.handle_connect(req).await
            }
            _ => {
                info!("{} request from {}", req.method(), addr);
                // Handle regular HTTP requests
                self.handle_request(req, false).await
            }
        };

        match res {
            Ok(r) => Ok(r),
            Err(err) => {
                let err = format!("{err:?}");
                warn!("handle error: {err}");

                Ok(Response::builder().status(400).body(err.into()).unwrap()) // this unwrap never fails, because only set the status code
            }
        }
    }

    fn listen_addr(&self) -> Result<SocketAddr> {
        Ok(self.opts.common.listen.parse()?)
    }
}

impl LocalProxy {
    /// Returns the proxy client if available, otherwise returns the direct client
    fn client(&self) -> &reqwest::Client {
        self.proxy_client.as_ref().unwrap_or(&self.direct_client)
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        is_https: bool,
    ) -> Result<Response<Full<Bytes>>> {
        let size_hint = req.body().size_hint();
        trace!("size hint: {:?}", size_hint);
        let (parts, body) = req.into_parts();
        let uri = build_full_url(is_https, &parts)?;
        let bypass = self
            .bypass
            .as_ref()
            .as_ref()
            .map(|b| b.check(&uri))
            .unwrap_or_default();

        let response = if !bypass
            && (self.opts.full
                || size_hint.lower() as usize > self.opts.chunk
                || size_hint
                    .upper()
                    .is_some_and(|u| u as usize > self.opts.chunk))
        {
            Forwarder::new(parts, body, &self.opts, is_https, self.client().clone())
                .await?
                .apply()
                .await?
        } else {
            // if bypass, always use direct client
            let client = if bypass {
                &self.direct_client
            } else {
                self.client()
            };

            let req = client.convert(parts, body, uri).await?;
            tracing::debug!(
                "Direct request without forwarding: {}, bypass: {}",
                req.url(),
                bypass
            );

            let response = client.execute(req).await?;
            response.convert(Plain, "Direct").await?
        };

        Ok(response)
    }
}

struct Plain;

impl CipherHelper for Plain {
    fn process(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        Ok(data.as_ref().to_vec())
    }

    fn adjust_content_type(_headers: &mut hyper::HeaderMap, _body_len: usize) -> Result<()> {
        Ok(())
    }

    fn name() -> &'static str {
        "Plain"
    }
}

fn new_client(proxy: Option<&String>) -> Result<reqwest::Client> {
    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true);
    if let Some(proxy) = proxy {
        Ok(client
            .proxy(reqwest::Proxy::all(proxy).context("invalid proxy option")?)
            .build()?)
    } else {
        // add no_proxy to make it not use http_proxy and https_proxy env variables
        Ok(client.no_proxy().build()?)
    }
}

trait RequestConvert {
    async fn convert(&self, parts: Parts, body: Incoming, uri: Uri) -> Result<reqwest::Request>;
}

impl RequestConvert for reqwest::Client {
    async fn convert(&self, parts: Parts, body: Incoming, uri: Uri) -> Result<reqwest::Request> {
        let body = body.collect().await?.to_bytes();
        const SKIP: &[HeaderName] = &[
            HOST,
            CONNECTION,
            PROXY_AUTHORIZATION,
            PROXY_AUTHENTICATE,
            UPGRADE,
            TE,
            TRAILER,
            TRANSFER_ENCODING,
        ];

        let mut builder = self.request(parts.method, uri.to_string());
        for (key, value) in parts.headers {
            if let Some(key) = key {
                if SKIP.contains(&key) {
                    continue;
                }

                builder = builder.header(key, value);
            }
        }

        Ok(builder.body(body).build()?)
    }
}

fn build_full_url(is_https: bool, parts: &Parts) -> Result<Uri> {
    if parts.uri.scheme().is_some() && parts.uri.authority().is_some() {
        return Ok(parts.uri.clone());
    }

    let host = parts
        .headers
        .get(HOST)
        .ok_or_else(|| anyhow::anyhow!("Can not get {HOST} header"))?
        .to_str()?;

    Ok(format!(
        "{}://{}{}{}",
        if is_https { "https" } else { "http" },
        host,
        parts.uri.path(),
        if let Some(query) = parts.uri.query() {
            format!("?{}", query)
        } else {
            "".to_owned()
        }
    )
    .parse()?)
}

mod buf;
mod bypass;
mod cert;
mod forward;
mod tls;
