use std::time::Instant;

use crate::{
    convert::{Decryptor, ResponseConverter},
    crypto::{Cipher, default_token},
    options::LocalModeOptions,
    proxy::{CHUNK_INDEX_HEADER, ORIGINAL_URL_HEADER, TOTAL_CHUNKS_HEADER, TRANSACTION_ID_HEADER},
};
use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Request, Response, Uri,
    body::{Bytes, Incoming},
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING},
    http::request::Parts,
};
use reqwest::Proxy;
use tracing::debug;
use uuid::Uuid;

pub struct Forwarder {
    chunks: Vec<Bytes>,
    remote_addr: String,
    client: reqwest::Client,
    parts: Parts,
    token: String,
    is_https: bool,
}

impl Forwarder {
    pub async fn new(
        req: Request<Incoming>,
        opts: &LocalModeOptions,
        is_https: bool,
    ) -> Result<Self> {
        let chunk_size = opts.chunk;
        let remote_addr = opts.remote.clone();

        let (parts, body) = req.into_parts();
        let mut body = body.collect().await?.to_bytes();
        if let Some(encoding) = parts.headers.get(TRANSFER_ENCODING) {
            // FIXME: Implement support for transfer encoding
            bail!(
                "transfer encoding: [{:?}] is not supported for now",
                encoding
            );
        }

        let length = if let Some(content_length) = parts.headers.get(CONTENT_LENGTH) {
            let content_length = content_length
                .to_str()
                .with_context(|| format!("invalid {CONTENT_LENGTH} header, non ascii"))?;
            let content_length = content_length
                .parse::<usize>()
                .with_context(|| format!("invalid {CONTENT_LENGTH} header, not number"))?;
            if content_length != body.len() {
                bail!(
                    "{CONTENT_LENGTH} {content_length} is not match to the actually body length {}",
                    body.len()
                );
            }

            content_length
        } else {
            body.len()
        };

        let chunks = if length > chunk_size {
            // split the body into chunks, if length is larger than chunk size.
            // but we use random real chunk size (which all smaller than the config chunk size),
            // this decreases the fingerprint of the request.
            let mut chunks = vec![];
            let low = (chunk_size as f32 * 0.8) as usize;
            loop {
                if body.is_empty() {
                    break;
                }

                let real_chunk_size = rand::random_range(low..chunk_size);
                let real_chunk_size = real_chunk_size.min(body.len());
                chunks.push(body.split_to(real_chunk_size));
            }

            chunks
        } else {
            vec![body]
        };

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
        let client = if let Some(proxy) = &opts.common.proxy {
            client
                .proxy(Proxy::all(proxy).context("invalid proxy option")?)
                .build()?
        } else {
            // add no_proxy to make it not use http_proxy and https_proxy env variables
            client.no_proxy().build()?
        };

        Ok(Self {
            chunks,
            remote_addr,
            client,
            is_https,
            parts,
            token: opts.common.token.clone().unwrap_or_else(default_token),
        })
    }

    pub async fn apply(self) -> Result<Response<Full<Bytes>>> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", USER_AGENT.parse()?);
        let uuid = Uuid::new_v4().to_string();
        let now = Instant::now();
        debug!("begin transaction {}", uuid);
        headers.insert(TRANSACTION_ID_HEADER, uuid.parse()?);
        let content_type = self
            .parts
            .headers
            .get(CONTENT_TYPE)
            .map(|c| c.to_str().unwrap_or(""))
            .unwrap_or("");
        let url = self.build_full_url(&self.parts)?;

        let info = format!(
            "{}+{:?}+{}+{}",
            self.parts.method, self.parts.version, content_type, url
        );
        debug!("build original info: {info}");

        let cipher = Cipher::new(&self.token);
        headers.insert(
            ORIGINAL_URL_HEADER,
            Base64::encode_string(&cipher.encrypt(info)?).parse()?,
        );

        for (key, value) in self.parts.headers.iter() {
            headers.insert(key.clone(), value.clone());
        }

        let total = self.chunks.len();
        headers.insert(TOTAL_CHUNKS_HEADER, total.to_string().parse()?);

        let mut last_response = None;
        for (index, chunk) in self.chunks.into_iter().enumerate() {
            headers.insert(CHUNK_INDEX_HEADER, index.to_string().parse()?);
            let chunk = cipher.encrypt(chunk)?;

            // we need reset the Content-Length and Content-Type headers
            headers.insert(CONTENT_LENGTH, chunk.len().to_string().parse()?);
            headers.insert(CONTENT_TYPE, "application/octet-stream".parse()?);
            debug!(
                "forwarding to {} [{}] with chunk index {} size {}",
                uuid,
                self.remote_addr,
                index,
                chunk.len()
            );

            let response = self
                .client
                .post(&self.remote_addr)
                .headers(headers.clone())
                .body(chunk)
                .send()
                .await?;

            if index == total - 1 {
                last_response = Some(response);
            }
        }

        let last_response =
            last_response.ok_or_else(|| anyhow!("no response for {uuid}, {}", self.parts.uri))?;
        debug!(
            "end transaction {}, last response status: {}, cost {:?}",
            uuid,
            last_response.status(),
            now.elapsed()
        );

        // Use the existing cipher instance to decrypt the response
        last_response
            .convert(Decryptor(&cipher))
            .await
            .context("response decrypt and convert error")
    }

    fn build_full_url(&self, parts: &Parts) -> Result<Uri> {
        if parts.uri.scheme().is_some() && parts.uri.authority().is_some() {
            return Ok(parts.uri.clone());
        }

        let host = parts
            .headers
            .get(HOST)
            .ok_or_else(|| anyhow!("Can not get {HOST} header"))?
            .to_str()?;

        Ok(format!(
            "{}://{}{}{}",
            if self.is_https { "https" } else { "http" },
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
}

// TODO: make this configurable
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
