use std::time::Instant;

use crate::{
    convert::{Decryptor, ResponseConverter},
    crypto::{Cipher, default_token, package_info},
    local::{build_full_url, new_client},
    options::LocalModeOptions,
    proxy::{CHUNK_INDEX_HEADER, ORIGINAL_URL_HEADER, TOTAL_CHUNKS_HEADER, TRANSACTION_ID_HEADER},
    remote::HostEx,
};
use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response, Uri,
    body::{Bytes, Incoming},
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING, USER_AGENT},
    http::request::Parts,
};
use tracing::{debug, info, trace};
use uuid::Uuid;

pub(crate) struct Forwarder {
    chunks: Vec<Bytes>,
    remote_addr: String,
    client: reqwest::Client,
    parts: Parts,
    token: String,
    is_https: bool,
}

impl Forwarder {
    pub(crate) async fn new(
        parts: Parts,
        body: Incoming,
        opts: &LocalModeOptions,
        is_https: bool,
    ) -> Result<Self> {
        let chunk_size = opts.chunk;
        let remote_addr = opts.remote.clone();

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

        // because we use ChaCha20-Poly1305, the encrypted chunk size will be increased by
        // - 12 (nonce length)
        // - 16 (authentication tag length)
        // - and the associated data length
        let chunk_size = chunk_size - 12 - 16 - package_info().len();
        // use Base64 will increase the size
        let chunk_size = 3 * (chunk_size / 4);
        let chunks = if length > chunk_size {
            // split the body into chunks, if length is larger than chunk size.
            // but we use random real chunk size (which all smaller than the config chunk size),
            // this decreases the fingerprint of the request.
            let mut chunks = vec![];
            let low = (chunk_size as f32 * 0.5) as usize;
            loop {
                if body.is_empty() {
                    break;
                }

                let real_chunk_size = rand::random_range(low..chunk_size);
                if body.len() < chunk_size {
                    chunks.push(body);
                    break;
                } else {
                    chunks.push(body.split_to(real_chunk_size));
                }
            }

            chunks
        } else {
            vec![body]
        };

        let client = new_client(opts, false)?;
        Ok(Self {
            chunks,
            remote_addr,
            client,
            is_https,
            parts,
            token: opts.common.token.clone().unwrap_or_else(default_token),
        })
    }

    pub(crate) async fn apply(self) -> Result<Response<Full<Bytes>>> {
        let id = Uuid::new_v4().to_string();
        let url = build_full_url(self.is_https, &self.parts)?;

        let mut headers = self.parts.headers;
        headers.insert(USER_AGENT, DEFAULT_USER_AGENT.parse()?);

        let now = Instant::now();
        info!("[{id}] transaction begins");

        // we need re-write the HOST header
        let remote_url: Uri = (self.remote_addr).parse()?;
        let host = remote_url.get_host()?;
        headers.insert(HOST, host.parse()?);

        // set uuid for this transaction
        headers.insert(TRANSACTION_ID_HEADER, id.parse()?);

        // get original content-type
        let content_type = headers
            .get(CONTENT_TYPE)
            .map(|c| c.to_str().unwrap_or(""))
            .unwrap_or("");

        // set the url info
        let info = format!(
            "{}+{:?}+{}+{}",
            self.parts.method, self.parts.version, content_type, url
        );

        let cipher = Cipher::new(&self.token);
        debug!("[{id}] build original info: {info}");
        headers.insert(
            ORIGINAL_URL_HEADER,
            Base64::encode_string(&cipher.encrypt(info)?).parse()?,
        );

        // reset content-type
        headers.insert(CONTENT_TYPE, "text/plain".parse()?);

        let total = self.chunks.len();
        headers.insert(TOTAL_CHUNKS_HEADER, total.to_string().parse()?);

        let mut last_response = None;
        for (index, chunk) in self.chunks.into_iter().enumerate() {
            headers.insert(CHUNK_INDEX_HEADER, index.to_string().parse()?);
            let request = self.client.post(&self.remote_addr);

            let request = if chunk.is_empty() {
                debug!(
                    "[{id}] forwarding to {} with chunk index {} empty body",
                    self.remote_addr, index
                );
                headers.remove(CONTENT_LENGTH);
                request
            } else {
                let chunk = cipher.encrypt(chunk)?;
                let chunk = Base64::encode_string(&chunk);

                debug!(
                    "[{id}] forwarding to {} with chunk index {} size {}",
                    self.remote_addr,
                    index,
                    chunk.len()
                );
                // we need reset the Content-Length headers
                headers.insert(CONTENT_LENGTH, chunk.len().to_string().parse()?);
                request.body(chunk)
            };
            let request = request.headers(headers.clone()).build()?;
            trace!("[{id}] request headers: {:?}", request.headers());

            let response = self.client.execute(request).await?;
            if index == total - 1 {
                last_response = Some(response);
            }
        }

        let last_response =
            last_response.ok_or_else(|| anyhow!("no response for {id}, {}", self.parts.uri))?;
        info!(
            "[{id}] transaction ends, last response status: {}, cost {:?}",
            last_response.status(),
            now.elapsed()
        );

        // Use the existing cipher instance to decrypt the response
        last_response
            .convert(Decryptor(&cipher), &id)
            .await
            .with_context(|| format!("[{id}] response decrypt and convert error"))
    }
}

// TODO: make this configurable
const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
