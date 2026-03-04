use std::time::Instant;

use crate::{
    convert::{Decryptor, ResponseConverter},
    crypto::{Cipher, default_token, package_info},
    header::Obfuscator,
    local::build_full_url,
    options::{DEFAULT_CHUNK, DEFAULT_REMOTE, LocalModeOptions},
    proxy::{
        CHUNK_INDEX_HEADER, COMMIT_INDEX_HEADER, ORIGINAL_URL_HEADER, TOTAL_CHUNKS_HEADER,
        TRANSACTION_ID_HEADER,
    },
    remote::HostEx,
};
use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use futures_util::{StreamExt, stream::FuturesUnordered};
use http_body_util::{BodyExt, Full};
use hyper::{
    Response, Uri,
    body::{Bytes, Incoming},
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, TRANSFER_ENCODING},
    http::request::Parts,
};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};
use uuid::Uuid;

pub(crate) struct Forwarder {
    chunks: Vec<Bytes>,
    remote_addr: String,
    client: reqwest::Client,
    parts: Parts,
    cipher: Arc<Cipher>,
    is_https: bool,
    no_base64: bool,
}

impl Forwarder {
    pub(crate) async fn new(
        parts: Parts,
        body: Incoming,
        opts: &LocalModeOptions,
        is_https: bool,
        client: reqwest::Client,
    ) -> Result<Self> {
        let chunk_size = opts.chunk.unwrap_or(DEFAULT_CHUNK);
        let remote_addr = opts.remote.clone().unwrap_or_else(|| DEFAULT_REMOTE.to_string());

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
        // use Base64 will increase the size (only if base64 is enabled)
        let chunk_size = if opts.common.no_base64.unwrap_or(false) {
            chunk_size
        } else {
            3 * (chunk_size / 4)
        };
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

        let cipher = Arc::new(Cipher::new(
            opts.common.token.clone().unwrap_or_else(default_token),
        ));
        Ok(Self {
            chunks,
            remote_addr,
            client,
            is_https,
            parts,
            cipher,
            no_base64: opts.common.no_base64.unwrap_or(false),
        })
    }

    pub(crate) async fn apply(self) -> Result<Response<Full<Bytes>>> {
        let id = Uuid::new_v4().to_string();
        let url = build_full_url(self.is_https, &self.parts)?;

        let mut headers = self.parts.headers;

        let now = Instant::now();
        info!("[{id}] transaction begins");

        Obfuscator::encode(&mut headers)?;

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

        debug!("[{id}] build original info: {info}");
        headers.insert(
            ORIGINAL_URL_HEADER,
            Base64::encode_string(&self.cipher.encrypt(info)?).parse()?,
        );

        // reset content-type based on whether base64 is used for body
        let content_type = if self.no_base64 {
            "application/octet-stream"
        } else {
            "text/plain"
        };
        headers.insert(CONTENT_TYPE, content_type.parse()?);

        let total = self.chunks.len();
        headers.insert(TOTAL_CHUNKS_HEADER, total.to_string().parse()?);

        // Create futures for all chunk requests using iterator and collect into FuturesUnordered
        let mut futures: FuturesUnordered<_> = self
            .chunks
            .into_iter()
            .enumerate()
            .map(|(index, chunk)| {
                // Clone necessary data for each future
                let client = self.client.clone();
                let remote_addr = self.remote_addr.clone();
                let mut chunk_headers = headers.clone();
                let chunk_cipher = self.cipher.clone();
                let chunk_id = id.clone();
                let no_base64 = self.no_base64;

                async move {
                    chunk_headers.insert(CHUNK_INDEX_HEADER, index.to_string().parse()?);

                    let request = client.post(&remote_addr);
                    let request = if chunk.is_empty() {
                        debug!(
                            "[{chunk_id}] forwarding to {} with chunk index {} empty body",
                            remote_addr, index
                        );
                        chunk_headers.remove(CONTENT_LENGTH);
                        request
                    } else {
                        let encrypted_chunk = chunk_cipher.encrypt(chunk)?;
                        let (body_data, body_len) = if no_base64 {
                            // Send raw binary data
                            let len = encrypted_chunk.len();
                            (encrypted_chunk, len)
                        } else {
                            // Encode as base64 string
                            let encoded = Base64::encode_string(&encrypted_chunk);
                            let len = encoded.len();
                            (encoded.into_bytes(), len)
                        };

                        debug!(
                            "[{chunk_id}] forwarding to {} with chunk index {} size {}",
                            remote_addr, index, body_len
                        );
                        // we need reset the Content-Length headers
                        chunk_headers.insert(CONTENT_LENGTH, body_len.to_string().parse()?);
                        request.body(body_data)
                    };

                    let request = request.headers(chunk_headers).build()?;
                    trace!("[{chunk_id}] request headers: {:?}", request.headers());

                    let response = client.execute(request).await?;

                    // Return the index along with the response to identify the last chunk
                    Ok::<_, anyhow::Error>((index, response))
                }
            })
            .collect();

        // Process chunk responses as they complete, returning immediately when we get the last chunk
        let mut last_response = None;

        while let Some(result) = futures.next().await {
            let (i, response) = result?;
            trace!(
                "[{id}] receiving: index: {} response: {:?}",
                i,
                response.headers()
            );

            let Some(commit_index) = response.headers().get(COMMIT_INDEX_HEADER) else {
                continue;
            };

            let Ok(commit_index) = commit_index.to_str() else {
                warn!("commit index {commit_index:?} can not conver to str");
                continue;
            };

            let Ok(commit_index) = commit_index.parse::<usize>() else {
                warn!("commit index {commit_index} can not conver to usize");
                continue;
            };

            if commit_index == i {
                last_response = Some(response);
                break;
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
            .convert(Decryptor(&self.cipher), &id)
            .await
            .with_context(|| format!("[{id}] response decrypt and convert error"))
    }
}
