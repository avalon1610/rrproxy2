use crate::crypto::Cipher;
use crate::proxy::CONTENT_TYPE_HEADER;
use anyhow::{Context, Result, anyhow, bail};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use hyper::{HeaderMap, Response};
use tracing::trace;

/// Trait for response conversion between reqwest and hyper formats
/// Handles both conversion and encryption/decryption of response bodies
pub(crate) trait ResponseConverter {
    /// Convert reqwest response to hyper response with encryption/decryption
    async fn convert<C: CipherHelper>(
        self,
        cipher: C,
        id: impl AsRef<str>,
    ) -> Result<Response<Full<Bytes>>>;
}

pub(crate) struct Decryptor<'a>(pub(crate) &'a Cipher);
pub(crate) struct Encryptor<'a>(pub(crate) &'a Cipher);

pub(crate) trait CipherHelper {
    fn process(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>>;

    fn adjust_content_type(headers: &mut HeaderMap) -> Result<()>;

    fn name() -> &'static str;
}

impl CipherHelper for Decryptor<'_> {
    fn name() -> &'static str {
        "decryptor"
    }

    fn process(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        self.0.decrypt(data)
    }

    fn adjust_content_type(headers: &mut HeaderMap) -> Result<()> {
        let original = headers
            .get(CONTENT_TYPE_HEADER)
            .ok_or_else(|| anyhow!("No original content type header"))?;
        if !original.is_empty() {
            headers.insert(CONTENT_TYPE, original.clone());
        }
        Ok(())
    }
}

impl CipherHelper for Encryptor<'_> {
    fn name() -> &'static str {
        "encryptor"
    }

    fn process(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        self.0.encrypt(data)
    }

    fn adjust_content_type(headers: &mut HeaderMap) -> Result<()> {
        let original = headers
            .get(CONTENT_TYPE)
            .map(|v| v.to_str().unwrap_or(""))
            .unwrap_or("");

        headers.insert(CONTENT_TYPE_HEADER, original.parse()?);
        headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());

        Ok(())
    }
}

impl ResponseConverter for reqwest::Response {
    async fn convert<C: CipherHelper>(
        self,
        cipher: C,
        id: impl AsRef<str>,
    ) -> Result<Response<Full<Bytes>>> {
        let id = id.as_ref();
        let status = self.status();
        let version = self.version();
        let mut headers = self.headers().clone();
        let body_bytes = self.bytes().await?;

        trace!(
            "[{id}] convert original response headers: {:?} body len: {}\n{}",
            headers,
            body_bytes.len(),
            str::from_utf8(&body_bytes).unwrap_or("<binary>")
        );
        // the response body if it's not empty
        let body = if body_bytes.is_empty() {
            body_bytes
        } else {
            let body = match cipher.process(&body_bytes) {
                Ok(data) => Bytes::from(data),
                Err(e) => {
                    bail!(
                        "[{id}] Failed to process response body: {e:?} by {}",
                        C::name()
                    );
                }
            };

            C::adjust_content_type(&mut headers).context("adjust content type error")?;
            headers.insert(CONTENT_LENGTH, body.len().to_string().parse()?);
            // remove transfer-encoding header if present, Transfer-encoding: chunked not compatible with Content-Length header
            headers.remove(TRANSFER_ENCODING);
            body
        };

        let mut response = Response::builder().status(status).version(version);
        for (name, value) in headers.iter() {
            response = response.header(name, value);
        }

        response
            .body(Full::new(body))
            .map_err(|e| anyhow!("failed to build response: {e:?}"))
    }
}
