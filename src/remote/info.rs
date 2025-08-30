use crate::{
    crypto::Cipher,
    proxy::{CHUNK_INDEX_HEADER, ORIGINAL_URL_HEADER, TOTAL_CHUNKS_HEADER, TRANSACTION_ID_HEADER},
};
use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use hyper::{Request, body::Incoming};

#[derive(Debug)]
pub(crate) struct Info {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) method: String,
    pub(crate) version: String,
    pub(crate) content_type: String,
    pub(crate) chunk_index: usize,
    pub(crate) total_chunks: usize,
}

impl Info {
    pub(crate) fn parse(request: &mut Request<Incoming>, cipher: &Cipher) -> Result<Self> {
        let headers = request.headers_mut();

        let id = headers
            .remove(TRANSACTION_ID_HEADER)
            .ok_or_else(|| anyhow!("Can not get {TRANSACTION_ID_HEADER} header"))?;
        let id = id
            .to_str()
            .with_context(|| format!("Invalid {TRANSACTION_ID_HEADER} header, not ascii"))?
            .to_string();

        let url = headers
            .remove(ORIGINAL_URL_HEADER)
            .ok_or_else(|| anyhow!("Can not get {ORIGINAL_URL_HEADER} header"))?;
        let url = url
            .to_str()
            .with_context(|| format!("Invalid {ORIGINAL_URL_HEADER} header, not ascii"))?;

        let chunk_index = headers
            .remove(CHUNK_INDEX_HEADER)
            .ok_or_else(|| anyhow!("Can not get {CHUNK_INDEX_HEADER} header"))?;
        let chunk_index = chunk_index
            .to_str()
            .with_context(|| format!("Invalid {CHUNK_INDEX_HEADER} header, not ascii"))?;
        let chunk_index = chunk_index
            .parse()
            .with_context(|| format!("Invalid {CHUNK_INDEX_HEADER} header, not a number"))?;

        let total_chunks = headers
            .remove(TOTAL_CHUNKS_HEADER)
            .ok_or_else(|| anyhow!("Can not get total_chunks header"))?;
        let total_chunks = total_chunks
            .to_str()
            .with_context(|| format!("Invalid {TOTAL_CHUNKS_HEADER} header, not ascii"))?;
        let total_chunks = total_chunks
            .parse::<usize>()
            .with_context(|| format!("Invalid {TOTAL_CHUNKS_HEADER} header, not a number"))?;

        let url = Base64::decode_vec(url)?;
        let url = cipher.decrypt(&url)?;
        let url = String::from_utf8_lossy(&url);
        let mut spans = url.split('+');
        let method = spans
            .next()
            .ok_or_else(|| anyhow!("Invalid {ORIGINAL_URL_HEADER} header , no method"))?
            .to_string();
        let version = spans
            .next()
            .ok_or_else(|| anyhow!("Invalid {ORIGINAL_URL_HEADER} header , no version"))?
            .to_string();
        let content_type = spans
            .next()
            .ok_or_else(|| anyhow!("Invalid {ORIGINAL_URL_HEADER} header , no content_type"))?
            .to_string();
        let url = spans
            .next()
            .ok_or_else(|| anyhow!("Invalid {ORIGINAL_URL_HEADER} header , no url"))?
            .to_string();

        Ok(Self {
            id,
            url,
            content_type,
            method,
            version,
            chunk_index,
            total_chunks,
        })
    }
}
