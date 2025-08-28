use crate::{
    crypto::{Encryptor, default_token},
    local::headers::{
        CHUNK_INDEX_HEADER, ORIGINAL_URL_HEADER, TOTAL_CHUNKS_HEADER, TRANSACTION_ID_HEADER,
    },
    options::LocalModeOptions,
};
use anyhow::{Context, Result, anyhow, bail};
use base64ct::{Base64, Encoding};
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Request, Response,
    body::{Bytes, Incoming},
    header::{CONTENT_LENGTH, TRANSFER_ENCODING},
    http::request::Parts,
};
use reqwest::Proxy;
use uuid::Uuid;

pub struct Forwarder {
    chunks: Vec<Bytes>,
    remote_addr: String,
    client: reqwest::Client,
    parts: Parts,
    token: String,
}

impl Forwarder {
    pub async fn new(req: Request<Incoming>, opts: &LocalModeOptions) -> Result<Self> {
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
        let client = if let Some(proxy) = &opts.proxy {
            client
                .proxy(Proxy::all(proxy).context("invalid proxy option")?)
                .build()?
        } else {
            client.build()?
        };

        Ok(Self {
            chunks,
            remote_addr,
            client,
            parts,
            token: opts.token.clone().unwrap_or_else(|| default_token()),
        })
    }

    pub async fn apply(self) -> Result<Response<Full<Bytes>>> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", USER_AGENT.parse()?);
        let uuid = Uuid::new_v4().to_string();
        headers.insert(TRANSACTION_ID_HEADER, uuid.parse()?);

        let info = format!(
            "{}+{:?}+{}",
            self.parts.method, self.parts.version, self.parts.uri
        );
        let encryptor = Encryptor::new(self.token);
        headers.insert(
            ORIGINAL_URL_HEADER,
            Base64::encode_string(&encryptor.encrypt(info)?).parse()?,
        );

        for (key, value) in self.parts.headers.iter() {
            headers.insert(key.clone(), value.clone());
        }

        let total = self.chunks.len();
        headers.insert(TOTAL_CHUNKS_HEADER, total.to_string().parse()?);

        let mut last_response = None;
        for (index, chunk) in self.chunks.into_iter().enumerate() {
            headers.insert(CHUNK_INDEX_HEADER, index.to_string().parse()?);
            let chunk = encryptor.encrypt(chunk)?;

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

        Ok(last_response
            .ok_or_else(|| anyhow!("no response for {uuid}, {}", self.parts.uri))?
            .convert()
            .await?)
    }
}

// TODO: make this configurable
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";

pub trait HyperConverter {
    async fn convert(self) -> Result<Response<Full<Bytes>>>;
}

impl HyperConverter for reqwest::Response {
    async fn convert(self) -> Result<Response<Full<Bytes>>> {
        let mut res = Response::builder()
            .status(self.status())
            .version(self.version());
        if let Some(headers) = res.headers_mut() {
            *headers = self.headers().clone();
        }

        let res = res
            .body(Full::new(self.bytes().await?))
            .map_err(|e| anyhow!("failed to convert response: {e:?}"))?;

        Ok(res)
    }
}
