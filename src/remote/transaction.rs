use crate::remote::info::Info;
use anyhow::Result;
use hyper::body::Bytes;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::http::request::Parts;
use hyper::{HeaderMap, Version};
use reqwest::Request;
use std::collections::BTreeMap;
use std::time::Instant;

pub struct Transaction {
    headers: HeaderMap,
    info: Info,
    cache: BTreeMap<usize, Bytes>,
    pub start: Instant,
}

impl Transaction {
    pub fn new(parts: Parts, body: Bytes, info: Info) -> Self {
        let headers = parts.headers;
        let mut cache = BTreeMap::new();
        cache.insert(info.chunk_index, body);

        Transaction {
            headers,
            info,
            cache,
            start: Instant::now(),
        }
    }

    pub fn update(&mut self, chunk_index: usize, body: Bytes) {
        self.cache.insert(chunk_index, body);
    }

    pub fn commit(self) -> Result<TransactionState> {
        if self.cache.len() < self.info.total_chunks {
            return Ok(TransactionState::Pending(self));
        }

        let method = (&*self.info.method).try_into()?;
        let url = self.info.url.parse()?;
        let version = self.info.version.parse_version()?;

        let mut request = Request::new(method, url);
        *request.version_mut() = version;
        let headers = request.headers_mut();
        headers.extend(self.headers);

        let body = self.cache.values().fold(Vec::new(), |mut acc, chunk| {
            acc.extend_from_slice(chunk);
            acc
        });

        // adjust content-type and content-length headers
        headers.insert(CONTENT_TYPE, self.info.content_type.parse()?);
        headers.insert(CONTENT_LENGTH, body.len().to_string().parse()?);

        *request.body_mut() = Some(body.into());
        Ok(TransactionState::Committed((request, self.start)))
    }
}

pub enum TransactionState {
    Pending(Transaction),
    Committed((Request, Instant)),
}

trait VersionExt {
    fn parse_version(self) -> Result<Version>;
}

impl VersionExt for &str {
    fn parse_version(self) -> Result<Version> {
        match self {
            "HTTP/0.9" => Ok(Version::HTTP_09),
            "HTTP/1.0" => Ok(Version::HTTP_10),
            "HTTP/1.1" => Ok(Version::HTTP_11),
            "HTTP/2.0" => Ok(Version::HTTP_2),
            "HTTP/3.0" => Ok(Version::HTTP_3),
            _ => Err(anyhow::anyhow!("Invalid version")),
        }
    }
}
