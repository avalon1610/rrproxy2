use crate::{
    crypto::{Decryptor, default_token},
    options::RemoteModeOptions,
    proxy::{HyperConverter, Proxy},
    remote::{
        info::Info,
        transaction::{Transaction, TransactionState},
    },
};
use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
use reqwest::{Client, ClientBuilder};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct RemoteProxy {
    opts: Arc<RemoteModeOptions>,
    transactions: Arc<Mutex<HashMap<String, Transaction>>>,
    decryptor: Arc<Decryptor>,
    client: Client,
}

impl Proxy for RemoteProxy {
    type Options = RemoteModeOptions;

    async fn new(opts: RemoteModeOptions) -> Result<Self> {
        let client = ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
        let client = if let Some(proxy) = &opts.common.proxy {
            client.proxy(reqwest::Proxy::all(proxy)?).build()?
        } else {
            client.build()?
        };

        Ok(Self {
            transactions: Arc::new(Mutex::new(HashMap::new())),
            decryptor: Arc::new(Decryptor::new(
                opts.common.token.clone().unwrap_or_else(default_token),
            )),
            opts: Arc::new(opts),
            client,
        })
    }

    fn listen_addr(&self) -> Result<SocketAddr> {
        Ok(self.opts.common.listen.parse()?)
    }

    async fn handler(
        self,
        request: Request<Incoming>,
        addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        // assume we only receiving request only from local part
        info!("local request from {}", addr);

        match self.handle_request(request).await {
            Ok(response) => Ok(response),
            Err(err) => {
                warn!("handle error: {err:?}");

                // CAUTION: Do not return details error info to client, make sure client can not detect our purpose.
                Ok(Response::builder()
                    .status(400)
                    .body("Invalid Request".into())
                    .unwrap()) // this unwrap never fails, because only set the status code
            }
        }
    }
}

impl RemoteProxy {
    async fn handle_request(
        &self,
        mut request: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>> {
        let now = Instant::now();
        let info = Info::parse(&mut request, &self.decryptor)?;
        debug!("parsed info {:?}", info);
        let (parts, body) = request.into_parts();
        let body = body.collect().await?.to_bytes();
        let body = self.decryptor.decrypt(&body)?;
        let body = Bytes::from_owner(body);
        let id = info.id.clone();

        let request = {
            let mut transactions = self.transactions.lock().unwrap();
            let transaction = if let Some(mut t) = transactions.remove(&id) {
                // old transaction, we update the body and chunk index
                debug!("transaction {id} updated {} bytes", body.len());
                t.update(info.chunk_index, body);
                t
            } else {
                // new transaction, we use request's headers (which already removed our internal headers)
                // and body (will be store in cache)
                debug!("new transaction {id} created, {} bytes", body.len());
                Transaction::new(parts, body, info)
            };

            match transaction.commit()? {
                TransactionState::Pending(t) => {
                    transactions.insert(id.clone(), t);
                    None
                }
                TransactionState::Committed(r) => Some(r),
            }
        };

        if let Some((request, start)) = request {
            let response = self
                .client
                .execute(request)
                .await
                .context("target request error")?;
            info!("handle whole transaction {} cost {:?}", id, start.elapsed());
            Ok(response.convert().await?)
        } else {
            info!("handle single chunk cost {:?}", now.elapsed());
            Ok(Response::default())
        }
    }
}

mod info;
mod transaction;
