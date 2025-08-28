use crate::{local::proxy::Proxy, options::LocalModeOptions};
use anyhow::Result;

pub async fn start(opts: LocalModeOptions) -> Result<()> {
    let proxy = Proxy::new(opts).await?;
    proxy.serve().await
}

mod buf;
mod cert;
mod forward;
pub mod headers;
mod proxy;
