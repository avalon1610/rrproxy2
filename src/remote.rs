use crate::{options::RemoteModeOptions, remote::proxy::Proxy};
use anyhow::Result;

mod proxy;

pub async fn start(opts: RemoteModeOptions) -> Result<()> {
    let proxy = Proxy::new(opts);
    proxy.serve().await?;

    Ok(())
}
