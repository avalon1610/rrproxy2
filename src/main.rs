use crate::{
    local::LocalProxy,
    options::{Commands, Options},
    proxy::Proxy,
    remote::RemoteProxy,
};
use anyhow::Result;
use clap::Parser;
use misc::TracingLogger;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Options::parse();
    let level = match opts.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let _log = TracingLogger::new(".", env!("CARGO_PKG_NAME"), level, "info")?.init()?;
    match opts.command {
        Commands::Local(o) => start::<LocalProxy>(o).await,
        Commands::Remote(o) => start::<RemoteProxy>(o).await,
    }
}

async fn start<P: Proxy>(opts: P::Options) -> Result<()> {
    let proxy = P::new(opts).await?;
    proxy.serve().await
}

mod crypto;
mod local;
mod options;
mod proxy;
mod remote;
