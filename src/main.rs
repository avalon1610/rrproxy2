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

    let log_dir = match opts.command {
        Commands::Local(_) => "local_proxy_logs",
        Commands::Remote(_) => "remote_proxy_logs",
    };

    let _log = TracingLogger::new(log_dir, env!("CARGO_PKG_NAME"), level, "info")?.init()?;
    match opts.command {
        Commands::Local(o) => {
            start::<LocalProxy>(o).await?;
        }
        Commands::Remote(o) => {
            if o.generate_token {
                println!("{}", uuid::Uuid::new_v4());
            } else {
                start::<RemoteProxy>(o).await?;
            }
        }
    }

    Ok(())
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
mod convert;
