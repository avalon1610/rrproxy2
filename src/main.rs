use crate::options::{Commands, Options};
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
        Commands::Local(o) => local::start(o).await,
        Commands::Remote(o) => remote::start(o).await,
    }
}

mod local;
mod options;
mod remote;
