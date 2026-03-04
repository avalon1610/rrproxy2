use crate::{
    local::LocalProxy,
    options::{Commands, ConfigFile, Merge, Options},
    proxy::Proxy,
    remote::RemoteProxy,
};
use anyhow::{Context, Result, bail};
use clap::Parser;
use misc::TracingLogger;

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = Options::parse();

    // Load config file if provided
    let config = if let Some(config_path) = &opts.config {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("failed to read config file: {}", config_path.display()))?;
        toml::from_str::<ConfigFile>(&content)
            .with_context(|| format!("failed to parse config file: {}", config_path.display()))?
    } else {
        ConfigFile::default()
    };

    // If no subcommand was given, infer the mode from the config file.
    if opts.command.is_none() {
        match (config.local.is_some(), config.remote.is_some()) {
            (true, false) => opts.command = Some(Commands::Local(Default::default())),
            (false, true) => opts.command = Some(Commands::Remote(Default::default())),
            (false, false) => bail!(
                "no subcommand given and no [local] or [remote] section found in the config file"
            ),
            (true, true) => bail!(
                "config file contains both [local] and [remote] sections; please specify the subcommand explicitly"
            ),
        }
    }

    // Merge config into CLI opts: CLI (Some) always wins; None means "not set on CLI",
    // so we fill from the config file as a fallback.
    match opts.command.as_mut().expect("command is set above") {
        Commands::Local(local) => {
            if let Some(cfg) = config.local {
                local.merge(cfg);
            }
        }
        Commands::Remote(remote) => {
            if let Some(cfg) = config.remote {
                remote.merge(cfg);
            }
        }
    }

    let command = opts.command.expect("command is set above");

    let level = match opts.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let log_dir = match &command {
        Commands::Local(_) => "local_proxy_logs",
        Commands::Remote(_) => "remote_proxy_logs",
    };

    let _log = TracingLogger::new(log_dir, env!("CARGO_PKG_NAME"), level, "info")?.init()?;
    match command {
        Commands::Local(o) => {
            start::<LocalProxy>(o).await?;
        }
        Commands::Remote(o) => {
            if o.generate_token.unwrap_or(false) {
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

mod convert;
mod crypto;
mod header;
mod local;
mod options;
mod proxy;
mod remote;
mod tls;
