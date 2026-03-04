use crate::{
    local::LocalProxy,
    options::{Commands, ConfigFile, Options},
    proxy::Proxy,
    remote::RemoteProxy,
};
use anyhow::{Context, Result};
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

    // Merge config into CLI opts: CLI (Some) always wins; None means "not set on CLI",
    // so we fill from the config file as a fallback.
    match &mut opts.command {
        Commands::Local(local) => {
            if let Some(cfg) = config.local {
                merge_opt(&mut local.common.listen, cfg.common.listen);
                merge_opt(&mut local.common.proxy, cfg.common.proxy);
                merge_opt(&mut local.common.token, cfg.common.token);
                merge_opt(&mut local.common.websocket, cfg.common.websocket);
                merge_opt(&mut local.common.no_base64, cfg.common.no_base64);
                merge_opt(&mut local.remote, cfg.remote);
                merge_opt(&mut local.chunk, cfg.chunk);
                merge_opt(&mut local.full, cfg.full);
                merge_opt(&mut local.bypass, cfg.bypass);
                merge_opt(&mut local.cert, cfg.cert);
                merge_opt(&mut local.key, cfg.key);
                merge_opt(&mut local.generate_ca, cfg.generate_ca);
                merge_opt(&mut local.ca_common_name, cfg.ca_common_name);
                merge_opt(&mut local.cache_dir, cfg.cache_dir);
            }
        }
        Commands::Remote(remote) => {
            if let Some(cfg) = config.remote {
                merge_opt(&mut remote.common.listen, cfg.common.listen);
                merge_opt(&mut remote.common.proxy, cfg.common.proxy);
                merge_opt(&mut remote.common.token, cfg.common.token);
                merge_opt(&mut remote.common.websocket, cfg.common.websocket);
                merge_opt(&mut remote.common.no_base64, cfg.common.no_base64);
                merge_opt(&mut remote.generate_token, cfg.generate_token);
                merge_opt(&mut remote.tls_cert, cfg.tls_cert);
                merge_opt(&mut remote.tls_key, cfg.tls_key);
                merge_opt(&mut remote.tls, cfg.tls);
            }
        }
    }

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
            if o.generate_token.unwrap_or(false) {
                println!("{}", uuid::Uuid::new_v4());
            } else {
                start::<RemoteProxy>(o).await?;
            }
        }
    }

    Ok(())
}

/// Fill `dst` from `src` only when `dst` is `None` (i.e. not set on the CLI).
fn merge_opt<T>(dst: &mut Option<T>, src: Option<T>) {
    if dst.is_none() {
        *dst = src;
    }
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
