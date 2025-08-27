use crate::options::LocalModeOptions;
use anyhow::Result;

pub async fn start(opts: LocalModeOptions) -> Result<()> {
    let mut cm = cert::CertManager::new(opts.cert, opts.key, opts.cache_dir).await?;

    if opts.generate_ca {
        cm.generate_ca_file(opts.ca_common_name).await?;
    }

    Ok(())
}

mod cert;
