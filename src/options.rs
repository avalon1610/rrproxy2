use std::path::PathBuf;
use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub(crate) struct Options {
    /// more verbose output, use -vv for even more verbose output
    #[arg(long, short, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run in local mode
    Local(LocalModeOptions),
    /// Run in remote mode
    Remote(RemoteModeOptions),
}

#[derive(Debug, Parser)]
pub(crate) struct CommonOptions {
    /// The address to listen on
    #[arg(long, short, default_value = "127.0.0.1:8080")]
    pub(crate) listen: String,

    /// The optional proxy address to use between local and remote. The proxy address should starts with http://
    #[arg(short, long, short)]
    pub(crate) proxy: Option<String>,

    /// The token for encryption, if not set, will use default one
    #[arg(long, short)]
    pub(crate) token: Option<String>,
}

#[derive(Debug, Parser)]
pub(crate) struct LocalModeOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,

    /// The address to forward requests to, should starts with http://
    #[arg(long, short, default_value = "http://127.0.0.1:8081")]
    pub(crate) remote: String,

    /// The size of the chunk to split for the large request
    #[arg(long, short, default_value_t = 10240)]
    pub(crate) chunk: usize,

    /// make all data go through the remote server. 
    /// by default, only large request (larger than chunk size) will go through the remote server
    #[arg(long, short)]
    pub(crate) full: bool,

    /// The Root CA certificate file path
    #[arg(long, default_value = "cert.ca.pem")]
    pub(crate) cert: PathBuf,

    /// The Root CA private key file path
    #[arg(long, default_value = "key.ca.pem")]
    pub(crate) key: PathBuf,

    /// Generate a new Root CA certificate and private key. cert and key path will be used.
    #[arg(short, long)]
    pub(crate) generate_ca: bool,

    /// The common name for the Root CA certificate generation
    #[arg(long, default_value = "RRProxy Root CA")]
    pub(crate) ca_common_name: String,

    /// The directory to cache the server certificate
    #[arg(long, default_value = "cert_cache")]
    pub(crate) cache_dir: PathBuf,
}

#[derive(Debug, Parser)]
pub(crate) struct RemoteModeOptions {
    #[command(flatten)]
    pub(crate) common: CommonOptions,

    /// generate an uuid token for encryption.
    #[arg(long, short)]
    pub(crate) generate_token: bool,
}
