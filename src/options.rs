use std::path::PathBuf;

use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Options {
    /// more verbose output, use -vv for even more verbose output
    #[arg(long, short, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run in local mode
    Local(LocalModeOptions),
    /// Run in remote mode
    Remote(RemoteModeOptions),
}

#[derive(Debug, Parser)]
pub struct LocalModeOptions {
    /// The address to listen on
    #[arg(long, short, default_value = "127.0.0.1:8080")]
    pub listen: String,

    /// The address to forward requests to, should starts with http://
    #[arg(long, short, default_value = "http://127.0.0.1:8081")]
    pub remote: String,

    /// The size of the chunk to split for the large request
    #[arg(long, short, default_value_t = 10240)]
    pub chunk: usize,

    /// The optional proxy address to use between local and remote. The proxy address should starts with http://
    #[arg(short, long, short)]
    pub proxy: Option<String>,

    /// The Root CA certificate file path
    #[arg(long, default_value = "cert.ca.pem")]
    pub cert: PathBuf,

    /// The Root CA private key file path
    #[arg(long, default_value = "key.ca.pem")]
    pub key: PathBuf,

    /// Generate a new Root CA certificate and private key. cert and key path will be used.
    #[arg(short, long)]
    pub generate_ca: bool,

    /// The common name for the Root CA certificate generation
    #[arg(long, default_value = "RRProxy Root CA")]
    pub ca_common_name: String,

    /// The directory to cache the server certificate
    #[arg(long, default_value = "cert_cache")]
    pub cache_dir: PathBuf,

    /// The token for authentication, if not set, will use default one
    #[arg(long, short)]
    pub token: Option<String>,
}

#[derive(Debug, Parser)]
pub struct RemoteModeOptions {
    /// The address to listen on
    #[arg(long, short, default_value = "127.0.0.1:8081")]
    pub listen: String,

    /// generate an uuid token for authentication, it should be used in local mode
    #[arg(long, short)]
    pub generate_token: bool,
}
