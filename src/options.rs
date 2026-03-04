use clap::ArgAction;
use clap::Parser;
use clap::Subcommand;
use merge_derive::Merge;
use serde::Deserialize;
use std::path::PathBuf;

// ── Merge support ─────────────────────────────────────────────────────────────
/// Merge two option sets: `self` (CLI) wins over `other` (config file).
pub(crate) trait Merge {
    fn merge(&mut self, other: Self);
}

impl<T> Merge for Option<T> {
    fn merge(&mut self, other: Self) {
        if self.is_none() {
            *self = other;
        }
    }
}

// ── Default values ────────────────────────────────────────────────────────────
pub(crate) const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
pub(crate) const DEFAULT_REMOTE: &str = "http://127.0.0.1:8081";
pub(crate) const DEFAULT_CHUNK: usize = 10240;
pub(crate) const DEFAULT_CERT: &str = "cert.ca.pem";
pub(crate) const DEFAULT_KEY: &str = "key.ca.pem";
pub(crate) const DEFAULT_CA_COMMON_NAME: &str = "RRProxy Root CA";
pub(crate) const DEFAULT_CACHE_DIR: &str = "cert_cache";

// ── Top-level CLI ─────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub(crate) struct Options {
    /// more verbose output, use -vv for even more verbose output
    #[arg(long, short, global = true, action = ArgAction::Count)]
    pub(crate) verbose: u8,

    /// Path to a TOML config file. Command-line options take priority over config file values.
    /// When a config file is provided, the subcommand (local/remote) may be omitted;
    /// the mode is inferred from whichever of [local] / [remote] is present in the file.
    #[arg(long, short)]
    pub(crate) config: Option<PathBuf>,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

// ── Config file (reuses the same option structs) ──────────────────────────────
/// TOML config file structure.  All fields use the same structs as the CLI.
/// Common fields (listen, proxy, token, websocket, no_base64) go directly under
/// [local] / [remote] because `common` is flattened into each section.
///
/// Example:
/// ```toml
/// [local]
/// listen = "0.0.0.0:8080"
/// websocket = true
/// remote = "http://remote:8081"
/// chunk = 20480
///
/// [remote]
/// listen = "0.0.0.0:8081"
/// token = "my-secret"
/// tls = true
/// ```
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ConfigFile {
    pub(crate) local: Option<LocalModeOptions>,
    pub(crate) remote: Option<RemoteModeOptions>,
}

// ── Subcommands ───────────────────────────────────────────────────────────────
#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run in local mode
    Local(LocalModeOptions),
    /// Run in remote mode
    Remote(RemoteModeOptions),
}

// ── Shared options ────────────────────────────────────────────────────────────
#[derive(Debug, Default, Parser, Deserialize, Merge)]
pub(crate) struct CommonOptions {
    /// The address to listen on (default: 127.0.0.1:8080)
    #[arg(long, short)]
    pub(crate) listen: Option<String>,

    /// The optional proxy address to use between local and remote. The proxy address should start with http://
    #[arg(short, long)]
    pub(crate) proxy: Option<String>,

    /// The token for encryption, if not set, will use default one
    #[arg(long, short)]
    pub(crate) token: Option<String>,

    /// Use WebSocket transport instead of HTTP chunked POST
    #[arg(long, short = 'w', action = ArgAction::SetTrue)]
    pub(crate) websocket: Option<bool>,

    /// Disable base64 encoding/decoding for encrypted data (default: enabled)
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) no_base64: Option<bool>,
}

// ── Local mode ────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Parser, Deserialize, Merge)]
pub(crate) struct LocalModeOptions {
    #[command(flatten)]
    #[serde(flatten)]
    pub(crate) common: CommonOptions,

    /// The address to forward requests to, should start with http:// (default: http://127.0.0.1:8081)
    #[arg(long, short)]
    pub(crate) remote: Option<String>,

    /// The size of the chunk to split for the large request (default: 10240)
    #[arg(long, short)]
    pub(crate) chunk: Option<usize>,

    /// Make all data go through the remote server.
    /// By default, only large requests (larger than chunk size) will go through the remote server
    #[arg(long, short, action = ArgAction::SetTrue)]
    pub(crate) full: Option<bool>,

    /// Bypass the specific target (supports CIDR and domain name), split with comma
    #[arg(long, short)]
    pub(crate) bypass: Option<String>,

    /// The Root CA certificate file path (default: cert.ca.pem)
    #[arg(long)]
    pub(crate) cert: Option<PathBuf>,

    /// The Root CA private key file path (default: key.ca.pem)
    #[arg(long)]
    pub(crate) key: Option<PathBuf>,

    /// Generate a new Root CA certificate and private key. cert and key path will be used.
    #[arg(short, long, action = ArgAction::SetTrue)]
    pub(crate) generate_ca: Option<bool>,

    /// The common name for the Root CA certificate generation (default: RRProxy Root CA)
    #[arg(long)]
    pub(crate) ca_common_name: Option<String>,

    /// The directory to cache the server certificate (default: cert_cache)
    #[arg(long)]
    pub(crate) cache_dir: Option<PathBuf>,

    /// Force remote forwarding for requests whose URL contains any of these keywords.
    /// Can be specified multiple times or as comma-separated values. Acts like --full for matching requests.
    #[arg(long, num_args = 1.., value_delimiter = ',')]
    pub(crate) remote_keywords: Option<Vec<String>>,
}

// ── Remote mode ───────────────────────────────────────────────────────────────
#[derive(Debug, Default, Parser, Deserialize, Merge)]
pub(crate) struct RemoteModeOptions {
    #[command(flatten)]
    #[serde(flatten)]
    pub(crate) common: CommonOptions,

    /// Generate a UUID token for encryption.
    #[arg(long, short, action = ArgAction::SetTrue)]
    pub(crate) generate_token: Option<bool>,

    /// Enable TLS. Provide a PEM cert file, or omit to auto-generate a self-signed cert.
    #[arg(long)]
    pub(crate) tls_cert: Option<PathBuf>,

    /// TLS private key file (PEM). Required if --tls-cert is set.
    #[arg(long)]
    pub(crate) tls_key: Option<PathBuf>,

    /// Enable TLS with a self-signed cert (no cert/key files needed).
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) tls: Option<bool>,
}
