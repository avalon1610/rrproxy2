use anyhow::Result;
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Parse a PEM certificate chain and a PKCS#8 PEM private key into the typed rustls values.
/// Shared between the local TLS interceptor (in-memory PEM) and the remote proxy (file-based PEM).
pub(crate) fn tls_parts_from_pem(
    mut cert_pem: &[u8],
    mut key_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("Failed to parse certificate"))?;

    let keys: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut key_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("Failed to parse private key"))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    Ok((cert_chain, PrivateKeyDer::Pkcs8(key)))
}

/// Build a [`TlsAcceptor`] from an already-parsed certificate chain and private key.
/// Shared between the local TLS interceptor and the remote proxy.
pub(crate) fn tls_acceptor_from_parts(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor> {
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
