use anyhow::{Result, anyhow};
use rcgen::Issuer;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::PathBuf;
use tokio::fs::create_dir_all;
use tokio::fs::read;
use tokio::fs::{remove_dir_all, write};
use tracing::warn;

pub struct CertManager<'a> {
    /// root ca certificate
    ca_cert_path: PathBuf,
    /// root ca private key
    key_cert_path: PathBuf,
    /// cache dir for the server certificate
    cache_dir: PathBuf,
    /// root ca certificate
    ca_issuer: Option<Issuer<'a, KeyPair>>,
}

impl CertManager<'_> {
    pub async fn new(cert: PathBuf, key: PathBuf, cache_dir: PathBuf) -> Result<Self> {
        if cache_dir.exists() {
            create_dir_all(&cache_dir).await?;
        }

        let ca_issuer = if cert.exists() && key.exists() {
            let cert_pem = String::from_utf8_lossy(&read(&cert).await?).to_string();
            let key_pem = String::from_utf8_lossy(&read(&key).await?).to_string();

            let ca_key = KeyPair::from_pem(&key_pem)?;
            let ca_issuer = Issuer::from_ca_cert_pem(&cert_pem, ca_key)?;

            Some(ca_issuer)
        } else {
            None
        };

        Ok(Self {
            ca_cert_path: cert,
            key_cert_path: key,
            cache_dir,
            ca_issuer,
        })
    }

    /// generate the ca certificate and key into the given path
    pub async fn generate_ca_file(&mut self, common_name: impl Into<String>) -> Result<()> {
        let (ca_cert, ca_key) = self.generate_ca_pem(common_name).await?;

        write(&self.ca_cert_path, &ca_cert).await?;
        write(&self.key_cert_path, &ca_key).await?;
        Ok(())
    }

    pub async fn generate_srv_pem(
        &self,
        common_name: impl Into<String>,
    ) -> Result<(String, String)> {
        let ca_issuer = self
            .ca_issuer
            .as_ref()
            .ok_or_else(|| anyhow!("ca issuer not found"))?;

        // Create certificate configuration with the provided common name
        let common_name = common_name.into();
        let cert_config = CertConfig {
            common_name,
            ..Default::default()
        };

        // Create server certificate parameters
        let mut server_params = CertificateParams::new(vec![cert_config.common_name.clone()])?;
        server_params.is_ca = IsCa::NoCa;
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.distinguished_name = cert_config.into();
        server_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        server_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

        // Generate a new key pair for the server certificate
        let server_key_pair = KeyPair::generate()?;

        // Create the server certificate signed by the CA
        let server_cert = server_params.signed_by(&server_key_pair, ca_issuer)?;

        // Serialize the certificate and key to PEM format
        let cert_pem = server_cert.pem();
        let key_pem = server_key_pair.serialize_pem();

        Ok((cert_pem, key_pem))
    }

    pub async fn generate_ca_pem(
        &mut self,
        common_name: impl Into<String>,
    ) -> Result<(String, String)> {
        self.clear_cache().await;

        let common_name = common_name.into();

        let mut ca_params = CertificateParams::new(vec![common_name.clone()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert_config = CertConfig {
            common_name,
            ..Default::default()
        };
        ca_params.distinguished_name = cert_config.clone().into();
        ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        ca_params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::days((cert_config.validity_days * 10) as i64);

        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let cert_pem = ca_cert.pem();
        let key_pem = ca_key.serialize_pem();

        self.ca_issuer = Some(Issuer::new(ca_params, ca_key));

        Ok((cert_pem, key_pem))
    }

    pub async fn clear_cache(&self) {
        if self.cache_dir.exists() {
            if let Err(e) = remove_dir_all(&self.cache_dir).await {
                warn!("failed to clear cache dir: {}", e)
            }
        }
    }
}

impl From<CertConfig> for DistinguishedName {
    fn from(value: CertConfig) -> Self {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, value.common_name);
        dn.push(DnType::OrganizationName, value.organization);
        dn.push(DnType::CountryName, value.country);
        dn.push(DnType::StateOrProvinceName, value.state);
        dn.push(DnType::LocalityName, value.city);
        dn.push(DnType::OrganizationalUnitName, value.org_unit);
        dn
    }
}

#[derive(Clone)]
struct CertConfig {
    /// common name for the certificate (typically for the domain)
    pub common_name: String,
    /// subject alternative names (additional domains/IPs)
    pub san_domains: Vec<String>,
    /// organization name
    pub organization: String,
    /// country name
    pub country: String,
    /// state/province name
    pub state: String,
    /// city name
    pub city: String,
    /// organization unit name
    pub org_unit: String,
    /// validity period in days
    pub validity_days: u32,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            common_name: "localhost".to_string(),
            san_domains: vec![],
            organization: env!("CARGO_PKG_NAME").to_string(),
            country: "CN".to_string(),
            state: "ZJ".to_string(),
            city: "HZ".to_string(),
            org_unit: "Dev".to_string(),
            validity_days: 365,
        }
    }
}
