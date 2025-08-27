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
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_generate_ca_pem_matches_openssl() {
        // Generate CA cert/key using our function
        let mut cert_manager = CertManager {
            ca_cert_path: PathBuf::from("/tmp/test_ca.crt"),
            key_cert_path: PathBuf::from("/tmp/test_ca.key"),
            cache_dir: PathBuf::from("/tmp/cache"),
            ca_issuer: None,
        };

        let common_name = "Test CA";
        let (cert_pem, key_pem) = cert_manager.generate_ca_pem(common_name).await.unwrap();

        // Create temporary directory for OpenSSL generated files
        let temp_dir = tempdir().unwrap();
        let openssl_cert_path = temp_dir.path().join("openssl_ca.crt");
        let openssl_key_path = temp_dir.path().join("openssl_ca.key");

        // Generate CA cert/key using OpenSSL with same configuration
        let openssl_result = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                openssl_key_path.to_str().unwrap(),
                "-out",
                openssl_cert_path.to_str().unwrap(),
                "-days",
                "3650",
                "-nodes", // No password
                "-subj",
                &format!(
                    "/CN={}/O={}/C=CN/ST=ZJ/L=HZ/OU=Dev",
                    common_name,
                    env!("CARGO_PKG_NAME")
                ),
            ])
            .output()
            .expect("Failed to execute openssl command");

        if !openssl_result.status.success() {
            panic!(
                "OpenSSL command failed: {}",
                String::from_utf8_lossy(&openssl_result.stderr)
            );
        }

        // Read OpenSSL generated files
        let openssl_cert = std::fs::read_to_string(&openssl_cert_path).unwrap();
        let openssl_key = std::fs::read_to_string(&openssl_key_path).unwrap();

        // Print certificate information for debugging
        println!("=== Generated Certificate Details ===");
        println!(
            "Generated Subject: {}",
            extract_field_from_pem(&cert_pem, "subject")
        );
        println!(
            "Generated Issuer: {}",
            extract_field_from_pem(&cert_pem, "issuer")
        );
        println!(
            "Generated Validity: {}",
            extract_field_from_pem(&cert_pem, "dates")
        );
        println!(
            "Generated Basic Constraints: {}",
            extract_field_from_pem(&cert_pem, "basic_constraints")
        );

        println!("\n=== OpenSSL Certificate Details ===");
        println!(
            "OpenSSL Subject: {}",
            extract_field_from_pem(&openssl_cert, "subject")
        );
        println!(
            "OpenSSL Issuer: {}",
            extract_field_from_pem(&openssl_cert, "issuer")
        );
        println!(
            "OpenSSL Validity: {}",
            extract_field_from_pem(&openssl_cert, "dates")
        );

        // Extract and compare certificate information
        // Compare subject information
        let cert_subject = extract_field_from_pem(&cert_pem, "subject");
        let openssl_cert_subject = extract_field_from_pem(&openssl_cert, "subject");
        assert_eq!(
            cert_subject, openssl_cert_subject,
            "Subject fields should match"
        );

        // Compare issuer information (for self-signed certs, should match subject)
        let cert_issuer = extract_field_from_pem(&cert_pem, "issuer");
        let openssl_cert_issuer = extract_field_from_pem(&openssl_cert, "issuer");
        assert_eq!(
            cert_issuer, openssl_cert_issuer,
            "Issuer fields should match"
        );

        // Compare validity dates
        let cert_dates = extract_field_from_pem(&cert_pem, "dates");
        let openssl_dates = extract_field_from_pem(&openssl_cert, "dates");
        println!("Generated Dates: {}", cert_dates);
        println!("OpenSSL Dates: {}", openssl_dates);

        // Compare basic constraints (should indicate CA for both)
        let cert_basic_constraints = extract_field_from_pem(&cert_pem, "basic_constraints");
        let openssl_basic_constraints = extract_field_from_pem(&openssl_cert, "basic_constraints");
        println!("Generated Basic Constraints: {}", cert_basic_constraints);
        println!("OpenSSL Basic Constraints: {}", openssl_basic_constraints);

        // Check that both certificates are CAs
        assert!(
            cert_basic_constraints.contains("CA:TRUE")
                || cert_basic_constraints.contains("CA:true"),
            "Generated cert should be a CA"
        );
        assert!(
            openssl_basic_constraints.contains("CA:TRUE")
                || openssl_basic_constraints.contains("CA:true"),
            "OpenSSL cert should be a CA"
        );

        // Both should have private key in PKCS#8 format
        assert!(
            key_pem.contains("PRIVATE KEY"),
            "Generated key should be in PRIVATE KEY format"
        );
        assert!(
            openssl_key.contains("PRIVATE KEY"),
            "OpenSSL key should be in PRIVATE KEY format"
        );

        println!("\n=== Test Passed ===");
        println!("Both certificates have matching subjects and are valid CAs");
    }

    fn extract_field_from_pem(pem: &str, field: &str) -> String {
        let temp_dir = tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        std::fs::write(&cert_path, pem).unwrap();

        match field {
            "subject" => {
                let output = Command::new("openssl")
                    .args([
                        "x509",
                        "-in",
                        cert_path.to_str().unwrap(),
                        "-noout",
                        "-subject",
                    ])
                    .output()
                    .expect("Failed to execute openssl x509 command");

                if !output.status.success() {
                    panic!(
                        "OpenSSL x509 command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            "issuer" => {
                let output = Command::new("openssl")
                    .args([
                        "x509",
                        "-in",
                        cert_path.to_str().unwrap(),
                        "-noout",
                        "-issuer",
                    ])
                    .output()
                    .expect("Failed to execute openssl x509 command");

                if !output.status.success() {
                    panic!(
                        "OpenSSL x509 command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            "dates" => {
                let output = Command::new("openssl")
                    .args([
                        "x509",
                        "-in",
                        cert_path.to_str().unwrap(),
                        "-noout",
                        "-dates",
                    ])
                    .output()
                    .expect("Failed to execute openssl x509 command");

                if !output.status.success() {
                    panic!(
                        "OpenSSL x509 command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            "basic_constraints" => {
                let output = Command::new("openssl")
                    .args([
                        "x509",
                        "-in",
                        cert_path.to_str().unwrap(),
                        "-noout",
                        "-text",
                    ])
                    .output()
                    .expect("Failed to execute openssl x509 command");

                if !output.status.success() {
                    panic!(
                        "OpenSSL x509 command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                // Extract Basic Constraints from the full text output
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("Basic Constraints") {
                        // Also get the next line which contains the value
                        let lines: Vec<&str> = output_str.lines().collect();
                        let line_idx = lines
                            .iter()
                            .position(|&l| l.contains("Basic Constraints"))
                            .unwrap();
                        if line_idx + 1 < lines.len() {
                            return format!("{}{}", line.trim(), lines[line_idx + 1].trim());
                        }
                        return line.trim().to_string();
                    }
                }
                "Basic Constraints not found".to_string()
            }
            "full_text" => {
                let output = Command::new("openssl")
                    .args([
                        "x509",
                        "-in",
                        cert_path.to_str().unwrap(),
                        "-noout",
                        "-text",
                    ])
                    .output()
                    .expect("Failed to execute openssl x509 command");

                if !output.status.success() {
                    panic!(
                        "OpenSSL x509 command failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            _ => "Unknown field".to_string(),
        }
    }
}
