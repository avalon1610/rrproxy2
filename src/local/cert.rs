use anyhow::{Result, anyhow};
use rcgen::Issuer;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::fs::read;
use tokio::fs::{create_dir_all, write};
use tracing::{debug, warn};

pub(crate) struct CertManager {
    /// root ca certificate
    ca_cert_path: PathBuf,
    /// root ca private key
    key_cert_path: PathBuf,
    /// cache dir for the server certificate
    cache_dir: PathBuf,
    /// root ca certificate
    ca_issuer: Option<Issuer<'static, KeyPair>>,
    /// memory cache
    cache: Mutex<HashMap<String, (String, String)>>,
}

impl CertManager {
    pub(crate) fn has_issuer(&self) -> bool {
        self.ca_issuer.is_some()
    }

    pub(crate) async fn new(
        cert: impl Into<PathBuf>,
        key: impl Into<PathBuf>,
        cache_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        let cert = cert.into();
        let key = key.into();
        let cache_dir = cache_dir.into();

        if !cache_dir.exists() {
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
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// generate the ca certificate and key into the given path
    pub(crate) async fn generate_ca_file(&mut self, common_name: impl Into<String>) -> Result<()> {
        let (ca_cert, ca_key) = self.generate_ca_pem(common_name).await?;

        write(&self.ca_cert_path, &ca_cert).await?;
        write(&self.key_cert_path, &ca_key).await?;
        Ok(())
    }

    pub(crate) async fn generate_srv_pem(
        &self,
        common_name: impl Into<String>,
    ) -> Result<(String, String)> {
        let common_name = common_name.into();
        debug!("generating certificate for {}", common_name);

        // Check memory cache first
        if let Some(cached) = self.cache.lock().unwrap().get(&common_name) {
            debug!("return {} cert from memory cache", common_name);
            return Ok(cached.clone());
        }

        // Generate hash for disk cache filenames
        let hash = blake3::hash(common_name.as_bytes());
        let hash_hex = hex::encode(hash.as_bytes());

        // Check disk cache
        let cert_path = self.cache_dir.join(format!("{}.cert", hash_hex));
        let key_path = self.cache_dir.join(format!("{}.key", hash_hex));

        if cert_path.exists() && key_path.exists() {
            let cert_pem = String::from_utf8_lossy(&read(&cert_path).await?).to_string();
            let key_pem = String::from_utf8_lossy(&read(&key_path).await?).to_string();
            debug!("return {} cert from disk cache", common_name);

            // Store in memory cache
            self.cache
                .lock()
                .unwrap()
                .insert(common_name, (cert_pem.clone(), key_pem.clone()));

            return Ok((cert_pem, key_pem));
        }

        // Generate new certificate if not found in caches
        let (cert_pem, key_pem) = self.generate_srv_pem_impl(&common_name).await?;

        // Store in memory cache
        self.cache
            .lock()
            .unwrap()
            .insert(common_name.clone(), (cert_pem.clone(), key_pem.clone()));

        write(&cert_path, &cert_pem).await?;
        write(&key_path, &key_pem).await?;

        debug!("generated and cached cert for {}", common_name);
        Ok((cert_pem, key_pem))
    }

    async fn generate_srv_pem_impl(
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

    pub(crate) async fn generate_ca_pem(
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

    pub(crate) async fn clear_cache(&self) {
        if self.cache_dir.exists() {
            let mut dir = match tokio::fs::read_dir(&self.cache_dir).await {
                Ok(dir) => dir,
                Err(e) => {
                    warn!("failed to read cache dir: {}", e);
                    return;
                }
            };

            while let Ok(Some(entry)) = dir.next_entry().await {
                let path = entry.path();
                // Try to remove as a file first
                if tokio::fs::remove_file(&path).await.is_err() {
                    // If that fails, try to remove as a directory
                    if let Err(e) = tokio::fs::remove_dir_all(&path).await {
                        warn!("failed to remove cache entry {:?}: {}", path, e);
                    }
                }
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
    pub(crate) common_name: String,
    /// subject alternative names (additional domains/IPs)
    pub(crate) san_domains: Vec<String>,
    /// organization name
    pub(crate) organization: String,
    /// country name
    pub(crate) country: String,
    /// state/province name
    pub(crate) state: String,
    /// city name
    pub(crate) city: String,
    /// organization unit name
    pub(crate) org_unit: String,
    /// validity period in days
    pub(crate) validity_days: u32,
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
    use std::path::PathBuf;
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
            cache: Mutex::new(HashMap::new()),
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

    #[tokio::test]
    async fn test_generate_srv_pem_matches_openssl() {
        // Load the existing CA certificate and key from the tests folder
        let ca_cert_path = PathBuf::from("./tests/cert.ca.pem");
        let ca_key_path = PathBuf::from("./tests/key.ca.pem");

        // Initialize CertManager with the existing CA
        let cert_manager = CertManager::new(ca_cert_path, ca_key_path, PathBuf::from("/tmp/cache"))
            .await
            .unwrap();

        let common_name = "localhost";

        // Generate server cert/key using our function
        let (cert_pem, key_pem) = cert_manager.generate_srv_pem(common_name).await.unwrap();

        // Create temporary directory for OpenSSL generated files
        let temp_dir = tempdir().unwrap();
        let openssl_cert_path = temp_dir.path().join("openssl_srv.crt");
        let openssl_key_path = temp_dir.path().join("openssl_srv.key");
        let openssl_csr_path = temp_dir.path().join("openssl_srv.csr");

        // Copy the CA files to the temp directory for OpenSSL commands
        let ca_cert_temp = temp_dir.path().join("ca.crt");
        let ca_key_temp = temp_dir.path().join("ca.key");
        std::fs::copy("./tests/cert.ca.pem", &ca_cert_temp).unwrap();
        std::fs::copy("./tests/key.ca.pem", &ca_key_temp).unwrap();

        // Generate server private key using OpenSSL
        let openssl_key_result = Command::new("openssl")
            .args(["genrsa", "-out", openssl_key_path.to_str().unwrap(), "2048"])
            .output()
            .expect("Failed to execute openssl genrsa command");

        if !openssl_key_result.status.success() {
            panic!(
                "OpenSSL genrsa command failed: {}",
                String::from_utf8_lossy(&openssl_key_result.stderr)
            );
        }

        // Generate CSR using OpenSSL
        let openssl_csr_result = Command::new("openssl")
            .args([
                "req",
                "-new",
                "-key",
                openssl_key_path.to_str().unwrap(),
                "-out",
                openssl_csr_path.to_str().unwrap(),
                "-subj",
                &format!(
                    "/CN={}/O={}/C=CN/ST=ZJ/L=HZ/OU=Dev",
                    common_name,
                    env!("CARGO_PKG_NAME")
                ),
            ])
            .output()
            .expect("Failed to execute openssl req command");

        if !openssl_csr_result.status.success() {
            panic!(
                "OpenSSL req command failed: {}",
                String::from_utf8_lossy(&openssl_csr_result.stderr)
            );
        }

        // Create an extension file for key usage
        let ext_file_path = temp_dir.path().join("extensions.cnf");
        let ext_content =
            "basicConstraints = CA:false\nkeyUsage = critical,digitalSignature,keyEncipherment\n";
        std::fs::write(&ext_file_path, ext_content).unwrap();

        // Sign the CSR with the CA to generate server certificate using OpenSSL
        let openssl_cert_result = Command::new("openssl")
            .args([
                "x509",
                "-req",
                "-in",
                openssl_csr_path.to_str().unwrap(),
                "-CA",
                ca_cert_temp.to_str().unwrap(),
                "-CAkey",
                ca_key_temp.to_str().unwrap(),
                "-CAcreateserial",
                "-out",
                openssl_cert_path.to_str().unwrap(),
                "-days",
                "365",
                "-extfile",
                ext_file_path.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute openssl x509 command");

        if !openssl_cert_result.status.success() {
            panic!(
                "OpenSSL x509 command failed: {}",
                String::from_utf8_lossy(&openssl_cert_result.stderr)
            );
        }

        // Read OpenSSL generated files
        let openssl_cert = std::fs::read_to_string(&openssl_cert_path).unwrap();
        let openssl_key = std::fs::read_to_string(&openssl_key_path).unwrap();

        // Print certificate information for debugging
        println!("=== Generated Server Certificate Details ===");
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
            "Generated Key Usage: {}",
            extract_field_from_pem(&cert_pem, "key_usage")
        );

        println!("\n=== OpenSSL Server Certificate Details ===");
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
        println!(
            "OpenSSL Key Usage: {}",
            extract_field_from_pem(&openssl_cert, "key_usage")
        );

        // Extract and compare certificate information
        // Compare subject information
        let cert_subject = extract_field_from_pem(&cert_pem, "subject");
        let openssl_cert_subject = extract_field_from_pem(&openssl_cert, "subject");
        assert_eq!(
            cert_subject, openssl_cert_subject,
            "Subject fields should match"
        );

        // Compare issuer information
        let cert_issuer = extract_field_from_pem(&cert_pem, "issuer");
        let openssl_cert_issuer = extract_field_from_pem(&openssl_cert, "issuer");
        assert_eq!(
            cert_issuer, openssl_cert_issuer,
            "Issuer fields should match"
        );

        // Both should have private key in PKCS#8 format
        assert!(
            cert_pem.contains("CERTIFICATE"),
            "Generated cert should contain CERTIFICATE"
        );
        assert!(
            openssl_cert.contains("CERTIFICATE"),
            "OpenSSL cert should contain CERTIFICATE"
        );

        assert!(
            key_pem.contains("PRIVATE KEY"),
            "Generated key should be in PRIVATE KEY format"
        );
        assert!(
            openssl_key.contains("PRIVATE KEY"),
            "OpenSSL key should be in PRIVATE KEY format"
        );

        println!("\n=== Test Passed ===");
        println!("Both server certificates have matching subjects and issuers");
    }

    #[tokio::test]
    async fn test_generate_srv_pem_cache() {
        // Create a temporary directory for cache
        let temp_dir = tempdir().unwrap();
        let cache_dir = temp_dir.path().join("cache");
        let ca_cert_path = PathBuf::from("./tests/cert.ca.pem");
        let ca_key_path = PathBuf::from("./tests/key.ca.pem");

        // Initialize CertManager with the existing CA
        let cert_manager =
            CertManager::new(ca_cert_path.clone(), ca_key_path.clone(), cache_dir.clone())
                .await
                .unwrap();

        let common_name = "test-cache.example.com";

        // Generate certificate for the first time
        let (cert_pem1, key_pem1) = cert_manager.generate_srv_pem(common_name).await.unwrap();

        // Check that certificate is now in memory cache
        assert!(cert_manager.cache.lock().unwrap().contains_key(common_name));

        // Check that certificate files are written to disk cache
        let hash = blake3::hash(common_name.as_bytes());
        let hash_hex = hex::encode(hash.as_bytes());
        let cert_path = cache_dir.join(format!("{}.cert", hash_hex));
        let key_path = cache_dir.join(format!("{}.key", hash_hex));
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Generate certificate for the second time (should use cache)
        let (cert_pem2, key_pem2) = cert_manager.generate_srv_pem(common_name).await.unwrap();

        // Verify cached certificate is returned
        assert_eq!(cert_pem1, cert_pem2);
        assert_eq!(key_pem1, key_pem2);

        // Create a new CertManager to test disk cache loading
        let cert_manager2 = CertManager::new(ca_cert_path.clone(), ca_key_path.clone(), cache_dir)
            .await
            .unwrap();

        // Generate certificate with new manager (should load from disk cache)
        let (cert_pem3, key_pem3) = cert_manager2.generate_srv_pem(common_name).await.unwrap();

        // Verify disk cached certificate is returned
        assert_eq!(cert_pem1, cert_pem3);
        assert_eq!(key_pem1, key_pem3);
        // Memory cache should now also contain the certificate
        assert!(
            cert_manager2
                .cache
                .lock()
                .unwrap()
                .contains_key(common_name)
        );
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
            "key_usage" => {
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

                // Extract Key Usage from the full text output
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("Key Usage") {
                        // Also get the next line which contains the value
                        let lines: Vec<&str> = output_str.lines().collect();
                        let line_idx = lines.iter().position(|&l| l.contains("Key Usage")).unwrap();
                        if line_idx + 1 < lines.len() {
                            return format!("{}{}", line.trim(), lines[line_idx + 1].trim());
                        }
                        return line.trim().to_string();
                    }
                }
                "Key Usage not found".to_string()
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
