use anyhow::Result;
use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use rand::RngCore;

pub(crate) struct Cipher {
    key: [u8; 32],
    associated_data: Vec<u8>,
}

pub(crate) fn default_token() -> String {
    package_info()
}

pub(crate) fn package_info() -> String {
    format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

impl Cipher {
    pub(crate) fn new(key: impl AsRef<str>) -> Self {
        let key = key.as_ref().as_bytes();
        let key: [u8; 32] = blake3::hash(key).into();
        let associated_data = package_info().into_bytes();

        Cipher {
            key,
            associated_data,
        }
    }

    pub(crate) fn encrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let data = data.as_ref();
        
        // Generate a random nonce for each encryption
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let ciphertext = cipher
            .encrypt(&nonce.into(), &[&self.associated_data, data].concat()[..])
            .map_err(|e| anyhow!("encryption error: {e:?}"))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    pub(crate) fn decrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let data = data.as_ref();
        
        if data.len() < 12 {
            return Err(anyhow!("Data too short to contain nonce"));
        }
        
        // Extract nonce from the beginning
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce: [u8; 12] = nonce_bytes.try_into()
            .map_err(|_| anyhow!("Invalid nonce length"))?;
        
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let plaintext = cipher
            .decrypt(&nonce.into(), ciphertext)
            .map_err(|e| anyhow!("decryption error: {e:?}"))?;

        // Remove associated data from plaintext
        if plaintext.len() < self.associated_data.len() {
            return Err(anyhow!("Decrypted data too short"));
        }
        
        let actual_data = &plaintext[self.associated_data.len()..];
        Ok(actual_data.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = Cipher::new("test-key");
        let original_data = b"Hello, World!";

        let encrypted_data = cipher.encrypt(original_data).expect("Encryption failed");
        let decrypted_data = cipher.decrypt(&encrypted_data).expect("Decryption failed");

        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_encrypt_different_keys() {
        let cipher1 = Cipher::new("key1");
        let cipher2 = Cipher::new("key2");
        let original_data = b"Hello, World!";

        let encrypted_data1 = cipher1.encrypt(original_data).expect("Encryption failed");
        let encrypted_data2 = cipher2.encrypt(original_data).expect("Encryption failed");

        // Encrypted data should be different when using different keys
        assert_ne!(encrypted_data1, encrypted_data2);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let cipher = Cipher::new("test-key");
        let original_data = b"";

        let encrypted_data = cipher.encrypt(original_data).expect("Encryption failed");
        let decrypted_data = cipher.decrypt(&encrypted_data).expect("Decryption failed");

        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_encrypt_large_data() {
        let cipher = Cipher::new("test-key");
        let original_data = vec![42u8; 10000]; // Large data of 10,000 bytes

        let encrypted_data = cipher.encrypt(&original_data).expect("Encryption failed");
        let decrypted_data = cipher.decrypt(&encrypted_data).expect("Decryption failed");

        assert_eq!(original_data, decrypted_data);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let cipher = Cipher::new("test-key");
        let invalid_data = b"invalid encrypted data";

        let result = cipher.decrypt(invalid_data);

        // Decryption should fail for invalid data
        assert!(result.is_err());
    }
}
