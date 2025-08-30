use anyhow::Result;
use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadMutInPlace};

pub struct Cipher {
    key: [u8; 32],
    nonce: [u8; 12],
    associated_data: Vec<u8>,
}

pub fn default_token() -> String {
    package_info()
}

pub fn package_info() -> String {
    format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

impl Cipher {
    pub fn new(key: impl AsRef<str>) -> Self {
        let key = key.as_ref().as_bytes();
        let key: [u8; 32] = blake3::hash(key).into();
        let associated_data = package_info().into_bytes();

        Cipher {
            nonce: key[..12].try_into().unwrap(), // this unwrap is safe because we know that the slice has the correct length
            key,
            associated_data,
        }
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let data = data.as_ref();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(data);

        let mut cipher = ChaCha20Poly1305::new(&self.key.into());
        cipher
            .encrypt_in_place(&self.nonce.into(), &self.associated_data, &mut buffer)
            .map_err(|e| anyhow!("encrypt in replace error: {e:?}"))?;

        Ok(buffer)
    }

    pub fn decrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(data.as_ref());

        let mut cipher = ChaCha20Poly1305::new(&self.key.into());
        cipher
            .decrypt_in_place(&self.nonce.into(), &self.associated_data, &mut buffer)
            .map_err(|e| anyhow!("decrypt in place error: {e:?}"))?;

        Ok(buffer)
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

    #[test]
    fn test_consistent_encryption() {
        let cipher = Cipher::new("consistent-key");
        let original_data = b"Consistent test data";

        // Encrypt the same data twice
        let encrypted_data1 = cipher.encrypt(original_data).expect("Encryption failed");
        let encrypted_data2 = cipher.encrypt(original_data).expect("Encryption failed");

        // With the same key and nonce, encryption should be consistent
        assert_eq!(encrypted_data1, encrypted_data2);
    }
}
