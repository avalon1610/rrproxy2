use anyhow::Result;
use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadMutInPlace};

pub struct Encryptor {
    key: [u8; 32],
    nonce: [u8; 12],
    associated_data: Vec<u8>,
}

pub fn default_token() -> String {
    format!("{}", package_info())
}

pub fn package_info() -> String {
    format!("{}-{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

impl Encryptor {
    pub fn new(key: impl AsRef<str>) -> Self {
        let key = key.as_ref().as_bytes();
        let key: [u8; 32] = blake3::hash(key).into();
        let associated_data = package_info().into_bytes();

        Encryptor {
            nonce: key[..12].try_into().unwrap(), // this unwrap is safe because we know that the slice has the correct length
            key,
            associated_data,
        }
    }

    pub fn encrypt(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>> {
        let data = data.as_ref();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(data);

        let mut cipher = ChaCha20Poly1305::new(&self.key.try_into()?);
        cipher
            .encrypt_in_place(&self.nonce.try_into()?, &self.associated_data, &mut buffer)
            .map_err(|e| anyhow!("encrypt in replace error: {e:?}"))?;

        Ok(buffer)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(data);

        let mut cipher = ChaCha20Poly1305::new(&self.key.try_into()?);
        cipher
            .decrypt_in_place(&self.nonce.try_into()?, &self.associated_data, &mut buffer)
            .map_err(|e| anyhow!("decrypt in place error: {e:?}"))?;

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = Encryptor::new("test-key");
        let original_data = b"Hello, World!";

        let encrypted_data = encryptor.encrypt(original_data).expect("Encryption failed");
        let decrypted_data = encryptor
            .decrypt(&encrypted_data)
            .expect("Decryption failed");

        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_encrypt_different_keys() {
        let encryptor1 = Encryptor::new("key1");
        let encryptor2 = Encryptor::new("key2");
        let original_data = b"Hello, World!";

        let encrypted_data1 = encryptor1
            .encrypt(original_data)
            .expect("Encryption failed");
        let encrypted_data2 = encryptor2
            .encrypt(original_data)
            .expect("Encryption failed");

        // Encrypted data should be different when using different keys
        assert_ne!(encrypted_data1, encrypted_data2);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let encryptor = Encryptor::new("test-key");
        let original_data = b"";

        let encrypted_data = encryptor.encrypt(original_data).expect("Encryption failed");
        let decrypted_data = encryptor
            .decrypt(&encrypted_data)
            .expect("Decryption failed");

        assert_eq!(original_data, decrypted_data.as_slice());
    }

    #[test]
    fn test_encrypt_large_data() {
        let encryptor = Encryptor::new("test-key");
        let original_data = vec![42u8; 10000]; // Large data of 10,000 bytes

        let encrypted_data = encryptor
            .encrypt(&original_data)
            .expect("Encryption failed");
        let decrypted_data = encryptor
            .decrypt(&encrypted_data)
            .expect("Decryption failed");

        assert_eq!(original_data, decrypted_data);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        let encryptor = Encryptor::new("test-key");
        let invalid_data = b"invalid encrypted data";

        let result = encryptor.decrypt(invalid_data);

        // Decryption should fail for invalid data
        assert!(result.is_err());
    }

    #[test]
    fn test_consistent_encryption() {
        let encryptor = Encryptor::new("consistent-key");
        let original_data = b"Consistent test data";

        // Encrypt the same data twice
        let encrypted_data1 = encryptor.encrypt(original_data).expect("Encryption failed");
        let encrypted_data2 = encryptor.encrypt(original_data).expect("Encryption failed");

        // With the same key and nonce, encryption should be consistent
        assert_eq!(encrypted_data1, encrypted_data2);
    }
}
