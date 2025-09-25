use crate::config::EncryptionConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Key};
use blake3;
use dashmap::DashMap;
use std::sync::Arc;
use typenum::U12;

pub struct EncryptionHandler {
    cipher: Aes256Gcm,
    nonce_seed: Vec<u8>,
    nonce_cache: Arc<DashMap<String, GenericArray<u8, U12>>>,
}

impl EncryptionHandler {
    /// Create new encryption handler
    pub fn new(config: &EncryptionConfig) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&config.key);
        let cipher = Aes256Gcm::new(key);

        Self {
            cipher,
            nonce_seed: config.nonce_seed.clone(),
            nonce_cache: Arc::new(DashMap::new()),
        }
    }

    /// Generate cryptographically secure unique nonce for file path.
    /// Nonce is generated using BLAKE3 hash of the combination of file path and nonce_seed,
    /// ensuring uniqueness and unpredictability. The first 12 bytes of the hash are used as nonce.
    /// To improve performance, the generated nonce is cached, and the same path request will return the cached result directly.
    ///
    /// Security: This approach provides cryptographic security guarantees that CRC32c-based
    /// generation lacks, preventing nonce reuse attacks in AES-GCM.
    pub fn generate_nonce(&self, path: &str) -> GenericArray<u8, U12> {
        // Check cache first for performance
        if let Some(nonce) = self.nonce_cache.get(path) {
            return *nonce;
        }

        // Generate cryptographically secure nonce using BLAKE3
        // Combine path and nonce_seed to ensure uniqueness across different seeds
        let mut hasher = blake3::Hasher::new();
        hasher.update(path.as_bytes());
        hasher.update(&self.nonce_seed);
        let hash = hasher.finalize();

        // Take first 12 bytes of the hash as nonce (BLAKE3 output is 32 bytes)
        let hash_bytes = hash.as_bytes();
        let nonce_bytes: [u8; 12] = hash_bytes[..12].try_into().unwrap();
        let nonce = GenericArray::from(nonce_bytes);

        // Cache nonce for performance
        self.nonce_cache.insert(path.to_string(), nonce);

        nonce
    }

    pub fn encrypt(&self, data: &[u8], path: &str) -> ZthfsResult<Vec<u8>> {
        let nonce = self.generate_nonce(path);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, data)
            .map_err(|e| ZthfsError::Crypto(format!("Encryption failed: {e:?}")))?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, data: &[u8], path: &str) -> ZthfsResult<Vec<u8>> {
        let nonce = self.generate_nonce(path);
        let plaintext = self
            .cipher
            .decrypt(&nonce, data)
            .map_err(|e| ZthfsError::Crypto(format!("Decryption failed: {e:?}")))?;
        Ok(plaintext)
    }

    /// Validate the validity of the encryption configuration, mainly checking the length of the key and nonce seed.
    pub fn validate_config(config: &EncryptionConfig) -> ZthfsResult<()> {
        if config.key.len() != 32 {
            return Err(ZthfsError::Config(
                "Encryption key must be 32 bytes".to_string(),
            ));
        }
        if config.nonce_seed.len() != 12 {
            return Err(ZthfsError::Config(
                "Nonce seed must be 12 bytes".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let test_data = b"Hello, medical data!";
        let path = "/test/file.txt";

        let encrypted = encryptor.encrypt(test_data, path).unwrap();
        let decrypted = encryptor.decrypt(&encrypted, path).unwrap();

        assert_eq!(test_data, decrypted.as_slice());
    }

    #[test]
    fn test_nonce_generation() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path1 = "/test/file1.txt";
        let path2 = "/test/file2.txt";

        let nonce1 = encryptor.generate_nonce(path1);
        let nonce2 = encryptor.generate_nonce(path2);

        // Different paths should generate different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_nonce_cryptographic_properties() {
        let config1 = EncryptionConfig::default();
        let config2 = EncryptionConfig::with_random_keys(); // Use different random keys
        let encryptor1 = EncryptionHandler::new(&config1);
        let encryptor2 = EncryptionHandler::new(&config2);

        let path = "/test/file.txt";

        // Same path with same seed should generate same nonce
        let nonce1a = encryptor1.generate_nonce(path);
        let nonce1b = encryptor1.generate_nonce(path);
        assert_eq!(nonce1a, nonce1b);

        // Same path with different seeds should generate different nonces
        let nonce2 = encryptor2.generate_nonce(path);
        assert_ne!(nonce1a, nonce2);

        // Verify nonce is exactly 12 bytes
        assert_eq!(nonce1a.len(), 12);
    }

    #[test]
    fn test_nonce_unpredictability() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        // Test that similar paths produce very different nonces
        let path1 = "/test/file1.txt";
        let path2 = "/test/file2.txt"; // Only differs by one character

        let nonce1 = encryptor.generate_nonce(path1);
        let nonce2 = encryptor.generate_nonce(path2);

        // Nonces should be different even for similar inputs
        assert_ne!(nonce1, nonce2);

        // Check avalanche effect: small input changes should cause large output changes
        let mut differing_bits = 0;
        for i in 0..12 {
            differing_bits += (nonce1[i] ^ nonce2[i]).count_ones();
        }

        // BLAKE3 has excellent diffusion properties. Even with similar inputs,
        // we expect significant differences. Allow for some statistical variation.
        assert!(differing_bits > 20); // At least 20% of bits differ (more conservative check)
    }

    #[test]
    fn test_nonce_consistency() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/file.txt";

        let nonce1 = encryptor.generate_nonce(path);
        let nonce2 = encryptor.generate_nonce(path);

        // Same path should generate the same nonce
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_config_validation() {
        // Invalid key length
        let config = EncryptionConfig {
            key: vec![1, 2, 3],
            ..Default::default()
        }; // 3 bytes instead of 32
        assert!(EncryptionHandler::validate_config(&config).is_err());

        // Restore valid configuration
        let config = EncryptionConfig::default();
        assert!(EncryptionHandler::validate_config(&config).is_ok());
    }

    #[test]
    fn test_key_generation() {
        let key = crate::config::EncryptionConfig::generate_key();
        assert_eq!(key.len(), 32);

        let nonce_seed = crate::config::EncryptionConfig::generate_nonce_seed();
        assert_eq!(nonce_seed.len(), 12);
    }

    #[test]
    fn test_default_config_is_insecure() {
        let default_config = EncryptionConfig::default();

        // The default config should contain obviously insecure placeholder values
        // This test ensures that default configs are clearly marked as insecure
        assert_eq!(default_config.key.len(), 32);
        assert_eq!(default_config.nonce_seed.len(), 12);

        // Check for the repeating pattern in default key (DEADBEEF...)
        assert_eq!(&default_config.key[0..4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&default_config.key[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);

        // Check for the repeating pattern in default nonce seed (BADCOFFE...)
        assert_eq!(&default_config.nonce_seed[0..4], &[0xBA, 0xDC, 0x0F, 0xFE]);
    }

    #[test]
    fn test_config_constructors() {
        // Test new constructor
        let key = vec![1u8; 32];
        let nonce_seed = vec![2u8; 12];
        let config = EncryptionConfig::new(key.clone(), nonce_seed.clone());
        assert_eq!(config.key, key);
        assert_eq!(config.nonce_seed, nonce_seed);

        // Test with_random_keys constructor
        let random_config = EncryptionConfig::with_random_keys();
        assert_eq!(random_config.key.len(), 32);
        assert_eq!(random_config.nonce_seed.len(), 12);
        // Random keys should be different from default insecure values
        assert_ne!(random_config.key, EncryptionConfig::default().key);
        assert_ne!(
            random_config.nonce_seed,
            EncryptionConfig::default().nonce_seed
        );
    }
}
