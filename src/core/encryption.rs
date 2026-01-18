use crate::config::EncryptionConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Key};
use blake3;
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use typenum::U12;

/// Manages nonce counters for secure AES-GCM encryption.
///
/// AES-256-GCM requires that nonces are NEVER reused under the same key.
/// This manager maintains a per-file counter to ensure nonce uniqueness,
/// even when files are modified multiple times.
///
/// The counter for each file is stored as an extended attribute on the
/// underlying file, ensuring persistence across filesystem restarts.
pub struct NonceManager {
    /// Base directory for the filesystem (used to resolve virtual paths to real paths)
    data_dir: PathBuf,
    /// In-memory cache of nonce counters for performance
    counter_cache: Arc<DashMap<String, u64>>,
    /// Extended attribute namespace for storing counters
    xattr_namespace: String,
}

impl NonceManager {
    /// Create a new NonceManager with the specified data directory.
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            counter_cache: Arc::new(DashMap::new()),
            xattr_namespace: "user.zthfs".to_string(),
        }
    }

    /// Create a new NonceManager with custom xattr namespace.
    pub fn with_namespace(data_dir: PathBuf, namespace: String) -> Self {
        Self {
            data_dir,
            counter_cache: Arc::new(DashMap::new()),
            xattr_namespace: namespace,
        }
    }

    /// Get the real path for a virtual path.
    fn virtual_to_real(&self, virtual_path: &str) -> PathBuf {
        let path = Path::new(virtual_path);
        self.data_dir.join(path.strip_prefix("/").unwrap_or(path))
    }

    /// Get the current nonce counter for a file, initializing if necessary.
    ///
    /// This reads the counter from extended attributes, falling back to the
    /// in-memory cache if the extended attribute doesn't exist.
    pub fn get_counter(&self, virtual_path: &str) -> ZthfsResult<u64> {
        // Check cache first
        if let Some(counter) = self.counter_cache.get(virtual_path) {
            return Ok(*counter);
        }

        // Read from extended attribute
        let real_path = self.virtual_to_real(virtual_path);
        let xattr_name = format!("{}.nonce_counter", self.xattr_namespace);

        match xattr::get(&real_path, &xattr_name) {
            Ok(Some(bytes)) if bytes.len() == 8 => {
                let counter = u64::from_be_bytes(bytes.try_into().unwrap());
                self.counter_cache.insert(virtual_path.to_string(), counter);
                Ok(counter)
            }
            _ => {
                // Initialize counter to 0 for new files
                self.counter_cache.insert(virtual_path.to_string(), 0);
                Ok(0)
            }
        }
    }

    /// Increment and return the next nonce counter for a file.
    ///
    /// This increments the counter, updates both the cache and extended
    /// attribute, and returns the new counter value.
    pub fn increment_counter(&self, virtual_path: &str) -> ZthfsResult<u64> {
        let current = self.get_counter(virtual_path)?;
        let next = current.saturating_add(1);

        // Check for counter overflow (should never happen in practice)
        if next == 0 {
            return Err(ZthfsError::Crypto(
                "Nonce counter overflow for file. This indicates an extreme scenario requiring manual intervention.".to_string()
            ));
        }

        // Update cache
        self.counter_cache.insert(virtual_path.to_string(), next);

        // Update extended attribute (ignore errors if file doesn't exist yet)
        let real_path = self.virtual_to_real(virtual_path);
        let xattr_name = format!("{}.nonce_counter", self.xattr_namespace);
        let bytes = next.to_be_bytes();
        let _ = xattr::set(&real_path, &xattr_name, &bytes);

        Ok(next)
    }

    /// Reset the counter for a file (e.g., after re-encryption with a new key).
    pub fn reset_counter(&self, virtual_path: &str) -> ZthfsResult<()> {
        self.counter_cache.insert(virtual_path.to_string(), 0);

        let real_path = self.virtual_to_real(virtual_path);
        let xattr_name = format!("{}.nonce_counter", self.xattr_namespace);
        let bytes = 0u64.to_be_bytes();
        let _ = xattr::set(&real_path, &xattr_name, &bytes);

        Ok(())
    }

    /// Remove the counter for a file (e.g., when deleting a file).
    pub fn remove_counter(&self, virtual_path: &str) -> ZthfsResult<()> {
        self.counter_cache.remove(virtual_path);

        let real_path = self.virtual_to_real(virtual_path);
        let xattr_name = format!("{}.nonce_counter", self.xattr_namespace);
        let _ = xattr::remove(&real_path, &xattr_name);

        Ok(())
    }
}

pub struct EncryptionHandler {
    cipher: Aes256Gcm,
    nonce_seed: Vec<u8>,
    nonce_cache: Arc<DashMap<String, GenericArray<u8, U12>>>,
    /// Optional nonce manager for counter-based nonce generation
    nonce_manager: Option<Arc<NonceManager>>,
    /// Whether to use counter-based nonces (more secure) or deterministic (legacy)
    use_counter_nonces: bool,
}

impl EncryptionHandler {
    /// Create new encryption handler without nonce manager (legacy mode).
    ///
    /// # Security Warning
    /// Without a nonce manager, this handler uses deterministic nonces
    /// based on file paths. This creates a CRITICAL vulnerability where
    /// modifying a file reuses the same nonce, allowing plaintext recovery
    /// through XOR analysis. Always prefer `with_nonce_manager()`.
    pub fn new(config: &EncryptionConfig) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&config.key);
        let cipher = Aes256Gcm::new(key);

        Self {
            cipher,
            nonce_seed: config.nonce_seed.clone(),
            nonce_cache: Arc::new(DashMap::new()),
            nonce_manager: None,
            use_counter_nonces: false,
        }
    }

    /// Create new encryption handler with nonce manager (secure mode).
    ///
    /// This is the RECOMMENDED constructor for production use. It ensures
    /// that each encryption operation uses a unique nonce by maintaining
    /// per-file counters stored as extended attributes.
    ///
    /// # Arguments
    /// * `config` - Encryption configuration containing key and nonce seed
    /// * `nonce_manager` - Nonce manager for counter-based nonce generation
    pub fn with_nonce_manager(config: &EncryptionConfig, nonce_manager: Arc<NonceManager>) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(&config.key);
        let cipher = Aes256Gcm::new(key);

        Self {
            cipher,
            nonce_seed: config.nonce_seed.clone(),
            nonce_cache: Arc::new(DashMap::new()),
            nonce_manager: Some(nonce_manager),
            use_counter_nonces: true,
        }
    }

    /// Set the nonce manager for this encryption handler.
    ///
    /// This can be used to upgrade a legacy handler to use counter-based nonces.
    pub fn set_nonce_manager(&mut self, nonce_manager: Arc<NonceManager>) {
        self.nonce_manager = Some(nonce_manager);
        self.use_counter_nonces = true;
        // Clear the nonce cache since we're changing nonce generation strategy
        self.nonce_cache.clear();
    }

    /// Check if this handler uses counter-based (secure) nonces.
    pub fn uses_counter_nonces(&self) -> bool {
        self.use_counter_nonces
    }

    /// Generate cryptographically secure unique nonce for file path.
    ///
    /// # Security Behavior
    ///
    /// - **With nonce manager (secure)**: Uses per-file counters to ensure
    ///   unique nonces even when files are modified. The nonce is derived from
    ///   `BLAKE3(path || nonce_seed || counter)`.
    ///
    /// - **Without nonce manager (legacy)**: Uses deterministic nonces
    ///   `BLAKE3(path || nonce_seed)`. This is VULNERABLE to nonce reuse
    ///   when files are modified.
    ///
    /// # Errors
    /// Returns `ZthfsError::Crypto` if hash conversion fails or counter overflow occurs.
    /// Generate nonce for encryption (increments counter).
    pub fn generate_nonce(&self, path: &str) -> ZthfsResult<GenericArray<u8, U12>> {
        self.generate_nonce_with_mode(path, true)
    }

    /// Generate nonce for decryption (uses current counter without incrementing).
    pub fn generate_nonce_for_decrypt(&self, path: &str) -> ZthfsResult<GenericArray<u8, U12>> {
        self.generate_nonce_with_mode(path, false)
    }

    /// Internal method to generate nonce with specified mode.
    fn generate_nonce_with_mode(&self, path: &str, for_encrypt: bool) -> ZthfsResult<GenericArray<u8, U12>> {
        // If using counter-based nonces, use counter in hash
        if self.use_counter_nonces
            && let Some(manager) = &self.nonce_manager
        {
                // For encryption: get current counter, then increment
                // For decryption: just get current counter (don't increment)
                let counter = if for_encrypt {
                    manager.increment_counter(path)?
                } else {
                    // For decryption, we need to find the counter that was used
                    // Try to get the last used counter from the manager
                    let c = manager.get_counter(path)?;
                    if c == 0 {
                        // File hasn't been encrypted yet, this is an error
                        return Err(ZthfsError::Crypto(
                            "Cannot decrypt file: no encryption counter found".to_string()
                        ));
                    }
                    c
                };

                // Check if we have a cached nonce for this specific counter value
                let cache_key = format!("{}#{}", path, counter);
                if let Some(nonce) = self.nonce_cache.get(&cache_key) {
                    return Ok(*nonce);
                }

                // Generate nonce using BLAKE3(path || nonce_seed || counter)
                let mut hasher = blake3::Hasher::new();
                hasher.update(path.as_bytes());
                hasher.update(&self.nonce_seed);
                hasher.update(&counter.to_be_bytes());
                let hash = hasher.finalize();

                let hash_bytes = hash.as_bytes();
                let nonce_bytes: [u8; 12] = hash_bytes[..12]
                    .try_into()
                    .map_err(|_| ZthfsError::Crypto("Failed to convert hash to nonce".to_string()))?;
                let nonce = GenericArray::from(nonce_bytes);

                // Cache with counter-specific key
                self.nonce_cache.insert(cache_key, nonce);
                return Ok(nonce);
        }

        // Legacy mode: deterministic nonce (VULNERABLE to reuse on modification)
        // This path is taken when use_counter_nonces is false
        if let Some(nonce) = self.nonce_cache.get(path) {
            return Ok(*nonce);
        }

        // Generate cryptographically secure nonce using BLAKE3
        // Combine path and nonce_seed to ensure uniqueness across different seeds
        let mut hasher = blake3::Hasher::new();
        hasher.update(path.as_bytes());
        hasher.update(&self.nonce_seed);
        let hash = hasher.finalize();

        // Take first 12 bytes of hash as nonce (BLAKE3 output is 32 bytes)
        let hash_bytes = hash.as_bytes();
        let nonce_bytes: [u8; 12] = hash_bytes[..12]
            .try_into()
            .map_err(|_| ZthfsError::Crypto("Failed to convert hash to nonce".to_string()))?;
        let nonce = GenericArray::from(nonce_bytes);

        // Cache nonce for performance
        self.nonce_cache.insert(path.to_string(), nonce);

        Ok(nonce)
    }

    pub fn encrypt(&self, data: &[u8], path: &str) -> ZthfsResult<Vec<u8>> {
        let nonce = self.generate_nonce(path)?;
        let ciphertext = self
            .cipher
            .encrypt(&nonce, data)
            .map_err(|e| ZthfsError::Crypto(format!("Encryption failed: {e:?}")))?;
        Ok(ciphertext)
    }

    pub fn decrypt(&self, data: &[u8], path: &str) -> ZthfsResult<Vec<u8>> {
        let nonce = self.generate_nonce_for_decrypt(path)?;
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

        let nonce1 = encryptor.generate_nonce(path1).unwrap();
        let nonce2 = encryptor.generate_nonce(path2).unwrap();

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
        let nonce1a = encryptor1.generate_nonce(path).unwrap();
        let nonce1b = encryptor1.generate_nonce(path).unwrap();
        assert_eq!(nonce1a, nonce1b);

        // Same path with different seeds should generate different nonces
        let nonce2 = encryptor2.generate_nonce(path).unwrap();
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

        let nonce1 = encryptor.generate_nonce(path1).unwrap();
        let nonce2 = encryptor.generate_nonce(path2).unwrap();

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

        let nonce1 = encryptor.generate_nonce(path).unwrap();
        let nonce2 = encryptor.generate_nonce(path).unwrap();

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

    #[test]
    fn test_decryption_with_invalid_ciphertext() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/file.txt";
        let invalid_ciphertext = vec![1u8; 16]; // Too short and invalid

        let result = encryptor.decrypt(&invalid_ciphertext, path);
        assert!(result.is_err());

        if let Err(ZthfsError::Crypto(msg)) = result {
            assert!(msg.contains("Decryption failed"));
        } else {
            panic!("Expected Crypto error");
        }
    }

    #[test]
    fn test_decryption_with_corrupted_ciphertext() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/file.txt";
        let test_data = b"Hello, medical data!";

        // First encrypt the data
        let encrypted = encryptor.encrypt(test_data, path).unwrap();

        // Corrupt the ciphertext by flipping some bytes
        let mut corrupted = encrypted.clone();
        corrupted[0] = corrupted[0].wrapping_add(1);
        corrupted[1] = corrupted[1].wrapping_add(1);

        // Decryption should fail
        let result = encryptor.decrypt(&corrupted, path);
        assert!(result.is_err());

        if let Err(ZthfsError::Crypto(msg)) = result {
            assert!(msg.contains("Decryption failed"));
        } else {
            panic!("Expected Crypto error");
        }
    }

    #[test]
    fn test_decryption_with_wrong_length_ciphertext() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/file.txt";

        // Ciphertext that's too short (AES-GCM has authentication tag overhead)
        let too_short = vec![1u8; 5];
        let result = encryptor.decrypt(&too_short, path);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_cache_consistency() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/cached_file.txt";

        // First call should compute and cache
        let nonce1 = encryptor.generate_nonce(path).unwrap();
        // Second call should return cached value
        let nonce2 = encryptor.generate_nonce(path).unwrap();

        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn test_validate_config_invalid_nonce_seed() {
        // Valid key but invalid nonce_seed
        let config = EncryptionConfig {
            key: vec![1u8; 32],
            nonce_seed: vec![1, 2, 3], // Only 3 bytes instead of 12
        };

        let result = EncryptionHandler::validate_config(&config);
        assert!(result.is_err());

        if let Err(ZthfsError::Config(msg)) = result {
            assert!(msg.contains("Nonce seed"));
        } else {
            panic!("Expected Config error");
        }
    }

    #[test]
    fn test_validate_config_invalid_key() {
        // Valid nonce_seed but invalid key
        let config = EncryptionConfig {
            key: vec![1, 2, 3, 4, 5], // Only 5 bytes instead of 32
            nonce_seed: vec![2u8; 12],
        };

        let result = EncryptionHandler::validate_config(&config);
        assert!(result.is_err());

        if let Err(ZthfsError::Config(msg)) = result {
            assert!(msg.contains("key"));
        } else {
            panic!("Expected Config error");
        }
    }

    #[test]
    fn test_encryption_empty_data() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let path = "/test/empty.txt";
        let encrypted = encryptor.encrypt(&[], path).unwrap();
        let decrypted = encryptor.decrypt(&encrypted, path).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encryption_large_data() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let large_data = vec![42u8; 1024 * 1024]; // 1 MB
        let path = "/test/large.bin";

        let encrypted = encryptor.encrypt(&large_data, path).unwrap();
        let decrypted = encryptor.decrypt(&encrypted, path).unwrap();

        assert_eq!(large_data, decrypted);
    }

    // ===== NonceManager Tests =====

    #[test]
    fn test_nonce_manager_creation() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::new(temp_dir.path().to_path_buf());
        assert_eq!(manager.get_counter("/test/file.txt").unwrap(), 0);
    }

    #[test]
    fn test_nonce_manager_increment() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::new(temp_dir.path().to_path_buf());

        let path = "/test/file.txt";
        
        // Initial counter should be 0
        assert_eq!(manager.get_counter(path).unwrap(), 0);
        
        // After increment, should be 1
        assert_eq!(manager.increment_counter(path).unwrap(), 1);
        
        // Counter should persist
        assert_eq!(manager.get_counter(path).unwrap(), 1);
        
        // Another increment
        assert_eq!(manager.increment_counter(path).unwrap(), 2);
    }

    #[test]
    fn test_nonce_manager_different_paths() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::new(temp_dir.path().to_path_buf());

        let path1 = "/test/file1.txt";
        let path2 = "/test/file2.txt";
        
        // Each path should have its own counter
        assert_eq!(manager.increment_counter(path1).unwrap(), 1);
        assert_eq!(manager.increment_counter(path2).unwrap(), 1);
        assert_eq!(manager.increment_counter(path1).unwrap(), 2);
        
        assert_eq!(manager.get_counter(path1).unwrap(), 2);
        assert_eq!(manager.get_counter(path2).unwrap(), 1);
    }

    #[test]
    fn test_nonce_manager_reset() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::new(temp_dir.path().to_path_buf());

        let path = "/test/file.txt";
        
        manager.increment_counter(path).unwrap();
        manager.increment_counter(path).unwrap();
        assert_eq!(manager.get_counter(path).unwrap(), 2);
        
        // Reset should bring counter back to 0
        manager.reset_counter(path).unwrap();
        assert_eq!(manager.get_counter(path).unwrap(), 0);
    }

    #[test]
    fn test_nonce_manager_remove() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::new(temp_dir.path().to_path_buf());

        let path = "/test/file.txt";
        
        manager.increment_counter(path).unwrap();
        assert!(manager.counter_cache.contains_key(path));
        
        manager.remove_counter(path).unwrap();
        assert!(!manager.counter_cache.contains_key(path));
    }

    #[test]
    fn test_nonce_manager_with_custom_namespace() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let manager = NonceManager::with_namespace(
            temp_dir.path().to_path_buf(),
            "custom.namespace".to_string()
        );
        
        let path = "/test/file.txt";
        assert_eq!(manager.increment_counter(path).unwrap(), 1);
    }

    #[test]
    fn test_encryption_handler_with_nonce_manager() {
        use tempfile::tempdir;
        use std::sync::Arc;
        
        let temp_dir = tempdir().unwrap();
        let config = EncryptionConfig::with_random_keys();
        let manager = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
        
        let handler = EncryptionHandler::with_nonce_manager(&config, manager.clone());
        
        assert!(handler.uses_counter_nonces());
        
        let path = "/test/file.txt";
        
        // First encryption should use counter 1
        let nonce1 = handler.generate_nonce(path).unwrap();
        assert_eq!(manager.get_counter(path).unwrap(), 1);
        
        // Second encryption should use counter 2
        let nonce2 = handler.generate_nonce(path).unwrap();
        assert_eq!(manager.get_counter(path).unwrap(), 2);
        
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_encryption_handler_set_nonce_manager() {
        use tempfile::tempdir;
        use std::sync::Arc;
        
        let temp_dir = tempdir().unwrap();
        let config = EncryptionConfig::with_random_keys();
        
        let mut handler = EncryptionHandler::new(&config);
        assert!(!handler.uses_counter_nonces());
        
        let manager = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
        handler.set_nonce_manager(manager);
        
        assert!(handler.uses_counter_nonces());
    }

    #[test]
    fn test_counter_based_nonce_uniqueness() {
        use tempfile::tempdir;
        use std::sync::Arc;
        
        let temp_dir = tempdir().unwrap();
        let config = EncryptionConfig::with_random_keys();
        let manager = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
        
        let handler = EncryptionHandler::with_nonce_manager(&config, manager);
        
        let path = "/test/file.txt";
        
        // Generate 100 nonces for the same path
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..100 {
            let nonce = handler.generate_nonce(path).unwrap();
            // Convert to vec for hashing
            let nonce_vec: Vec<u8> = nonce.to_vec();
            nonces.insert(nonce_vec);
        }
        
        // All nonces should be unique
        assert_eq!(nonces.len(), 100);
    }

    #[test]
    fn test_nonce_no_reuse_across_file_modifications() {
        use tempfile::tempdir;
        use std::sync::Arc;
        
        let temp_dir = tempdir().unwrap();
        let config = EncryptionConfig::with_random_keys();
        let manager = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
        
        let handler = EncryptionHandler::with_nonce_manager(&config, manager);
        
        let path = "/medical/patient_record.txt";
        let data1 = b"Initial diagnosis: Healthy";
        let data2 = b"Updated diagnosis: Condition detected";
        let data3 = b"Final diagnosis: Recovered";
        
        // First version: encrypt and immediately decrypt
        let encrypted1 = handler.encrypt(data1, path).unwrap();
        assert_eq!(handler.decrypt(&encrypted1, path).unwrap(), data1.to_vec());
        
        // Second version: encrypt and immediately decrypt
        let encrypted2 = handler.encrypt(data2, path).unwrap();
        assert_eq!(handler.decrypt(&encrypted2, path).unwrap(), data2.to_vec());
        
        // Third version: encrypt and immediately decrypt
        let encrypted3 = handler.encrypt(data3, path).unwrap();
        assert_eq!(handler.decrypt(&encrypted3, path).unwrap(), data3.to_vec());
        
        // All ciphertexts should be different (different nonces used)
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted2, encrypted3);
        assert_ne!(encrypted1, encrypted3);
    }

    #[test]
    fn test_legacy_mode_nonce_reuse_warning() {
        let config = EncryptionConfig::with_random_keys();
        let handler = EncryptionHandler::new(&config);
        
        assert!(!handler.uses_counter_nonces());
        
        let path = "/test/file.txt";
        
        // In legacy mode, same path produces same nonce
        let nonce1 = handler.generate_nonce(path).unwrap();
        let nonce2 = handler.generate_nonce(path).unwrap();
        assert_eq!(nonce1, nonce2);
        
        // This demonstrates the VULNERABILITY: modifying a file
        // would reuse the same nonce
    }

    #[test]
    fn test_encryption_decryption_with_nonce_manager() {
        use tempfile::tempdir;
        use std::sync::Arc;
        
        let temp_dir = tempdir().unwrap();
        let config = EncryptionConfig::with_random_keys();
        let manager = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
        
        // Create separate handler instances to simulate real-world usage
        let handler1 = EncryptionHandler::with_nonce_manager(&config, manager.clone());
        let handler2 = EncryptionHandler::with_nonce_manager(&config, manager);
        
        let test_data = b"Sensitive medical data requiring nonce uniqueness!";
        let path = "/medical/patient_123.txt";
        
        // Encrypt with one handler, decrypt with another (same underlying manager)
        let encrypted = handler1.encrypt(test_data, path).unwrap();
        let decrypted = handler2.decrypt(&encrypted, path).unwrap();
        
        assert_eq!(test_data, decrypted.as_slice());
    }
}
