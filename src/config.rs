use crate::errors::{ZthfsError, ZthfsResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// AES-256 key (32 bytes)
    pub key: Vec<u8>,
    /// Nonce seed for generating nonce
    pub nonce_seed: Vec<u8>,
}

impl EncryptionConfig {
    /// Create a new EncryptionConfig with the specified key and nonce seed
    pub fn new(key: Vec<u8>, nonce_seed: Vec<u8>) -> Self {
        Self { key, nonce_seed }
    }

    /// Create a new EncryptionConfig with randomly generated key and nonce seed
    /// WARNING: This should only be used for testing or development.
    /// In production, always use persistent keys.
    pub fn with_random_keys() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        let mut nonce_seed = vec![0u8; 12];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut nonce_seed);
        Self { key, nonce_seed }
    }

    /// Generate a random encryption key
    pub fn generate_key() -> [u8; 32] {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce seed
    pub fn generate_nonce_seed() -> [u8; 12] {
        use rand::RngCore;
        let mut seed = [0u8; 12];
        rand::rng().fill_bytes(&mut seed);
        seed
    }

    /// Validate that this configuration is safe for production use.
    ///
    /// This checks for known insecure patterns in keys that should never be used
    /// in production, such as the default placeholder values.
    ///
    /// # Errors
    /// Returns `ZthfsError::Config` if the configuration is unsafe for production.
    pub fn validate_for_production(&self) -> ZthfsResult<()> {
        // Check for the default DEADBEEF pattern in key
        let deadbeef_pattern = [0xDE, 0xAD, 0xBE, 0xEF].repeat(8);
        if self.key == deadbeef_pattern {
            return Err(ZthfsError::Config(
                "Encryption key contains insecure default pattern (DEADBEEF). \
                 This key must NOT be used in production. \
                 Generate a secure key using EncryptionConfig::generate_key() \
                 or EncryptionConfig::with_random_keys()."
                    .to_string(),
            ));
        }

        // Check for the default BADCOFFE pattern in nonce seed
        let badcoffe_pattern = [0xBA, 0xDC, 0x0F, 0xFE].repeat(3);
        if self.nonce_seed == badcoffe_pattern {
            return Err(ZthfsError::Config(
                "Nonce seed contains insecure default pattern (BADCOFFE). \
                 This value must NOT be used in production. \
                 Generate a secure seed using EncryptionConfig::generate_nonce_seed() \
                 or EncryptionConfig::with_random_keys()."
                    .to_string(),
            ));
        }

        // Check for all-zero key
        if self.key.iter().all(|&b| b == 0) {
            return Err(ZthfsError::Config(
                "Encryption key is all zeros. This is insecure and must NOT be used in production."
                    .to_string(),
            ));
        }

        // Check for all-ones key
        if self.key.iter().all(|&b| b == 0xFF) {
            return Err(ZthfsError::Config(
                "Encryption key is all 0xFF. This is insecure and must NOT be used in production."
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Check if this configuration uses the insecure default values.
    pub fn is_insecure_default(&self) -> bool {
        let deadbeef_pattern = [0xDE, 0xAD, 0xBE, 0xEF].repeat(8);
        let badcoffe_pattern = [0xBA, 0xDC, 0x0F, 0xFE].repeat(3);
        self.key == deadbeef_pattern && self.nonce_seed == badcoffe_pattern
    }
}

impl Default for EncryptionConfig {
    /// Default configuration with placeholder values.
    ///
    /// # WARNING
    /// This default configuration contains **insecure placeholder values** and
    /// should **NEVER** be used in production. Always provide explicit keys.
    ///
    /// The default values use repeating patterns (DEADBEEF/BADCOFFE) that are
    /// trivially detectable and provide no real security. Call
    /// `validate_for_production()` to detect accidental use of these defaults.
    fn default() -> Self {
        // Use clearly insecure placeholder values to prevent accidental use
        // These are obviously not random and will be easily detectable
        let key = [0xDE, 0xAD, 0xBE, 0xEF].repeat(8); // Repeating pattern: DEADBEEF...
        let nonce_seed = [0xBA, 0xDC, 0x0F, 0xFE].repeat(3); // Repeating pattern: BADCOFFE...

        Self {
            key: key.to_vec(),
            nonce_seed: nonce_seed.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogConfig {
    pub enabled: bool,
    pub file_path: String,
    pub level: String,
    /// Maximum log file size (bytes)
    pub max_size: u64,
    /// Log rotation count
    pub rotation_count: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file_path: "/var/log/zthfs/access.log".to_string(),
            level: "info".to_string(),
            max_size: 10 * 1024 * 1024, // 10MB
            rotation_count: 5,
        }
    }
}

/// Integrity verification configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrityConfig {
    /// Whether to enable integrity verification
    pub enabled: bool,
    /// Verification algorithm
    pub algorithm: String,
    /// Extended attribute namespace
    pub xattr_namespace: String,
    /// Secret key for cryptographic integrity verification (32 bytes for BLAKE3)
    pub key: Vec<u8>,
}

impl IntegrityConfig {
    /// Create a new IntegrityConfig with a secure random key
    pub fn new() -> Self {
        Self {
            enabled: true,
            algorithm: "blake3".to_string(),
            xattr_namespace: "user.zthfs".to_string(),
            key: EncryptionConfig::generate_key().to_vec(),
        }
    }

    /// Create a new IntegrityConfig with a specific key
    pub fn with_key(key: Vec<u8>) -> Self {
        Self {
            enabled: true,
            algorithm: "blake3".to_string(),
            xattr_namespace: "user.zthfs".to_string(),
            key,
        }
    }
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Cache size
    pub cache_size: usize,
    /// Concurrent limit
    pub max_concurrent_ops: usize,
    /// Block size
    pub block_size: u32,
    /// Prefetch size
    pub prefetch_size: usize,
    /// Chunk size for file chunking (bytes, 0 to disable)
    pub chunk_size: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            cache_size: 1000,
            max_concurrent_ops: 100,
            block_size: 4096,
            prefetch_size: 8192,
            chunk_size: 4 * 1024 * 1024, // 4MB default chunk size
        }
    }
}

/// Security configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Allowed user ID list
    pub allowed_users: Vec<u32>,
    /// Allowed group ID list
    pub allowed_groups: Vec<u32>,
    /// Encryption strength
    pub encryption_strength: String,
    /// Access control level
    pub access_control_level: String,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_users: vec![0],  // root user
            allowed_groups: vec![0], // root group
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        }
    }
}

/// Filesystem configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilesystemConfig {
    /// Data directory
    pub data_dir: String,
    /// Mount point
    pub mount_point: String,
    /// Encryption configuration
    pub encryption: EncryptionConfig,
    /// Logging configuration
    pub logging: LogConfig,
    /// Integrity configuration
    pub integrity: IntegrityConfig,
    /// Performance configuration
    pub performance: PerformanceConfig,
    /// Security configuration
    pub security: SecurityConfig,
}

impl FilesystemConfig {
    /// Load configuration from file
    pub fn from_file<P: AsRef<Path>>(path: P) -> ZthfsResult<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ZthfsError::Config(format!("Failed to read config file: {e}")))?;

        serde_json::from_str(&contents)
            .map_err(|e| ZthfsError::Config(format!("Failed to parse config: {e}")))
    }

    /// Save configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> ZthfsResult<()> {
        let path = path.as_ref();
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| ZthfsError::Config(format!("Failed to serialize config: {e}")))?;

        std::fs::write(path, contents)
            .map_err(|e| ZthfsError::Config(format!("Failed to write config file: {e}")))
    }

    /// Validate configuration
    pub fn validate(&self) -> ZthfsResult<()> {
        // Validate data directory
        if self.data_dir.is_empty() {
            return Err(ZthfsError::Config(
                "Data directory cannot be empty".to_string(),
            ));
        }

        // Validate mount point
        if self.mount_point.is_empty() {
            return Err(ZthfsError::Config(
                "Mount point cannot be empty".to_string(),
            ));
        }

        // Validate encryption key length
        if self.encryption.key.len() != 32 {
            return Err(ZthfsError::Config(
                "Encryption key must be 32 bytes".to_string(),
            ));
        }

        // Validate nonce seed length
        if self.encryption.nonce_seed.len() != 12 {
            return Err(ZthfsError::Config(
                "Nonce seed must be 12 bytes".to_string(),
            ));
        }

        // Validate logging configuration
        if self.logging.enabled && self.logging.file_path.is_empty() {
            return Err(ZthfsError::Config(
                "Log file path cannot be empty when logging is enabled".to_string(),
            ));
        }

        // Validate integrity configuration
        use crate::core::integrity::IntegrityHandler;
        IntegrityHandler::validate_config(&self.integrity)?;

        // Validate integrity key length for cryptographic algorithms
        if self.integrity.enabled
            && self.integrity.algorithm.to_lowercase() == "blake3"
            && self.integrity.key.len() != 32
        {
            return Err(ZthfsError::Config(
                "Integrity key must be 32 bytes for BLAKE3".to_string(),
            ));
        }

        // Production mode: validate encryption keys are not using default values
        #[cfg(feature = "production")]
        self.encryption.validate_for_production()?;

        Ok(())
    }

    /// Validate configuration with optional production checks.
    ///
    /// This is a runtime version of production validation that can be called
    /// even when the production feature flag is not enabled at compile time.
    /// It's useful for the `validate` CLI command.
    pub fn validate_with_production_checks(&self) -> ZthfsResult<()> {
        self.validate()?;
        self.encryption.validate_for_production()?;
        Ok(())
    }
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            data_dir: "/var/lib/zthfs/data".to_string(),
            mount_point: "/mnt/zthfs".to_string(),
            encryption: EncryptionConfig::default(),
            logging: LogConfig::default(),
            integrity: IntegrityConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

/// Configuration builder
#[derive(Default)]
pub struct FilesystemConfigBuilder {
    config: FilesystemConfig,
}

impl FilesystemConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data_dir(mut self, dir: String) -> Self {
        self.config.data_dir = dir;
        self
    }

    pub fn mount_point(mut self, mount: String) -> Self {
        self.config.mount_point = mount;
        self
    }

    pub fn encryption(mut self, encryption: EncryptionConfig) -> Self {
        self.config.encryption = encryption;
        self
    }

    pub fn logging(mut self, logging: LogConfig) -> Self {
        self.config.logging = logging;
        self
    }

    pub fn integrity(mut self, integrity: IntegrityConfig) -> Self {
        self.config.integrity = integrity;
        self
    }

    pub fn performance(mut self, performance: PerformanceConfig) -> Self {
        self.config.performance = performance;
        self
    }

    pub fn security(mut self, security: SecurityConfig) -> Self {
        self.config.security = security;
        self
    }

    pub fn build(self) -> ZthfsResult<FilesystemConfig> {
        let config = self.config;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = FilesystemConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        // Empty data directory should fail
        let config = FilesystemConfig {
            data_dir: String::new(),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Restore default values
        let config = FilesystemConfig {
            data_dir: "/tmp/test".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = FilesystemConfigBuilder::new()
            .data_dir("/tmp/test".to_string())
            .mount_point("/mnt/test".to_string())
            .build()
            .unwrap();

        assert_eq!(config.data_dir, "/tmp/test");
        assert_eq!(config.mount_point, "/mnt/test");
    }

    #[test]
    fn test_config_file_operations() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");

        let config = FilesystemConfig::default();
        config.save_to_file(&config_path).unwrap();

        let loaded_config = FilesystemConfig::from_file(&config_path).unwrap();
        assert_eq!(config.data_dir, loaded_config.data_dir);
    }

    #[test]
    fn test_validate_for_production_with_defaults() {
        // Default config should fail production validation
        let config = EncryptionConfig::default();
        assert!(config.validate_for_production().is_err());
        assert!(config.is_insecure_default());

        let err = config.validate_for_production().unwrap_err();
        assert!(err.to_string().contains("DEADBEEF"));
    }

    #[test]
    fn test_validate_for_production_with_zeros() {
        // All-zero key should fail
        let config = EncryptionConfig {
            key: vec![0u8; 32],
            nonce_seed: vec![1u8; 12],
        };
        assert!(config.validate_for_production().is_err());
        let err = config.validate_for_production().unwrap_err();
        assert!(err.to_string().contains("all zeros"));
    }

    #[test]
    fn test_validate_for_production_with_ones() {
        // All-ones key should fail
        let config = EncryptionConfig {
            key: vec![0xFFu8; 32],
            nonce_seed: vec![1u8; 12],
        };
        assert!(config.validate_for_production().is_err());
        let err = config.validate_for_production().unwrap_err();
        assert!(err.to_string().contains("0xFF"));
    }

    #[test]
    fn test_validate_for_production_with_random_keys() {
        // Random keys should pass
        let config = EncryptionConfig::with_random_keys();
        assert!(!config.is_insecure_default());
        assert!(config.validate_for_production().is_ok());
    }

    #[test]
    fn test_validate_for_production_with_explicit_keys() {
        // Explicit secure keys should pass
        let config = EncryptionConfig {
            key: EncryptionConfig::generate_key().to_vec(),
            nonce_seed: EncryptionConfig::generate_nonce_seed().to_vec(),
        };
        assert!(!config.is_insecure_default());
        assert!(config.validate_for_production().is_ok());
    }
}
