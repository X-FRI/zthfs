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

impl Default for EncryptionConfig {
    fn default() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        let mut nonce_seed = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce_seed);
        Self { key, nonce_seed }
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
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: "crc32c".to_string(),
            xattr_namespace: "user.zthfs".to_string(),
        }
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
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            cache_size: 1000,
            max_concurrent_ops: 100,
            block_size: 4096,
            prefetch_size: 8192,
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
        let mut config = FilesystemConfig::default();

        // Empty data directory should fail
        config.data_dir = String::new();
        assert!(config.validate().is_err());

        // Restore default values
        config.data_dir = "/tmp/test".to_string();
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
}
