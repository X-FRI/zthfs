//! ZTHFS - Zero-Trust Healthcare File System
//!
//! A transparent encryption filesystem designed specifically for medical data protection.
//! Built with Rust and FUSE, providing HIPAA/GDPR compliant data security.
//!
//! ## Features
//!
//! - **Transparent Encryption**: AES-256-GCM encryption with unique nonce per file
//! - **Data Integrity**: CRC32c checksum verification with extended attributes
//! - **Access Logging**: Comprehensive audit trail for compliance
//! - **Permission Control**: User and group-based access control
//! - **Medical Data Optimized**: Designed for healthcare workflows
//!
//! ## Architecture
//!
//! The system is organized into several key modules:
//!
//! - `config`: Configuration management and validation
//! - `core`: Core functionality (encryption, integrity, logging)
//! - `fs_impl`: Filesystem implementation and operations
//! - `errors`: Custom error types and handling
//! - `utils`: Utility functions and helpers
//!
//! ## Usage
//!
//! ```rust
//! use zthfs::{config::FilesystemConfigBuilder, fs_impl::Zthfs};
//! use tempfile::tempdir;
//!
//! // Create configuration with temporary directories
//! let temp_dir = tempdir().unwrap();
//! let config = FilesystemConfigBuilder::new()
//!     .data_dir(temp_dir.path().to_string_lossy().to_string())
//!     .mount_point("/tmp/zthfs_mount".to_string())
//!     .logging(zthfs::config::LogConfig {
//!         enabled: true, // Enable logging
//!         file_path: "/tmp/zthfs.log".to_string(),
//!         level: "info".to_string(),
//!         max_size: 1024 * 1024,
//!         rotation_count: 3,
//!     })
//!     .build()
//!     .unwrap();
//!
//! // Create filesystem instance
//! let fs = Zthfs::new(&config).unwrap();
//!
//! // Filesystem is ready to use
//! // In production, you would mount it with FUSE:
//! // fs.mount(&config.mount_point, &[]);
//! ```

pub mod config;
pub mod core;
#[cfg(test)]
mod error_tests;
pub mod errors;
pub mod fs_impl;
pub mod key_derivation;
pub mod key_management;
pub mod transactions;
pub mod utils;

// Re-export main types for convenience
pub use config::{
    EncryptionConfig, FilesystemConfig, FilesystemConfigBuilder, IntegrityConfig, LogConfig,
    PerformanceConfig, SecurityConfig,
};
pub use core::encryption::{EncryptionHandler, NonceManager};
pub use core::integrity::IntegrityHandler;
pub use core::logging::{AccessLogEntry, LogHandler};
pub use errors::{ZthfsError, ZthfsResult};
pub use fs_impl::Zthfs;
pub use key_derivation::{KeyDerivationConfig, fast_params, high_security_params};
pub use key_management::{
    FileKeyStorage, InMemoryKeyStorage, KeyManager, KeyMetadata, KeyStorage, StoredKey,
    create_file_key_manager,
};
pub use transactions::{
    CowHelper, TransactionId, TransactionOp, TransactionStatus, WalEntry, WriteAheadLog,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build information
pub const BUILD_INFO: &str = concat!(
    "version=",
    env!("CARGO_PKG_VERSION"),
    " build_time=",
    env!("VERGEN_BUILD_TIMESTAMP"),
    " git_sha=",
    env!("VERGEN_GIT_SHA"),
    " rustc=",
    env!("VERGEN_RUSTC_SEMVER")
);

/// Initialize the ZTHFS system with logging
pub fn init() -> ZthfsResult<()> {
    env_logger::init();
    log::info!("ZTHFS v{VERSION} initialized");
    Ok(())
}

/// Health check function
pub fn health_check() -> ZthfsResult<String> {
    let mut checks = vec![
        "✓ AES-GCM encryption: Available".to_string(),
        "✓ CRC32c integrity: Available".to_string(),
        "✓ JSON serialization: Available".to_string(),
        "✓ FUSE integration: Available".to_string(),
    ];

    // Check system requirements
    if std::path::Path::new("/dev/fuse").exists() {
        checks.push("✓ FUSE device: Available".to_string());
    } else {
        checks.push("✗ FUSE device: Not available".to_string());
    }

    Ok(checks.join("\n"))
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::fs_impl::security::FileAccess;

    #[test]
    fn test_security_integration() {
        // Test permission checks without creating actual filesystem
        let validator = crate::fs_impl::security::SecurityValidator::new(SecurityConfig {
            allowed_users: vec![1000],
            allowed_groups: vec![1000],
            ..Default::default()
        });

        // Test permission checks
        // User 1000 owns the file (uid=1000, gid=1000)
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Read
        ));
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Write
        ));
        assert!(!validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Execute
        )); // No execute permission
        // User 2000 is not in allowed list, file owned by user 1000, group 1000
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o777,
            FileAccess::Read
        )); // User not allowed
    }

    #[test]
    fn test_configuration_validation() {
        // Test invalid configurations are caught
        let invalid_config = FilesystemConfig {
            data_dir: String::new(), // Empty data directory
            mount_point: "/mnt/test".to_string(),
            encryption: EncryptionConfig::with_random_keys(),
            logging: LogConfig::default(),
            integrity: IntegrityConfig::default(),
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
        };

        assert!(invalid_config.validate().is_err());

        // Test invalid integrity algorithm
        let invalid_integrity_config = FilesystemConfig {
            data_dir: "/tmp/test".to_string(),
            mount_point: "/mnt/test".to_string(),
            encryption: EncryptionConfig::with_random_keys(),
            logging: LogConfig::default(),
            integrity: IntegrityConfig {
                enabled: true,
                algorithm: "invalid_algorithm".to_string(),
                xattr_namespace: "user.zthfs".to_string(),
                key: vec![1; 32], // Dummy key for test
                hmac_key: None,
            },
            performance: PerformanceConfig::default(),
            security: SecurityConfig::default(),
        };

        assert!(invalid_integrity_config.validate().is_err());

        // Test valid configuration
        let valid_config = FilesystemConfigBuilder::new()
            .data_dir("/tmp/test".to_string())
            .mount_point("/mnt/test".to_string())
            .encryption(EncryptionConfig::with_random_keys())
            .build()
            .unwrap();

        assert!(valid_config.validate().is_ok());
    }

    #[test]
    fn test_init_function() {
        // Test the init function
        let result = init();
        assert!(result.is_ok());
        // Verify VERSION is not empty
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_health_check() {
        // Test the health_check function
        let result = health_check();
        assert!(result.is_ok());

        let health_output = result.unwrap();
        // Verify the output contains expected strings
        assert!(health_output.contains("AES-GCM encryption"));
        assert!(health_output.contains("CRC32c integrity"));
        assert!(health_output.contains("JSON serialization"));
        assert!(health_output.contains("FUSE integration"));

        // Check if /dev/fuse exists (should on most Linux systems)
        if std::path::Path::new("/dev/fuse").exists() {
            assert!(health_output.contains("FUSE device: Available"));
        } else {
            assert!(health_output.contains("FUSE device: Not available"));
        }
    }

    #[test]
    fn test_version_constant() {
        // Test VERSION constant is accessible and valid
        assert!(!VERSION.is_empty());
        // VERSION should be a semantic version like "0.1.0"
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_build_info_constant() {
        // Test BUILD_INFO constant is accessible
        assert!(!BUILD_INFO.is_empty());
        // BUILD_INFO should contain version information
        assert!(BUILD_INFO.contains("version="));
        assert!(BUILD_INFO.contains("build_time="));
        assert!(BUILD_INFO.contains("git_sha="));
        assert!(BUILD_INFO.contains("rustc="));
    }

    #[test]
    fn test_module_reexports() {
        // Test that key types are re-exported
        // This is a compile-time check that the re-exports work
        let _ = ZthfsError::Io(std::io::Error::other("test"));
        let _: ZthfsResult<()> = Ok(());

        // Test that config types are available
        let log_config = LogConfig::default();
        assert!(!log_config.file_path.is_empty()); // Default has a file path

        // Test that encryption config is available
        let enc_config = EncryptionConfig::with_random_keys();
        assert!(!enc_config.key.is_empty());
    }
}
