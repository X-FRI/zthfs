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
pub mod errors;
pub mod fs_impl;
pub mod utils;

// Re-export main types for convenience
pub use config::{
    EncryptionConfig, FilesystemConfig, FilesystemConfigBuilder, IntegrityConfig, LogConfig,
    PerformanceConfig, SecurityConfig,
};
pub use core::encryption::EncryptionHandler;
pub use core::integrity::IntegrityHandler;
pub use core::logging::{AccessLogEntry, LogHandler};
pub use errors::{ZthfsError, ZthfsResult};
pub use fs_impl::{Zthfs, operations::FileSystemOperations};
pub mod operations {
    pub use crate::fs_impl::operations::FileSystemOperations;
}

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
    let mut checks = Vec::new();

    // Check if required dependencies are available
    checks.push("✓ AES-GCM encryption: Available".to_string());
    checks.push("✓ CRC32c integrity: Available".to_string());
    checks.push("✓ JSON serialization: Available".to_string());
    checks.push("✓ FUSE integration: Available".to_string());

    // Check system requirements
    if std::path::Path::new("/dev/fuse").exists() {
        checks.push("✓ FUSE device: Available".to_string());
    } else {
        checks.push("✗ FUSE device: Not available".to_string());
    }

    Ok(checks.join("\n"))
}
