# ZTHFS API Documentation

## Introduction

ZTHFS provides a complete Rust API for building and operating transparent encrypted filesystems. This documentation describes the main API interfaces and usage methods.

## Core Modules

### Configuration Management

```rust
use zthfs::config::{FilesystemConfig, FilesystemConfigBuilder, EncryptionConfig};

// Create default configuration
let config = FilesystemConfig::default();

// Create configuration using builder pattern
let config = FilesystemConfigBuilder::new()
    .data_dir("/var/lib/zthfs/data".to_string())
    .mount_point("/mnt/zthfs".to_string())
    .build()
    .unwrap();

// Load configuration from file
let config = FilesystemConfig::from_file("/etc/zthfs/config.json").unwrap();

// Save configuration to file
config.save_to_file("/etc/zthfs/config.json").unwrap();
```

### Encryption Operations

```rust
use zthfs::core::encryption::EncryptionHandler;
use zthfs::config::EncryptionConfig;

// Create encryption handler
let config = EncryptionConfig::default();
let encryptor = EncryptionHandler::new(&config);

// Encrypt data
let data = b"sensitive medical data";
let path = "/patient/record.txt";
let encrypted = encryptor.encrypt(data, path).unwrap();

// Decrypt data
let decrypted = encryptor.decrypt(&encrypted, path).unwrap();
assert_eq!(data.to_vec(), decrypted);

// Generate random keys
let key = EncryptionHandler::generate_key(); // 32 bytes
let nonce_seed = EncryptionHandler::generate_nonce_seed(); // 12 bytes
```

### Integrity Verification

```rust
use zthfs::core::integrity::IntegrityHandler;
use zthfs::config::IntegrityConfig;

// Compute checksum
let data = b"medical data";
let checksum = IntegrityHandler::compute_checksum(data);

// Verify integrity
let is_valid = IntegrityHandler::verify_integrity(data, checksum);
assert!(is_valid);

// Store checksum using extended attributes
let path = std::path::Path::new("/file.txt");
let config = IntegrityConfig::default();

IntegrityHandler::set_checksum_xattr(path, checksum, &config).unwrap();
let stored_checksum = IntegrityHandler::get_checksum_from_xattr(path, &config).unwrap();
assert_eq!(Some(checksum), stored_checksum);
```

### Logging Management

```rust
use zthfs::core::logging::LogHandler;
use zthfs::config::LogConfig;

// Create log handler
let config = LogConfig::default();
let logger = LogHandler::new(&config).unwrap();

// Log access events
logger.log_access("read", "/file.txt", 1000, 1000, "success", None).unwrap();

// Log error events
logger.log_error("write", "/file.txt", 1000, 1000, "permission denied", None).unwrap();

// Log performance metrics
logger.log_performance(zthfs::core::logging::PerformanceLogParams {
    operation: "encrypt".to_string(),
    path: "/file.txt".to_string(),
    uid: 1000,
    gid: 1000,
    duration_ms: 150,
    file_size: Some(1024),
    checksum: Some("abc123".to_string()),
}).unwrap();

// Flush all logs
logger.flush_all().unwrap();
```

### Filesystem Operations

```rust
use zthfs::fs_impl::{Zthfs, FileSystemOperations};
use zthfs::config::FilesystemConfigBuilder;

// Create filesystem instance
let config = FilesystemConfigBuilder::new()
    .data_dir("/tmp/zthfs_data".to_string())
    .mount_point("/tmp/zthfs_mount".to_string())
    .build()
    .unwrap();

let fs = Zthfs::new(&config).unwrap();

// Read file
let data = FileSystemOperations::read_file(&fs, std::path::Path::new("/test.txt")).unwrap();

// Write file
let data = b"Hello, World!";
FileSystemOperations::write_file(&fs, std::path::Path::new("/test.txt"), data).unwrap();

// Check if file exists
let exists = FileSystemOperations::path_exists(&fs, std::path::Path::new("/test.txt"));

// Get file size
let size = FileSystemOperations::get_file_size(&fs, std::path::Path::new("/test.txt")).unwrap();

// Remove file
FileSystemOperations::remove_file(&fs, std::path::Path::new("/test.txt")).unwrap();
```

### Security Features

```rust
use zthfs::fs_impl::security::{SecurityValidator, SecurityEvent, SecurityLevel};
use zthfs::config::SecurityConfig;

// Create security validator
let config = SecurityConfig::default();
let validator = SecurityValidator::new(config);

// Validate user access permissions
let has_access = validator.validate_user_access(1000, 1000);
assert!(has_access);

// Record security events
validator.record_security_event(
    SecurityEvent::AuthenticationFailure {
        user: 1000,
        reason: "Invalid password".to_string(),
    },
    SecurityLevel::Medium,
).unwrap();

// Check if user is locked
let is_locked = validator.is_user_locked(1000);
if is_locked {
    println!("User is locked due to too many failed attempts");
}

// Validate secure paths
validator.validate_secure_path("/safe/path").unwrap();
validator.validate_secure_path("../unsafe/path").unwrap(); // Will fail
```

### Utility Functions

```rust
use zthfs::utils::Utils;

// Validate path safety
let is_safe = Utils::is_safe_path(std::path::Path::new("/safe/file.txt"));
assert!(is_safe);

// Format file size
let size_str = Utils::format_file_size(1024 * 1024); // "1.00 MB"
assert_eq!(size_str, "1.00 MB");

// Generate random string
let random = Utils::generate_random_string(16);
assert_eq!(random.len(), 16);

// Encode/decode Base64
let data = b"Hello, World!";
let encoded = Utils::encode_base64(data);
let decoded = Utils::decode_base64(&encoded).unwrap();
assert_eq!(data.to_vec(), decoded);

// Validate email format
let is_valid = Utils::is_valid_email("user@example.com");
assert!(is_valid);
```

## Error Handling

```rust
use zthfs::errors::{ZthfsError, ZthfsResult};

// ZTHFS uses custom error types
fn example_function() -> ZthfsResult<()> {
    // Operations may fail
    match some_operation() {
        Ok(result) => Ok(result),
        Err(e) => Err(ZthfsError::Fs(format!("Operation failed: {}", e))),
    }
}

// Error type conversions
impl From<std::io::Error> for ZthfsError {
    fn from(err: std::io::Error) -> Self {
        ZthfsError::Io(err)
    }
}

impl From<aes_gcm::Error> for ZthfsError {
    fn from(err: aes_gcm::Error) -> Self {
        ZthfsError::Crypto(err.to_string())
    }
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_roundtrip() {
        let config = EncryptionConfig::default();
        let encryptor = EncryptionHandler::new(&config);

        let data = b"test data";
        let path = "/test/file.txt";

        let encrypted = encryptor.encrypt(data, path).unwrap();
        let decrypted = encryptor.decrypt(&encrypted, path).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_filesystem_operations() {
        let temp_dir = tempdir().unwrap();
        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().to_string_lossy().to_string())
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();
        let test_data = b"Hello, World!";
        let path = std::path::Path::new("/test.txt");

        // Test write operation
        FileSystemOperations::write_file(&fs, path, test_data).unwrap();

        // Test read operation
        let read_data = FileSystemOperations::read_file(&fs, path).unwrap();
        assert_eq!(test_data.to_vec(), read_data);

        // Test delete operation
        FileSystemOperations::remove_file(&fs, path).unwrap();
        assert!(!FileSystemOperations::path_exists(&fs, path));
    }
}
```

## Performance Benchmarks

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_encrypt_1mb(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let data = vec![0u8; 1024 * 1024]; // 1MB
    let path = "/test/large_file.txt";

    c.bench_function("encrypt_1mb", |b| {
        b.iter(|| {
            let _ = encryptor.encrypt(black_box(&data), black_box(path));
        })
    });
}

criterion_group!(benches, bench_encrypt_1mb);
criterion_main!(benches);
```
