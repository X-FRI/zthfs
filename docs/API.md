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

// Create encryption handler with secure random keys
let config = EncryptionConfig::with_random_keys();
let encryptor = EncryptionHandler::new(&config);

// Create encryption handler with specific keys
let key = EncryptionConfig::generate_key();
let nonce_seed = EncryptionConfig::generate_nonce_seed();
let config = EncryptionConfig::new(key.to_vec(), nonce_seed.to_vec());
let encryptor = EncryptionHandler::new(&config);

// Encrypt data with BLAKE3 nonce generation
let data = b"sensitive medical data";
let path = "/patient/record.txt";
let encrypted = encryptor.encrypt(data, path).unwrap();

// Decrypt data
let decrypted = encryptor.decrypt(&encrypted, path).unwrap();
assert_eq!(data.to_vec(), decrypted);

// WARNING: Default config contains insecure placeholder values
// let insecure_config = EncryptionConfig::default(); // NOT FOR PRODUCTION!
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

### Asynchronous Logging Management

```rust
use zthfs::core::logging::{LogHandler, PerformanceLogParams};
use zthfs::config::LogConfig;

// Create asynchronous log handler with channel-based architecture
let config = LogConfig {
    enabled: true,
    file_path: "/var/log/zthfs/access.log".to_string(),
    level: "info".to_string(),
    max_size: 100 * 1024 * 1024, // 100MB
    rotation_count: 5,
};
let logger = LogHandler::new(&config).unwrap();

// Log access events (async, non-blocking)
logger.log_access("read", "/patient/record.txt", 1000, 1000, "success", None).unwrap();

// Log error events (async, non-blocking)
logger.log_error("write", "/file.txt", 1000, 1000, "permission denied", None).unwrap();

// Log performance metrics with structured data
logger.log_performance(PerformanceLogParams {
    operation: "encrypt".to_string(),
    path: "/large_medical_scan.dcm".to_string(),
    uid: 1000,
    gid: 1000,
    duration_ms: 150,
    file_size: Some(1024 * 1024), // 1MB
    checksum: Some("abc123...".to_string()),
}).unwrap();

// Force flush all pending logs (blocking operation)
logger.flush_logs().unwrap();

// Shutdown logger and wait for completion
logger.flush_all().unwrap(); // Also shuts down the async worker
```

### Filesystem Operations (with Partial Write Support)

```rust
use zthfs::fs_impl::{Zthfs, FileSystemOperations};
use zthfs::fs_impl::security::FileAccess;
use zthfs::config::FilesystemConfigBuilder;

// Create filesystem instance with security features
let config = FilesystemConfigBuilder::new()
    .data_dir("/tmp/zthfs_data".to_string())
    .mount_point("/tmp/zthfs_mount".to_string())
    .encryption(zthfs::config::EncryptionConfig::with_random_keys())
    .build()
    .unwrap();

let fs = Zthfs::new(&config).unwrap();

// Full file operations
let data = b"Hello, World!";
FileSystemOperations::write_file(&fs, std::path::Path::new("/test.txt"), data).unwrap();
let read_data = FileSystemOperations::read_file(&fs, std::path::Path::new("/test.txt")).unwrap();

// Partial write operations (POSIX-compliant)
let additional_data = b" Universe!";
let bytes_written = FileSystemOperations::write_partial(
    &fs,
    std::path::Path::new("/test.txt"),
    5, // Offset: after "Hello"
    additional_data
).unwrap();
assert_eq!(bytes_written, additional_data.len() as u32);

// Result: "Hello Universe!" (original "Hello, World!" partially overwritten)

// Check file access permissions
let can_read = fs.check_file_access(1000, 1000, FileAccess::Read, Some(0o644));
let can_write = fs.check_file_access(1000, 1000, FileAccess::Write, Some(0o644));

// File metadata operations
let exists = FileSystemOperations::path_exists(&fs, std::path::Path::new("/test.txt"));
let size = FileSystemOperations::get_file_size(&fs, std::path::Path::new("/test.txt")).unwrap();

// Clean up
FileSystemOperations::remove_file(&fs, std::path::Path::new("/test.txt")).unwrap();
```

### Security Features (POSIX Permissions & Access Control)

```rust
use zthfs::fs_impl::security::{SecurityValidator, SecurityEvent, SecurityLevel, FileAccess};
use zthfs::config::SecurityConfig;

// Create security validator with fine-grained access control
let config = SecurityConfig {
    allowed_users: vec![1000, 0],
    allowed_groups: vec![1000, 0],
    encryption_strength: "high".to_string(),
    access_control_level: "strict".to_string(),
};
let validator = SecurityValidator::new(config);

// Validate POSIX-style file permissions
// Parameters: user_uid, user_gid, file_uid, file_gid, file_mode, access_type
let can_read = validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Read);
let can_write = validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Write);
let can_execute = validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Execute);
assert!(can_read && can_write && !can_execute); // rw-r--r-- permissions

// User in file's group gets group permissions
let group_can_read = validator.check_file_permission(1001, 1000, 1000, 1000, 0o640, FileAccess::Read);
assert!(group_can_read); // User 1001 in group 1000 can read file with 0o640 permissions

// Other users get other permissions only
let other_can_write = validator.check_file_permission(2000, 2000, 1000, 1000, 0o646, FileAccess::Write);
assert!(other_can_write); // User 2000 can write file with 0o646 permissions (--w------ for others)

// Root user has full access regardless of file ownership/permissions
let root_can_execute = validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Execute);
assert!(root_can_execute); // Root always has access

// Record security events with severity levels
validator.record_security_event(
    SecurityEvent::AuthenticationFailure {
        user: 1000,
        reason: "Invalid password".to_string(),
    },
    SecurityLevel::Medium,
).unwrap();

// Check if user is locked due to failed attempts
let is_locked = validator.is_user_locked(1000);
if is_locked {
    println!("User is locked due to too many failed attempts");
}

// Validate secure paths (prevent path traversal and suspicious files)
validator.validate_secure_path("/safe/path/file.txt").unwrap();
validator.validate_secure_path("../unsafe/path").unwrap_err(); // Path traversal detected
validator.validate_secure_path("malware.exe").unwrap_err(); // Suspicious extension
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

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use zthfs::fs_impl::security::{SecurityValidator, FileAccess};

    #[test]
    fn test_blake3_nonce_security() {
        // Test BLAKE3 nonce generation security
        let config = EncryptionConfig::with_random_keys();
        let encryptor = EncryptionHandler::new(&config);

        let path1 = "/test/file1.txt";
        let path2 = "/test/file2.txt";

        let nonce1 = encryptor.generate_nonce(path1);
        let nonce2 = encryptor.generate_nonce(path2);

        // Different paths should produce different nonces
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 12); // GCM nonce size
    }

    #[test]
    fn test_posix_permissions() {
        let validator = SecurityValidator::new(SecurityConfig {
            allowed_users: vec![1000],
            allowed_groups: vec![1000],
            ..Default::default()
        });

        // Test rw-r--r-- permissions (0o644) - user 1000 owns the file
        assert!(validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Read));
        assert!(validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Write));
        assert!(!validator.check_file_permission(1000, 1000, 1000, 1000, 0o644, FileAccess::Execute));

        // Test group permissions - user 1001 in group 1000
        assert!(validator.check_file_permission(1001, 1000, 1000, 1000, 0o640, FileAccess::Read));
        assert!(!validator.check_file_permission(1001, 1000, 1000, 1000, 0o640, FileAccess::Write)); // No group write permission

        // Root always has access regardless of file ownership
        assert!(validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Execute));
    }

    #[test]
    fn test_config_validation() {
        // Invalid algorithm should fail
        let invalid_config = IntegrityConfig {
            enabled: true,
            algorithm: "invalid".to_string(),
            xattr_namespace: "user.zthfs".to_string(),
        };
        assert!(IntegrityHandler::validate_config(&invalid_config).is_err());

        // Valid config should pass
        let valid_config = IntegrityConfig::default();
        assert!(IntegrityHandler::validate_config(&valid_config).is_ok());
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_end_to_end_encryption_workflow() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");

        std::fs::create_dir_all(&data_dir).unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(data_dir.to_string_lossy().to_string())
            .mount_point("/tmp/test_mount".to_string())
            .encryption(EncryptionConfig::with_random_keys())
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();

        // Test full file operations
        let medical_data = b"Patient: John Doe\nDiagnosis: Hypertension";
        let path = std::path::Path::new("/medical_record.txt");

        FileSystemOperations::write_file(&fs, path, medical_data).unwrap();
        let read_data = FileSystemOperations::read_file(&fs, path).unwrap();
        assert_eq!(read_data, medical_data);

        // Test partial write operations
        let update = b" - Controlled";
        let bytes = FileSystemOperations::write_partial(&fs, path, 25, update).unwrap();
        assert_eq!(bytes, update.len() as u32);

        let final_data = FileSystemOperations::read_file(&fs, path).unwrap();
        assert!(final_data.ends_with(b" - Controlled"));

        // Clean up
        FileSystemOperations::remove_file(&fs, path).unwrap();
    }

    #[test]
    fn test_async_logging_performance() {
        let temp_dir = tempdir().unwrap();
        let log_file = temp_dir.path().join("test.log");

        let config = LogConfig {
            enabled: true,
            file_path: log_file.to_string_lossy().to_string(),
            level: "info".to_string(),
            max_size: 1024 * 1024,
            rotation_count: 3,
        };

        let logger = LogHandler::new(&config).unwrap();

        // Test async logging (non-blocking)
        for i in 0..10 {
            logger.log_access(
                "read",
                &format!("/test/file_{}.txt", i),
                1000, 1000, "success", None
            ).unwrap();
        }

        // Flush and shutdown
        logger.flush_all().unwrap();
    }
}
```

## Performance Benchmarks

Run comprehensive performance benchmarks:

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark suites
cargo bench --bench crypto_benchmarks    # Encryption performance
cargo bench --bench logging_benchmarks   # Async logging performance
cargo bench --bench filesystem_benchmarks # File operations
cargo bench --bench integrity_benchmarks  # Integrity verification

# Run with detailed output
cargo bench --bench crypto_benchmarks -- --verbose
```

### Benchmark Configuration

```rust
use criterion::{Criterion, criterion_group, criterion_main};
use zthfs::{config::*, core::*, fs_impl::*};

// Example: Comprehensive encryption benchmark
fn bench_blake3_encryption(c: &mut Criterion) {
    let config = EncryptionConfig::with_random_keys(); // Secure keys
    let encryptor = EncryptionHandler::new(&config);

    let data_1kb = vec![0u8; 1024];
    let data_1mb = vec![0u8; 1024 * 1024];
    let path = "/benchmark/test.dat";

    let mut group = c.benchmark_group("encryption_blake3");

    group.bench_function("1KB_encrypt", |b| {
        b.iter(|| encryptor.encrypt(std::hint::black_box(&data_1kb), std::hint::black_box(path)))
    });

    group.bench_function("1MB_encrypt", |b| {
        b.iter(|| encryptor.encrypt(std::hint::black_box(&data_1mb), std::hint::black_box(path)))
    });

    group.bench_function("nonce_generation", |b| {
        b.iter(|| encryptor.generate_nonce(std::hint::black_box(path)))
    });

    group.finish();
}

// Example: Async logging benchmark
fn bench_async_logging(c: &mut Criterion) {
    let temp_dir = std::env::temp_dir();
    let config = LogConfig {
        enabled: true,
        file_path: temp_dir.join("bench.log").to_string_lossy().to_string(),
        level: "info".to_string(),
        max_size: 100 * 1024 * 1024,
        rotation_count: 5,
    };

    let logger = LogHandler::new(&config).unwrap();

    c.bench_function("async_log_single", |b| {
        b.iter(|| {
            logger.log_access(
                std::hint::black_box("read"),
                std::hint::black_box("/bench/file.txt"),
                1000, 1000, std::hint::black_box("success"), None
            )
        })
    });

    // Cleanup
    let _ = logger.flush_all();
}

criterion_group!(benches, bench_blake3_encryption, bench_async_logging);
criterion_main!(benches);
```

### Benchmark Results Summary

- **Encryption**: BLAKE3 nonce generation provides cryptographic security with acceptable performance overhead
- **Async Logging**: Channel-based architecture eliminates lock contention in concurrent scenarios
- **File Operations**: Partial write support adds POSIX compliance with reasonable performance cost
- **Security Checks**: Fine-grained permission validation ensures enterprise-grade access control

See README.md for detailed benchmark results and performance analysis.
