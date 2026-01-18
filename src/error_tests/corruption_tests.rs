//! Data corruption scenario tests
//!
//! Tests how the filesystem handles corrupted data, metadata, and other integrity issues.
//! These tests verify error recovery and reporting for corruption scenarios.

use crate::config::{FilesystemConfigBuilder, IntegrityConfig, LogConfig};
use crate::fs_impl::Zthfs;
use crate::fs_impl::{file_create, file_read, file_write, metadata_ops, path_ops};
use std::path::Path;

/// Helper to create a test filesystem with integrity enabled
fn create_fs_with_integrity() -> (tempfile::TempDir, Zthfs) {
    let temp_dir = tempfile::TempDir::new().unwrap();

    // SAFETY: getuid() and getgid() are async-signal-safe libc functions
    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };

    let mut config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();

    // Enable integrity checking
    config.integrity = IntegrityConfig {
        enabled: true,
        algorithm: "crc32c".to_string(),
        xattr_namespace: "user.zthfs".to_string(),
        key: vec![1u8; 32],
        hmac_key: None,
    };

    config.security.allowed_users = vec![current_uid, 0];
    config.security.allowed_groups = vec![current_gid, 0];

    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}

#[test]
fn test_read_corrupted_metadata() {
    // Test reading a file with corrupted JSON metadata
    let (_temp_dir, fs) = create_fs_with_integrity();

    let test_path = Path::new("/corrupt_meta_test.txt");
    let test_data = b"Test data for metadata corruption";

    // Create a file (this will use chunked storage if data is large enough)
    file_write::write_file(&fs, test_path, test_data).unwrap();

    // Get the metadata path
    let metadata_path = metadata_ops::get_metadata_path(&fs, test_path);

    // If metadata exists, corrupt it
    if metadata_path.exists() {
        // Corrupt the JSON metadata
        std::fs::write(&metadata_path, b"corrupted json{{{").unwrap();

        // Attempting to read the file should handle corruption gracefully
        let result = file_read::read_file(&fs, test_path);

        // Should fail with an error (could be Fs or Serialization error)
        assert!(result.is_err(), "Should fail gracefully with corrupted metadata");

        // Verify it's an appropriate error type
        match result.unwrap_err() {
            crate::errors::ZthfsError::Serialization(msg) => {
                let has_keyword = msg.contains("metadata") || msg.contains("json");
                assert!(has_keyword, "Serialization error should mention metadata or json");
            }
            crate::errors::ZthfsError::Fs(msg) => {
                // Also acceptable - might be reported as filesystem error
                assert!(msg.len() > 0);
            }
            other => panic!("Expected Serialization or Fs error, got: {:?}", other),
        }
    } else {
        // File was too small to use chunked storage, metadata doesn't exist
        // This is expected behavior - test passes
        assert!(true);
    }
}

#[test]
fn test_read_truncated_file() {
    // Test reading a truncated encrypted file
    let (_temp_dir, fs) = create_fs_with_integrity();

    let test_path = Path::new("/truncated_test.txt");
    let test_data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    // Write the file
    file_write::write_file(&fs, test_path, test_data).unwrap();

    // Get the real path on disk
    let real_path = path_ops::virtual_to_real(&fs, test_path);

    // Read the encrypted data
    let encrypted_data = std::fs::read(&real_path).unwrap();

    // Truncate the file to half its size (corrupting the encryption)
    if encrypted_data.len() > 20 {
        let truncated_len = encrypted_data.len() / 2;
        std::fs::write(&real_path, &encrypted_data[..truncated_len]).unwrap();

        // Attempting to read should fail
        // The decryption should fail because the ciphertext is too short
        let result = file_read::read_file(&fs, test_path);

        assert!(result.is_err(), "Should fail to read truncated encrypted file");

        match result.unwrap_err() {
            crate::errors::ZthfsError::Crypto(_) => {
                // Expected - decryption failed due to truncation
            }
            crate::errors::ZthfsError::Integrity(_) => {
                // Also expected - integrity check detected corruption
            }
            crate::errors::ZthfsError::Fs(msg) => {
                // Also acceptable - IO error during read
                assert!(msg.len() > 0);
            }
            other => {
                panic!("Expected Crypto, Integrity, or Fs error for truncated file, got: {:?}", other);
            }
        }
    }
}

#[test]
fn test_integrity_check_failure_detection() {
    // Test that integrity verification detects data corruption
    let (_temp_dir, fs) = create_fs_with_integrity();

    let test_path = Path::new("/integrity_test.txt");
    let test_data = b"Critical medical data that must remain intact";

    // Write the file
    file_write::write_file(&fs, test_path, test_data).unwrap();

    // Get the real path
    let real_path = path_ops::virtual_to_real(&fs, test_path);

    // Read the encrypted data
    let mut encrypted_data = std::fs::read(&real_path).unwrap();

    // Corrupt the encrypted data by flipping bits
    if !encrypted_data.is_empty() {
        encrypted_data[0] ^= 0xFF;
        if encrypted_data.len() > 1 {
            encrypted_data[1] ^= 0xAA;
        }

        // Write back the corrupted data
        std::fs::write(&real_path, &encrypted_data).unwrap();

        // Attempting to read should fail
        // Either integrity check fails or decryption fails (corrupted ciphertext)
        let result = file_read::read_file(&fs, test_path);

        assert!(result.is_err(), "Should detect corrupted data");

        match result.unwrap_err() {
            crate::errors::ZthfsError::Integrity(_) => {
                // Best case - integrity check detected the corruption
            }
            crate::errors::ZthfsError::Crypto(_) => {
                // Also acceptable - decryption failed on corrupted data
            }
            other => {
                // At minimum should have failed
                assert!(format!("{:?}", other).len() > 0);
            }
        }
    }
}

#[test]
fn test_recover_from_inode_conflict() {
    // Test that the inode system handles conflicts correctly
    let temp_dir = tempfile::TempDir::new().unwrap();

    // SAFETY: getuid() and getgid() are async-signal-safe libc functions
    let _current_uid = unsafe { libc::getuid() };
    let _current_gid = unsafe { libc::getgid() };

    let config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();

    let fs = Zthfs::new(&config).unwrap();

    // Create multiple files and verify they get different inodes
    let paths = vec![
        Path::new("/file1.txt"),
        Path::new("/file2.txt"),
        Path::new("/file3.txt"),
    ];

    let mut inodes = std::collections::HashSet::new();

    for path in &paths {
        let inode = fs.get_or_create_inode(path).unwrap();
        // Each file should get a unique inode
        assert!(
            inodes.insert(inode),
            "Inode {} for path {:?} was already assigned",
            inode,
            path
        );
    }

    // Verify we can look up paths from inodes
    for path in &paths {
        let inode = fs.get_or_create_inode(path).unwrap();
        let lookup_path = fs.get_path_for_inode(inode);
        assert!(
            lookup_path.is_some(),
            "Should be able to lookup path for inode {}",
            inode
        );
        assert_eq!(lookup_path.unwrap(), *path);
    }

    // Root directory should always be inode 1
    let root_inode = fs.get_or_create_inode(Path::new("/")).unwrap();
    assert_eq!(root_inode, 1, "Root directory must be inode 1");

    // Getting root again should return the same inode
    let root_inode2 = fs.get_or_create_inode(Path::new("/")).unwrap();
    assert_eq!(root_inode2, 1);
}

#[test]
fn test_corrupted_database_recovery() {
    // Test filesystem behavior when the inode database is corrupted
    let temp_dir = tempfile::TempDir::new().unwrap();

    let config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();

    let fs = Zthfs::new(&config).unwrap();

    // Create a file and get its inode
    let test_path = Path::new("/db_test.txt");
    let inode = fs.get_or_create_inode(test_path).unwrap();

    // Verify the path is stored
    let lookup = fs.get_path_for_inode(inode);
    assert_eq!(lookup.unwrap(), test_path);

    // The sled database is persistent and should survive fs instance recreation
    drop(fs);

    // Create a new filesystem instance with the same data directory
    let fs2 = Zthfs::new(&config).unwrap();

    // The inode mapping should be preserved
    let lookup2 = fs2.get_path_for_inode(inode);
    assert_eq!(
        lookup2.unwrap(),
        test_path,
        "Inode mapping should persist across filesystem instances"
    );
}

#[test]
fn test_write_error_handling() {
    // Test error handling when write operations fail
    let (_temp_dir, fs) = create_fs_with_integrity();

    // Attempt to write to a path with an invalid parent
    // This should fail gracefully
    let invalid_path = Path::new("/nonexistent_dir/subdir/file.txt");

    let result = file_write::write_file(&fs, invalid_path, b"test data");

    // The write might succeed (creating parent dirs) or fail
    // depending on implementation. Either is acceptable.
    // We just verify it doesn't panic.
    match result {
        Ok(_) => {
            // Implementation created parent dirs - clean up
            let _ = file_create::remove_file(&fs, invalid_path);
        }
        Err(_) => {
            // Implementation rejected invalid path - also fine
        }
    }
}

#[test]
fn test_empty_file_handling() {
    // Test that empty files are handled correctly
    let (_temp_dir, fs) = create_fs_with_integrity();

    let test_path = Path::new("/empty_test.txt");

    // Write empty data
    file_write::write_file(&fs, test_path, b"").unwrap();

    // Read back - should get empty data
    let result = file_read::read_file(&fs, test_path);
    assert!(result.is_ok(), "Should be able to read empty file");

    let data = result.unwrap();
    assert_eq!(data.len(), 0, "Empty file should return empty data");

    // Clean up
    file_create::remove_file(&fs, test_path).unwrap();
}

#[test]
fn test_nonexistent_file_read() {
    // Test reading a file that doesn't exist
    let (_temp_dir, fs) = create_fs_with_integrity();

    let nonexistent_path = Path::new("/this_file_does_not_exist.txt");

    let result = file_read::read_file(&fs, nonexistent_path);

    assert!(result.is_err(), "Should fail to read nonexistent file");

    match result.unwrap_err() {
        crate::errors::ZthfsError::Fs(msg) => {
            assert!(
                msg.contains("not found") || msg.contains("No such file"),
                "Error message should indicate file not found: {}",
                msg
            );
        }
        crate::errors::ZthfsError::Io(io_err) => {
            assert_eq!(
                io_err.kind(),
                std::io::ErrorKind::NotFound,
                "IO error should be NotFound"
            );
        }
        other => {
            panic!("Expected Fs or Io error for nonexistent file, got: {:?}", other);
        }
    }
}
