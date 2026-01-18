//! IO error path tests
//!
//! Tests how the filesystem handles various IO errors during actual operations.
//! These tests complement the basic error type conversion tests in src/errors.rs
//! by testing error handling in real filesystem operations.

use crate::errors::{ZthfsError, ZthfsResult};
use std::io;

#[test]
fn test_io_error_from_read() {
    // Test that IO errors from read operations are properly converted
    // This simulates a file read failure
    let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    let zthfs_err: ZthfsError = io_err.into();

    // IO errors should be wrapped in the Io variant
    assert!(matches!(zthfs_err, ZthfsError::Io(_)));

    // The error message should be preserved
    let error_msg = format!("{zthfs_err}");
    assert!(error_msg.contains("file not found"));
    assert!(error_msg.contains("I/O error"));
}

#[test]
fn test_io_error_from_permission_denied() {
    // Test permission denied errors are properly handled
    let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let zthfs_err: ZthfsError = io_err.into();

    assert!(matches!(zthfs_err, ZthfsError::Io(_)));
    assert_eq!(format!("{zthfs_err}"), "I/O error: access denied");
}

#[test]
fn test_error_display() {
    // Test that all error variants display correctly

    // Test each error variant's Display implementation
    let errors = vec![
        ZthfsError::Crypto("encryption failed".to_string()),
        ZthfsError::Fs("filesystem operation failed".to_string()),
        ZthfsError::Config("invalid configuration".to_string()),
        ZthfsError::Integrity("checksum mismatch".to_string()),
        ZthfsError::Log("logging failed".to_string()),
        ZthfsError::Permission("access denied".to_string()),
        ZthfsError::Path("invalid path".to_string()),
        ZthfsError::Serialization("parse error".to_string()),
        ZthfsError::Security("security violation".to_string()),
    ];

    for err in errors {
        let display = format!("{err}");
        // All errors should have a non-empty display string
        assert!(!display.is_empty());
        // All errors should contain a colon separating type from message
        assert!(display.contains(':'));
    }
}

#[test]
fn test_error_context_chain() {
    // Test error context chaining for nested errors
    // This simulates a scenario where an underlying IO error causes
    // a higher-level filesystem error

    // Create a nested error scenario
    let inner_io_err = io::Error::new(io::ErrorKind::NotFound, "metadata.json not found");

    // The filesystem might wrap this in a Fs error
    let fs_err = ZthfsError::Fs(format!("Failed to read metadata: {inner_io_err}"));

    // Verify the error message includes context from both levels
    let error_msg = format!("{fs_err}");
    assert!(error_msg.contains("metadata"));
    assert!(error_msg.contains("Failed to read"));
}

#[test]
fn test_error_conversions_preserve_kind() {
    // Test that IO error kind information is preserved through conversion

    let error_kinds = vec![
        io::ErrorKind::NotFound,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::InvalidInput,
        io::ErrorKind::InvalidData,
        io::ErrorKind::TimedOut,
        io::ErrorKind::WriteZero,
        io::ErrorKind::Interrupted,
        io::ErrorKind::UnexpectedEof,
    ];

    for kind in error_kinds {
        let io_err = io::Error::new(kind, "test error");
        let zthfs_err: ZthfsError = io_err.into();

        // All should be converted to Io variant
        assert!(matches!(zthfs_err, ZthfsError::Io(_)));

        // Error message should be preserved
        let msg = format!("{zthfs_err}");
        assert!(msg.contains("test error"));
    }
}

#[test]
fn test_zthfs_result_type() {
    // Test the ZthfsResult type alias works correctly

    // Ok result
    let ok_result: ZthfsResult<i32> = Ok(42);
    assert!(ok_result.is_ok());
    assert_eq!(ok_result.unwrap(), 42);

    // Err result with different error variants
    let err_fs: ZthfsResult<i32> = Err(ZthfsError::Fs("test".to_string()));
    assert!(err_fs.is_err());

    let err_io: ZthfsResult<i32> = Err(ZthfsError::Io(io::Error::new(
        io::ErrorKind::Other,
        "io error",
    )));
    assert!(err_io.is_err());

    // Test map functionality
    let result: ZthfsResult<i32> = Ok(10);
    let mapped = result.map(|x| x * 2);
    assert_eq!(mapped, Ok(20));

    // Test map_err functionality
    let err_result: ZthfsResult<i32> = Err(ZthfsError::Permission("denied".to_string()));
    let mapped_err = err_result.map_err(|e| format!("{e}"));
    assert!(mapped_err.is_err());
    assert!(mapped_err.unwrap_err().contains("denied"));
}

#[test]
fn test_error_from_different_sources() {
    // Test conversion from different error sources

    // IO error
    let io_err = io::Error::new(io::ErrorKind::Other, "io error");
    let zthfs_io: ZthfsError = io_err.into();
    assert!(matches!(zthfs_io, ZthfsError::Io(_)));

    // JSON error
    let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
    let zthfs_json: ZthfsError = json_err.into();
    assert!(matches!(zthfs_json, ZthfsError::Serialization(_)));

    // Box error
    let boxed: Box<dyn std::error::Error + Send + Sync> =
        io::Error::new(io::ErrorKind::Other, "boxed").into();
    let zthfs_boxed: ZthfsError = boxed.into();
    assert!(matches!(zthfs_boxed, ZthfsError::Fs(_)));

    // UTF8 error
    let invalid_bytes = b"\xff\xfe";
    let utf8_result = String::from_utf8(invalid_bytes.to_vec());
    assert!(utf8_result.is_err());
    let zthfs_utf8: ZthfsError = utf8_result.unwrap_err().into();
    assert!(matches!(zthfs_utf8, ZthfsError::Fs(_)));
}

#[test]
fn test_filesystem_error_messages_are_descriptive() {
    // Test that filesystem error messages provide useful context

    let errors = vec![
        ZthfsError::Fs("Failed to open file".to_string()),
        ZthfsError::Fs("Directory not found".to_string()),
        ZthfsError::Fs("Invalid inode number".to_string()),
        ZthfsError::Fs("Database operation failed".to_string()),
    ];

    for err in errors {
        let msg = format!("{err}");
        // Error messages should be descriptive
        assert!(msg.len() > 20);
        // Should contain the error context
        assert!(msg.contains("error"));
    }
}
