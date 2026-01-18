//! Test utilities for FUSE operation testing
//!
//! Provides mock structures and helpers for testing FUSE callbacks
//! without needing actual FUSE mounting.

use std::path::Path;
use tempfile::TempDir;
use crate::config::{FilesystemConfig, FilesystemConfigBuilder, LogConfig};
use crate::fs_impl::Zthfs;

/// Mock request with configurable uid/gid
///
/// Note: This is a simplified mock for testing. Creating actual fuser::Request
/// instances requires internal FUSE channel state, so we use this simple struct
/// to represent request parameters in tests.
pub struct MockRequest {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl MockRequest {
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            pid: 1000,
        }
    }

    pub fn root() -> Self {
        Self::new(0, 0)
    }

    pub fn unprivileged() -> Self {
        Self::new(1000, 1000)
    }
}

/// Test helper to verify reply error codes
pub trait ReplyExt {
    fn is_error(&self) -> bool;
    fn error_code(&self) -> Option<i32>;
}

/// Capture reply state for testing
pub struct TestReply<T> {
    pub reply: Option<T>,
    pub error: Option<i32>,
    pub called: bool,
}

impl<T> TestReply<T> {
    pub fn new() -> Self {
        Self {
            reply: None,
            error: None,
            called: false,
        }
    }

    pub fn success(&self) -> bool {
        self.called && self.error.is_none()
    }

    pub fn failed(&self) -> bool {
        self.called && self.error.is_some()
    }
}

impl<T> Default for TestReply<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyExt for TestReply<()> {
    fn is_error(&self) -> bool {
        self.error.is_some()
    }

    fn error_code(&self) -> Option<i32> {
        self.error
    }
}

/// Creates a test filesystem configuration with disabled logging and permissive security
pub fn create_test_config(data_dir: &Path) -> FilesystemConfig {
    // Get current user's uid/gid for test configuration
    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };

    // Build base config
    let mut config = FilesystemConfigBuilder::new()
        .data_dir(data_dir.to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();

    // For tests, allow the current user and root to access the filesystem
    // This allows tests to run without root privileges
    config.security.allowed_users = vec![current_uid, 0];
    config.security.allowed_groups = vec![current_gid, 0];

    config
}

/// Create a test filesystem with the given configuration
///
/// Returns a tuple of (temp_dir, filesystem) where the temp_dir
/// will be automatically cleaned up when dropped.
pub fn create_test_fs() -> (TempDir, Zthfs) {
    let temp_dir = TempDir::new().unwrap();
    let config = create_test_config(temp_dir.path());
    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}

/// A test filesystem wrapper with automatic cleanup
///
/// This struct manages both the temporary directories and the filesystem instance.
pub struct TestFs {
    pub data_dir: TempDir,
    pub fs: Zthfs,
}

impl TestFs {
    /// Creates a new test filesystem with temporary directories
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the data directory path
    pub fn data_path(&self) -> &Path {
        self.data_dir.path()
    }
}

impl Default for TestFs {
    fn default() -> Self {
        let data_dir = TempDir::new().unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(data_dir.path().to_string_lossy().to_string())
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

        Self { data_dir, fs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_request_creation() {
        let req = MockRequest::new(1000, 1000);
        assert_eq!(req.uid, 1000);
        assert_eq!(req.gid, 1000);
        assert_eq!(req.pid, 1000);
    }

    #[test]
    fn test_mock_request_root() {
        let req = MockRequest::root();
        assert_eq!(req.uid, 0);
        assert_eq!(req.gid, 0);
    }

    #[test]
    fn test_mock_request_unprivileged() {
        let req = MockRequest::unprivileged();
        assert_eq!(req.uid, 1000);
        assert_eq!(req.gid, 1000);
    }

    #[test]
    fn test_test_reply_default() {
        let reply: TestReply<()> = TestReply::default();
        assert!(!reply.called);
        assert!(reply.error.is_none());
        assert!(reply.reply.is_none());
    }

    #[test]
    fn test_test_reply_new() {
        let reply: TestReply<()> = TestReply::new();
        assert!(!reply.called);
        assert!(reply.error.is_none());
    }

    #[test]
    fn test_create_test_fs() {
        let (_temp_dir, fs) = create_test_fs();
        assert!(fs.data_dir().exists());
    }

    #[test]
    fn test_test_fs_creation() {
        let test_fs = TestFs::new();
        assert!(test_fs.data_path().exists());
    }

    #[test]
    fn test_create_test_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = create_test_config(temp_dir.path());
        assert!(!config.data_dir.is_empty());
        assert!(!config.logging.enabled);
    }
}
