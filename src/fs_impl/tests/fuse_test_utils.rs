//! Test utilities for FUSE operation testing
//!
//! Provides mock structures and helpers for testing FUSE callbacks
//! without needing actual FUSE mounting.

use crate::config::{FilesystemConfig, FilesystemConfigBuilder, LogConfig};
use crate::fs_impl::Zthfs;
use tempfile::TempDir;

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

    /// Converts this mock request to a fuser::Request.
    ///
    /// # Note
    ///
    /// This is a stub implementation. Creating an actual `fuser::Request` requires
    /// FUSE channel state from an active mount. This method documents the requirement
    /// but cannot be fully implemented without a live FUSE connection.
    ///
    /// In tests, use the `MockRequest` fields directly (uid, gid, pid) rather than
    /// trying to get a fuser::Request.
    #[allow(dead_code)]
    pub fn as_fuser_request(&self) -> &'static str {
        // FIXME: Cannot construct actual fuser::Request without FuseDevice/channel state
        // This stub documents the interface requirement for the spec
        "fuser::Request requires active FUSE mount - use MockRequest fields in tests"
    }
}

/// Test helper to verify reply error codes
///
/// TODO: This trait will be used in future tasks for testing FUSE reply verification.
/// Currently unused as reply testing requires more complex FUSE integration.
pub trait ReplyExt {
    fn is_error(&self) -> bool;
    fn error_code(&self) -> Option<i32>;
}

/// Capture reply state for testing
///
/// TODO: This struct will be used in future tasks for capturing and verifying FUSE reply
/// state. Currently unused as reply testing requires more complex FUSE integration.
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

/// Creates a test filesystem configuration with disabled logging and permissive security
pub fn create_test_config(data_dir: &std::path::Path) -> FilesystemConfig {
    // Get current user's uid/gid for test configuration
    // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
    // succeed and return valid uid_t/gid_t values. They have no preconditions.
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

/// Creates a temporary test filesystem without mounting
///
/// Returns a tuple of (temp_dir, filesystem) where the temp_dir
/// will be automatically cleaned up when dropped.
pub fn create_test_fs() -> (TempDir, Zthfs) {
    let temp_dir = TempDir::new().unwrap();
    let config = create_test_config(temp_dir.path());
    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}
