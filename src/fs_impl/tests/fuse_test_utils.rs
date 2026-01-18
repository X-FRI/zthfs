//! Test utilities for FUSE operation testing
//!
//! Provides mock structures and helpers for testing FUSE callbacks
//! without needing actual FUSE mounting.

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
