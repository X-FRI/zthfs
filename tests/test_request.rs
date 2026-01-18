//! Test Request type for FUSE operations
//!
//! Provides a simplified Request-like type for testing Filesystem trait methods.

/// A test-only request with configurable uid/gid
///
/// For use in calling Filesystem trait methods directly without
/// needing a real FUSE request from the kernel.
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl TestRequest {
    /// Create a new test request with specific uid/gid
    pub fn new(uid: u32, gid: u32) -> Self {
        Self {
            uid,
            gid,
            pid: 1000, // Default test PID
        }
    }

    /// Create a root request (uid=0, gid=0)
    pub fn root() -> Self {
        Self::new(0, 0)
    }

    /// Create an unprivileged user request
    pub fn unprivileged() -> Self {
        // SAFETY: getuid/getgid are async-signal-safe and always succeed
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        Self::new(uid, gid)
    }

    /// Create a request with a specific user
    pub fn with_uid(uid: u32) -> Self {
        Self::new(uid, 0)
    }

    /// Create a request with a specific group
    pub fn with_gid(gid: u32) -> Self {
        Self::new(0, gid)
    }
}

impl Default for TestRequest {
    fn default() -> Self {
        Self::unprivileged()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_request_root() {
        let req = TestRequest::root();
        assert_eq!(req.uid, 0);
        assert_eq!(req.gid, 0);
    }

    #[test]
    fn test_test_request_unprivileged() {
        let req = TestRequest::unprivileged();
        // Current user should not be root (usually)
        assert!(req.uid >= 1000 || req.uid == 0);
    }

    #[test]
    fn test_test_request_custom() {
        let req = TestRequest::new(1234, 5678);
        assert_eq!(req.uid, 1234);
        assert_eq!(req.gid, 5678);
    }
}
