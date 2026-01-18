//! Test capture type for ReplyEmpty

/// Captures the result of FUSE operations that have no return value
/// (e.g., access, unlink, rmdir, fsync)
pub struct CaptureReplyEmpty {
    /// Error code if operation failed
    pub error: Option<i32>,
    /// Whether ok() was called
    pub called: bool,
}

impl CaptureReplyEmpty {
    pub fn new() -> Self {
        Self {
            error: None,
            called: false,
        }
    }

    /// Mimics fuser::ReplyEmpty::ok()
    pub fn ok(&mut self) {
        self.called = true;
    }

    /// Mimics fuser::ReplyEmpty::error()
    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.called && self.error.is_none()
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn get_error(&self) -> Option<i32> {
        self.error
    }
}

impl Default for CaptureReplyEmpty {
    fn default() -> Self {
        Self::new()
    }
}
