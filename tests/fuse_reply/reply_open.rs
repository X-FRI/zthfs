//! Test capture type for ReplyOpen

/// Captures the result of a FUSE open operation
pub struct CaptureReplyOpen {
    pub flags: Option<u64>,
    pub error: Option<i32>,
}

impl CaptureReplyOpen {
    pub fn new() -> Self {
        Self {
            flags: None,
            error: None,
        }
    }

    pub fn opened(&mut self, flags: u64) {
        self.flags = Some(flags);
    }

    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }

    pub fn get_flags(&self) -> Option<u64> {
        self.flags
    }

    pub fn get_error(&self) -> Option<i32> {
        self.error
    }
}

impl Default for CaptureReplyOpen {
    fn default() -> Self {
        Self::new()
    }
}
