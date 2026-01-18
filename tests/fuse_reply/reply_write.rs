//! Test capture type for ReplyWrite

/// Captures the result of a FUSE write operation
pub struct CaptureReplyWrite {
    pub size: Option<u32>,
    pub error: Option<i32>,
}

impl CaptureReplyWrite {
    pub fn new() -> Self {
        Self {
            size: None,
            error: None,
        }
    }

    pub fn written(&mut self, size: u32) {
        self.size = Some(size);
    }

    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.size.is_some()
    }

    pub fn get_size(&self) -> Option<u32> {
        self.size
    }

    pub fn get_error(&self) -> Option<i32> {
        self.error
    }
}

impl Default for CaptureReplyWrite {
    fn default() -> Self {
        Self::new()
    }
}
