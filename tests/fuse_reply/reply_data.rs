//! Test capture type for ReplyData

/// Captures the result of a FUSE read operation
pub struct CaptureReplyData {
    pub data: Option<Vec<u8>>,
    pub error: Option<i32>,
}

impl CaptureReplyData {
    pub fn new() -> Self {
        Self {
            data: None,
            error: None,
        }
    }

    pub fn data(&mut self, data: &[u8]) {
        self.data = Some(data.to_vec());
    }

    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.data.is_some()
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn get_error(&self) -> Option<i32> {
        self.error
    }
}

impl Default for CaptureReplyData {
    fn default() -> Self {
        Self::new()
    }
}
