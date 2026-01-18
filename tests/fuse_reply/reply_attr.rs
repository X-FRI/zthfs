//! Test capture type for ReplyAttr

use fuser::FileAttr;
use std::time::Duration;

/// Captures the result of a FUSE getattr operation
pub struct CaptureReplyAttr {
    /// The file attributes returned
    pub attr: Option<FileAttr>,
    /// The time-to-live for this attribute
    pub ttl: Option<Duration>,
    /// Error code if operation failed
    pub error: Option<i32>,
}

impl CaptureReplyAttr {
    pub fn new() -> Self {
        Self {
            attr: None,
            ttl: None,
            error: None,
        }
    }

    /// Mimics fuser::ReplyAttr::attr()
    pub fn attr(&mut self, ttl: &Duration, attr: &FileAttr) {
        self.ttl = Some(*ttl);
        self.attr = Some(*attr);
    }

    /// Mimics fuser::ReplyAttr::error()
    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.attr.is_some()
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn get_attr(&self) -> Option<&FileAttr> {
        self.attr.as_ref()
    }

    pub fn get_error(&self) -> Option<i32> {
        self.error
    }
}

impl Default for CaptureReplyAttr {
    fn default() -> Self {
        Self::new()
    }
}
