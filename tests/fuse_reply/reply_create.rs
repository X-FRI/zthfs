//! Test capture type for ReplyCreate

use fuser::FileAttr;
use std::time::Duration;

/// Captures the result of a FUSE create operation
pub struct CaptureReplyCreate {
    pub attr: Option<FileAttr>,
    pub ttl: Option<Duration>,
    pub generation: Option<u64>,
    pub flags: Option<u32>,
    pub error: Option<i32>,
}

impl CaptureReplyCreate {
    pub fn new() -> Self {
        Self {
            attr: None,
            ttl: None,
            generation: None,
            flags: None,
            error: None,
        }
    }

    pub fn created(&mut self, ttl: &Duration, attr: &FileAttr, generation: u64, flags: u32) {
        self.ttl = Some(*ttl);
        self.attr = Some(*attr);
        self.generation = Some(generation);
        self.flags = Some(flags);
    }

    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none()
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

impl Default for CaptureReplyCreate {
    fn default() -> Self {
        Self::new()
    }
}
