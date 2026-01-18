//! Test capture type for ReplyEntry

use fuser::{FileAttr, FileType};
use std::time::Duration;

/// Captures the result of a FUSE lookup operation
///
/// This type implements the same interface as fuser::ReplyEntry's methods
/// that are called by Filesystem trait implementations, but captures
/// the results in memory for testing.
pub struct CaptureReplyEntry {
    /// The file attributes returned
    pub attr: Option<FileAttr>,
    /// The generation number
    pub generation: Option<u64>,
    /// The time-to-live for this entry
    pub ttl: Option<Duration>,
    /// Error code if operation failed
    pub error: Option<i32>,
}

impl CaptureReplyEntry {
    pub fn new() -> Self {
        Self {
            attr: None,
            generation: None,
            ttl: None,
            error: None,
        }
    }

    /// Mimics fuser::ReplyEntry::entry()
    pub fn entry(&mut self, ttl: &Duration, attr: &FileAttr, generation: u64) {
        self.ttl = Some(*ttl);
        self.attr = Some(*attr);
        self.generation = Some(generation);
    }

    /// Mimics fuser::ReplyEntry::error()
    pub fn error(&mut self, error: i32) {
        self.error = Some(error);
    }

    /// Returns true if the operation succeeded
    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.attr.is_some()
    }

    /// Returns true if the operation failed
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Get the error code
    pub fn get_error(&self) -> Option<i32> {
        self.error
    }

    /// Get the inode number
    pub fn inode(&self) -> Option<u64> {
        self.attr.as_ref().map(|a| a.ino)
    }

    /// Get the file size
    pub fn size(&self) -> Option<u64> {
        self.attr.as_ref().map(|a| a.size)
    }

    /// Get the file type
    pub fn kind(&self) -> Option<FileType> {
        self.attr.as_ref().map(|a| a.kind)
    }
}

impl Default for CaptureReplyEntry {
    fn default() -> Self {
        Self::new()
    }
}
