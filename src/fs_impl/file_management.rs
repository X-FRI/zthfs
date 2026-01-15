//! File management operations for ZTHFS.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to file_create and file_copy modules.

// Re-export file management functions from new modules
pub use crate::fs_impl::{file_copy, file_create};
