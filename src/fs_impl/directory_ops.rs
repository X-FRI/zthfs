//! Directory operations for ZTHFS.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to dir_read and dir_modify modules.

// Re-export directory-related functions from new modules
pub use crate::fs_impl::{dir_modify, dir_read};
