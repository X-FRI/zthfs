//! File attribute operations for ZTHFS.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to attr_ops and file_attr_ops modules.

// Re-export attribute-related functions from new modules
pub use crate::fs_impl::{attr_ops, file_attr_ops};
