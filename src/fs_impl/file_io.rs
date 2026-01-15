//! File I/O operations for ZTHFS.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to file_read, file_write, and chunk_ops modules.

// Re-export I/O-related functions from new modules
pub use crate::fs_impl::{chunk_ops, file_read, file_write};
