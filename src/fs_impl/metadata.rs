//! Metadata operations for ZTHFS.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to metadata_ops.

// Re-export from the new metadata_ops module
pub use crate::fs_impl::metadata_ops::{ChunkedFileMetadata, DIR_MARKER_SUFFIX, METADATA_SUFFIX};
