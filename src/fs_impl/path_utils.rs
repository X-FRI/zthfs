//! Path and inode utility functions for ZTHFS filesystem operations.
//!
//! This module provides re-exports for backward compatibility.
//! The actual implementation has been moved to path_ops and inode_ops modules.

use crate::fs_impl::Zthfs;
use std::path::{Path, PathBuf};

// Re-export path and inode operations from new modules
pub use crate::fs_impl::{inode_ops, path_ops};

// Keep the method implementation for backward compatibility
impl Zthfs {
    /// Convert the virtual path in ZTHFS to the real physical path in the underlying file system.
    /// Use fs.data_dir as the root directory, and concatenate the virtual path (remove the leading /) to form the real path under data_dir.
    /// For example, the virtual path /test/file.txt when data_dir is /var/lib/zthfs/data will be mapped to /var/lib/zthfs/data/test/file.txt.
    /// DEPRECATED: Use path_ops::virtual_to_real instead.
    #[deprecated(note = "Use path_ops::virtual_to_real instead")]
    pub fn virtual_to_real(&self, path: &Path) -> PathBuf {
        self.data_dir.join(path.strip_prefix("/").unwrap_or(path))
    }
}
