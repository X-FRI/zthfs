//! File attribute operations for ZTHFS.
//!
//! This module provides functions for retrieving file attributes
//! such as size, permissions, timestamps, etc.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, inode_ops, metadata_ops, path_ops};
use fuser::{FileAttr, FileType};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Get the attributes of the specified inode (file or directory).
/// Returns size, permissions, timestamps, and other metadata.
pub fn get_attr(fs: &Zthfs, path: &Path) -> ZthfsResult<FileAttr> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    let dir_marker_path = metadata_ops::get_dir_marker_path(fs, path);

    // Check if we have extended metadata (file or directory)
    let (size, mtime, mode, uid, gid, atime, ctime, is_dir) = if metadata_path.exists() {
        let meta = metadata_ops::load_metadata(fs, path)?;
        (
            meta.size,
            meta.mtime,
            meta.mode,
            meta.uid,
            meta.gid,
            meta.atime,
            meta.ctime,
            meta.is_dir,
        )
    } else if dir_marker_path.exists() {
        let meta = metadata_ops::load_dir_metadata(fs, path)?;
        (
            meta.size,
            meta.mtime,
            meta.mode,
            meta.uid,
            meta.gid,
            meta.atime,
            meta.ctime,
            meta.is_dir,
        )
    } else {
        // Fallback to filesystem metadata for non-chunked files
        let real_path = path_ops::virtual_to_real(fs, path);
        let fs_meta = fs::metadata(&real_path)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (
            fs_meta.len(),
            now,
            fs_meta.permissions().mode() as u32,
            fs_meta.uid(),
            fs_meta.gid(),
            now,
            now,
            real_path.is_dir(),
        )
    };

    let inode = inode_ops::get_inode(fs, path)?;
    let kind = if is_dir {
        FileType::Directory
    } else {
        FileType::RegularFile
    };

    // Helper to convert unix seconds to SystemTime
    let secs_to_sys_time = |secs: u64| -> std::time::SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)
    };

    Ok(FileAttr {
        ino: inode,
        size,
        blocks: size.div_ceil(4096),
        atime: secs_to_sys_time(atime),
        mtime: secs_to_sys_time(mtime),
        ctime: secs_to_sys_time(ctime),
        crtime: secs_to_sys_time(ctime),
        kind,
        perm: mode as u16,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfigBuilder, LogConfig};

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, Zthfs) {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().join("data").to_string_lossy().to_string())
            .logging(LogConfig {
                enabled: true,
                file_path: log_dir.join("test.log").to_string_lossy().to_string(),
                level: "info".to_string(),
                max_size: 1024 * 1024,
                rotation_count: 3,
            })
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();
        (temp_dir, fs)
    }

    #[test]
    fn test_metadata_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/metadata_test.txt");
        let data = b"Test data for metadata operations";

        // Write file
        crate::fs_impl::file_write::write_file(&fs, file_path, data).unwrap();

        // Get attributes
        let attr = get_attr(&fs, file_path).unwrap();

        // Verify basic attributes
        // Note: attr.size returns the encrypted file size, not the original data size
        assert!(attr.size > data.len() as u64); // Encrypted size > original size
        assert_eq!(attr.kind, FileType::RegularFile);
        assert_eq!(attr.nlink, 1);

        // Inode should be consistent
        let inode = inode_ops::get_inode(&fs, file_path).unwrap();
        assert_eq!(attr.ino, inode);

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }
}
