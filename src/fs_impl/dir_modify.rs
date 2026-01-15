//! Directory modification operations for ZTHFS.
//!
//! This module provides functions for creating and removing directories.

use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::{Zthfs, attr_ops, inode_ops, metadata_ops, path_ops};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Create a directory with metadata.
pub fn create_directory(fs: &Zthfs, path: &Path, mode: u32) -> ZthfsResult<fuser::FileAttr> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Ensure parent directory exists
    if let Some(parent) = real_path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    // Create the actual directory
    fs::create_dir(&real_path)?;

    // Create directory marker file with metadata
    let marker_path = metadata_ops::get_dir_marker_path(fs, path);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let metadata = metadata_ops::ChunkedFileMetadata {
        size: 0,
        chunk_count: 0,
        chunk_size: 0,
        mtime: now,
        mode,
        uid: unsafe { libc::getuid() } as u32,
        gid: unsafe { libc::getgid() } as u32,
        atime: now,
        ctime: now,
        is_dir: true,
    };

    let json =
        serde_json::to_string(&metadata).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    fs::write(&marker_path, json)?;

    // Set directory permissions
    let mut perms = fs::metadata(&real_path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&real_path, perms)?;

    // Get and return attributes
    attr_ops::get_attr(fs, path)
}

/// Check if a directory is empty (no children).
pub fn is_directory_empty(fs: &Zthfs, path: &Path) -> ZthfsResult<bool> {
    let path_str = path.to_string_lossy();
    let prefix = sled::IVec::from(path_str.as_bytes());

    // Scan inode_db for entries with this path as prefix
    for result in fs.inode_db.scan_prefix(prefix) {
        let (key, _) = result?;

        // Skip the directory's own marker file
        let key_str = String::from_utf8_lossy(&key);
        if key_str == path_str {
            continue;
        }

        // Check if this is a direct child (not a deeper descendant)
        let relative = key_str.strip_prefix(&path_str as &str);
        if relative.is_none() {
            continue;
        }

        let relative = relative.unwrap();
        // Skip if it's the directory itself (path ends with nothing or just /)
        if relative.is_empty() || relative == "/" {
            continue;
        }

        // Check if this is a direct child (no additional slashes except leading)
        // relative.starts_with('/') means we need to skip the leading slash
        let relative_path = relative.strip_prefix('/').unwrap_or(relative);
        if relative_path.contains('/') {
            // Deeper nested path, not direct child
            continue;
        }

        return Ok(false);
    }

    // Also check the actual filesystem
    let real_path = path_ops::virtual_to_real(fs, path);
    if let Ok(entries) = fs::read_dir(&real_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            // Skip the directory marker file and dot entries
            if name
                .to_string_lossy()
                .ends_with(metadata_ops::DIR_MARKER_SUFFIX)
            {
                continue;
            }
            if name == "." || name == ".." {
                continue;
            }
            return Ok(false);
        }
    }

    Ok(true)
}

/// Remove a directory.
/// If recursive is false, the directory must be empty.
pub fn remove_directory(fs: &Zthfs, path: &Path, recursive: bool) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Check if directory exists
    if !real_path.is_dir() {
        return Err(ZthfsError::Fs("Not a directory".to_string()));
    }

    // Check if empty (unless recursive)
    if !recursive && !is_directory_empty(fs, path)? {
        return Err(ZthfsError::Fs("Directory not empty".to_string()));
    }

    // Remove directory marker file
    let marker_path = metadata_ops::get_dir_marker_path(fs, path);
    let _ = fs::remove_file(&marker_path);

    // Remove the actual directory
    if recursive {
        fs::remove_dir_all(&real_path)?;
    } else {
        fs::remove_dir(&real_path)?;
    }

    // Clean up bidirectional inode mappings
    let path_str = path.to_string_lossy();

    // Get the inode before removing (to clean up reverse mapping)
    if let Ok(inode) = inode_ops::get_inode(fs, path) {
        // Remove inode -> path reverse mapping
        let _ = fs.inode_db.remove(inode.to_be_bytes());
        // Remove from in-memory cache
        fs.inodes.remove(&inode);
    }

    // Remove path -> inode mapping
    let _ = fs.inode_db.remove(path_str.as_bytes());

    Ok(())
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
    fn test_mkdir_creates_directory_marker() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/test_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();

        let marker_path = metadata_ops::get_dir_marker_path(&fs, dir_path);
        assert!(marker_path.exists());

        let metadata = metadata_ops::load_dir_metadata(&fs, dir_path).unwrap();
        assert!(metadata.is_dir);
        assert_eq!(metadata.mode, 0o755);
    }

    #[test]
    fn test_mkdir_nested() {
        let (_temp_dir, fs) = create_test_fs();
        let nested_path = Path::new("/level1/level2/level3");

        create_directory(&fs, nested_path, 0o755).unwrap();

        assert!(path_ops::path_exists(&fs, Path::new("/level1")));
        assert!(path_ops::path_exists(&fs, Path::new("/level1/level2")));
        assert!(path_ops::path_exists(&fs, nested_path));
    }

    #[test]
    fn test_is_directory_empty_true() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/empty_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();

        assert!(is_directory_empty(&fs, dir_path).unwrap());
    }

    #[test]
    fn test_is_directory_empty_false() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/non_empty_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();
        let file_path = Path::new("/non_empty_dir/file.txt");
        crate::fs_impl::file_write::write_file(&fs, file_path, b"data").unwrap();

        assert!(!is_directory_empty(&fs, dir_path).unwrap());
    }

    #[test]
    fn test_rmdir_empty_directory() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/empty_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();
        assert!(path_ops::path_exists(&fs, dir_path));

        remove_directory(&fs, dir_path, false).unwrap();
        assert!(!path_ops::path_exists(&fs, dir_path));
    }

    #[test]
    fn test_rmdir_non_empty_returns_error() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/non_empty_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();
        let file_path = Path::new("/non_empty_dir/file.txt");
        crate::fs_impl::file_write::write_file(&fs, file_path, b"data").unwrap();

        let result = remove_directory(&fs, dir_path, false);
        assert!(matches!(result, Err(ZthfsError::Fs(msg)) if msg.contains("not empty")));
    }

    #[test]
    fn test_rmdir_recursive() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/parent_dir");

        create_directory(&fs, dir_path, 0o755).unwrap();
        let file_path = Path::new("/parent_dir/file.txt");
        crate::fs_impl::file_write::write_file(&fs, file_path, b"data").unwrap();

        // Non-recursive should fail
        assert!(remove_directory(&fs, dir_path, false).is_err());

        // Recursive should succeed
        remove_directory(&fs, dir_path, true).unwrap();
        assert!(!path_ops::path_exists(&fs, dir_path));
    }
}
