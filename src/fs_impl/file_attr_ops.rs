//! File attribute modification operations for ZTHFS.
//!
//! This module provides functions for setting file attributes
//! such as mode, uid, gid, size, and timestamps.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, chunk_ops, file_read, file_write, metadata_ops, path_ops};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Set file attributes (mode, uid, gid, size, atime, mtime).
#[allow(clippy::too_many_arguments)]
pub fn set_file_attributes(
    fs: &Zthfs,
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    atime: Option<u64>,
    mtime: Option<u64>,
) -> ZthfsResult<()> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    let dir_marker_path = metadata_ops::get_dir_marker_path(fs, path);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if metadata_path.exists() {
        // File with extended metadata
        let mut metadata = metadata_ops::load_metadata(fs, path)?;

        // Track if any attributes were changed
        let attributes_changed =
            mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some();

        if let Some(new_mode) = mode {
            metadata.mode = new_mode;
        }
        if let Some(new_uid) = uid {
            metadata.uid = new_uid;
        }
        if let Some(new_gid) = gid {
            metadata.gid = new_gid;
        }
        if let Some(new_atime) = atime {
            metadata.atime = new_atime;
        }
        if let Some(new_mtime) = mtime {
            metadata.mtime = new_mtime;
        }

        // Always update ctime when attributes change
        metadata.ctime = now;

        if attributes_changed {
            metadata_ops::save_metadata(fs, path, &metadata)?;
        }

        // Handle truncate via size
        if let Some(new_size) = size
            && new_size != metadata.size
        {
            truncate_file(fs, path, new_size)?;
        }
    } else if dir_marker_path.exists() {
        // Directory with metadata
        let mut metadata = metadata_ops::load_dir_metadata(fs, path)?;

        // Track if any attributes were changed
        let attributes_changed =
            mode.is_some() || uid.is_some() || gid.is_some() || atime.is_some() || mtime.is_some();

        if let Some(new_mode) = mode {
            metadata.mode = new_mode;
        }
        if let Some(new_uid) = uid {
            metadata.uid = new_uid;
        }
        if let Some(new_gid) = gid {
            metadata.gid = new_gid;
        }
        if let Some(new_atime) = atime {
            metadata.atime = new_atime;
        }
        if let Some(new_mtime) = mtime {
            metadata.mtime = new_mtime;
        }
        metadata.ctime = now;

        if attributes_changed {
            let json = serde_json::to_string(&metadata)
                .map_err(|e| crate::errors::ZthfsError::Serialization(e.to_string()))?;
            fs::write(&dir_marker_path, json)?;
        }
    }

    // Also update filesystem permissions
    let real_path = path_ops::virtual_to_real(fs, path);
    if real_path.exists()
        && let Some(new_mode) = mode
    {
        let mut perms = fs::metadata(&real_path)?.permissions();
        perms.set_mode(new_mode);
        fs::set_permissions(&real_path, perms)?;
    }

    Ok(())
}

/// Truncate file to specified size.
pub fn truncate_file(fs: &Zthfs, path: &Path, new_size: u64) -> ZthfsResult<()> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);

    if metadata_path.exists() {
        let mut metadata = metadata_ops::load_metadata(fs, path)?;

        use std::cmp::Ordering;
        match new_size.cmp(&metadata.size) {
            Ordering::Less => {
                // Truncate: just update metadata size
                // Read operations will respect the new size
                metadata.size = new_size;
                metadata_ops::save_metadata(fs, path, &metadata)?;
            }
            Ordering::Greater => {
                // Extend: write zeros at the end
                let current_data = chunk_ops::read_file_chunked(fs, path)?;
                let mut extended_data = vec![0u8; new_size as usize];
                extended_data[..current_data.len()].copy_from_slice(&current_data);
                chunk_ops::write_file_chunked(fs, path, &extended_data)?;
            }
            Ordering::Equal => {
                // Same size, nothing to do
            }
        }
    } else {
        // Regular file - read, truncate/extend, write back
        let current_data = file_read::read_file(fs, path).unwrap_or_default();
        let mut new_data = vec![0u8; new_size as usize];
        let copy_len = std::cmp::min(current_data.len(), new_data.len());
        new_data[..copy_len].copy_from_slice(&current_data[..copy_len]);
        file_write::write_file(fs, path, &new_data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionConfig, FilesystemConfigBuilder, LogConfig};
    use crate::fs_impl::attr_ops;

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, Zthfs) {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().join("data").to_string_lossy().to_string())
            .encryption(EncryptionConfig::with_random_keys())
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
    fn test_truncate_smaller() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.txt");
        let data = b"Hello, World!";
        file_write::write_file(&fs, file_path, data).unwrap();

        truncate_file(&fs, file_path, 5).unwrap();

        let read = file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read, b"Hello");
    }

    #[test]
    fn test_truncate_larger() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.txt");
        file_write::write_file(&fs, file_path, b"Hello").unwrap();

        truncate_file(&fs, file_path, 10).unwrap();

        let read = file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read.len(), 10);
        assert_eq!(&read[..5], b"Hello");
        assert_eq!(&read[5..], &[0u8; 5]);
    }

    #[test]
    fn test_truncate_chunked_file() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.dat");

        let chunk_size = chunk_ops::get_chunk_size(&fs);
        let large_data = vec![0x42u8; chunk_size * 2];
        chunk_ops::write_file_chunked(&fs, file_path, &large_data).unwrap();

        // Truncate to half size
        let new_size = (chunk_size) as u64;
        truncate_file(&fs, file_path, new_size).unwrap();

        // Verify metadata was updated
        let metadata = metadata_ops::load_metadata(&fs, file_path).unwrap();
        assert_eq!(metadata.size, new_size);

        // Verify size through get_attr as well
        let attr = attr_ops::get_attr(&fs, file_path).unwrap();
        assert_eq!(attr.size, new_size);
    }

    #[test]
    fn test_setattr_chmod() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.txt");
        file_write::write_file(&fs, file_path, b"data").unwrap();

        set_file_attributes(&fs, file_path, Some(0o644), None, None, None, None, None).unwrap();

        let attr = attr_ops::get_attr(&fs, file_path).unwrap();
        assert!(attr.perm > 0);
    }

    #[test]
    fn test_setattr_chmod_directory() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/test_dir");

        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        set_file_attributes(&fs, dir_path, Some(0o700), None, None, None, None, None).unwrap();

        let metadata = metadata_ops::load_dir_metadata(&fs, dir_path).unwrap();
        assert_eq!(metadata.mode, 0o700);

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, false).unwrap();
    }
}
