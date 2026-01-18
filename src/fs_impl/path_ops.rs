//! Path operations for ZTHFS.
//!
//! This module provides functions for path conversion and existence checks.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, metadata_ops};
use std::path::{Path, PathBuf};

/// Convert the virtual path in ZTHFS to the real physical path in the underlying file system.
/// Use fs.data_dir as the root directory, and concatenate the virtual path (remove the leading /) to form the real path under data_dir.
/// For example, the virtual path /test/file.txt when data_dir is /var/lib/zthfs/data will be mapped to /var/lib/zthfs/data/test/file.txt.
pub fn virtual_to_real(fs: &Zthfs, path: &Path) -> PathBuf {
    fs.data_dir.join(path.strip_prefix("/").unwrap_or(path))
}

/// Check if a path exists in the filesystem.
/// This checks for chunked files, directories, and regular files.
pub fn path_exists(fs: &Zthfs, path: &Path) -> bool {
    let real_path = virtual_to_real(fs, path);
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    let dir_marker_path = metadata_ops::get_dir_marker_path(fs, path);

    // Check if it's a chunked file, directory, or regular file
    metadata_path.exists() || dir_marker_path.exists() || real_path.exists()
}

/// Get the size of a file in bytes.
/// For chunked files, this reads the metadata to get the original (unencrypted) size.
/// For regular files, this reads and decrypts the file to get the original size.
pub fn get_file_size(fs: &Zthfs, path: &Path) -> ZthfsResult<u64> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    if metadata_path.exists() {
        // For chunked files, get size from metadata
        let metadata = metadata_ops::load_metadata(fs, path)?;
        Ok(metadata.size)
    } else {
        // For regular files, read and decrypt to get original size
        // Note: This requires the file_read module
        let data = crate::fs_impl::file_read::read_file(fs, path)?;
        Ok(data.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionConfig, FilesystemConfigBuilder, LogConfig};

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
    fn test_virtual_to_real_path_conversion() {
        let (temp_dir, fs) = create_test_fs();

        let virtual_path = Path::new("/test/file.txt");
        let real_path = virtual_to_real(&fs, virtual_path);

        assert!(real_path.starts_with(temp_dir.path().join("data")));
        assert!(real_path.ends_with("test/file.txt"));
    }

    #[test]
    fn test_path_exists_nonexistent() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/does_not_exist.txt");
        assert!(!path_exists(&fs, test_path));
    }

    #[test]
    fn test_path_exists_after_create() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/test.txt");
        crate::fs_impl::file_write::write_file(&fs, test_path, b"Hello").unwrap();
        assert!(path_exists(&fs, test_path));
    }
}
