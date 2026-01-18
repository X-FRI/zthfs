//! Space operations for ZTHFS.

use crate::errors::ZthfsResult;
use crate::fs_impl::Zthfs;
use std::fs;

/// Get available space in the filesystem.
/// Returns a simplified estimate (1GB fallback).
pub fn get_available_space(fs: &Zthfs) -> ZthfsResult<u64> {
    // Simplified to check the available space of the data directory.
    let _metadata = fs::metadata(&fs.data_dir)?;
    // TODO: Use a more accurate method to get the available space.
    // TODO: Return an estimated value for now.
    Ok(1024 * 1024 * 1024) // 1GB as fallback
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
    fn test_get_available_space() {
        let (_temp_dir, fs) = create_test_fs();

        let space = get_available_space(&fs).unwrap();
        // Should return the fallback value
        assert_eq!(space, 1024 * 1024 * 1024);
    }
}
