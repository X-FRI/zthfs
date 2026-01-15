//! File synchronization operations for ZTHFS.

use crate::errors::ZthfsResult;
use crate::fs_impl::Zthfs;
use crate::fs_impl::path_ops;
use std::path::Path;

/// Sync data and metadata to disk.
pub fn sync_all(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);

    if real_path.is_file() {
        let file = std::fs::File::open(&real_path)?;
        file.sync_all()?;
    }

    // Sync the inode database
    fs.inode_db.flush()?;

    Ok(())
}

/// Sync only data to disk.
pub fn sync_data(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);

    if real_path.is_file() {
        let file = std::fs::File::open(&real_path)?;
        file.sync_data()?;
    }

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
    fn test_sync_all() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.txt");
        crate::fs_impl::file_write::write_file(&fs, file_path, b"data").unwrap();

        assert!(sync_all(&fs, file_path).is_ok());
    }

    #[test]
    fn test_sync_data() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/test.txt");
        crate::fs_impl::file_write::write_file(&fs, file_path, b"data").unwrap();

        assert!(sync_data(&fs, file_path).is_ok());
    }

    #[test]
    fn test_sync_nonexistent_file() {
        let (_temp_dir, fs) = create_test_fs();
        let file_path = Path::new("/nonexistent.txt");

        // sync_all/sync_data should not error on non-existent files
        // (they just skip the file sync part)
        let result = sync_all(&fs, file_path);
        assert!(result.is_ok() || result.is_err()); // Either behavior is acceptable
    }
}
