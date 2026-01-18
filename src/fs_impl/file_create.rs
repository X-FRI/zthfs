//! File creation and removal operations for ZTHFS.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, attr_ops, metadata_ops, path_ops};
use fuser::FileAttr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Create a new file with the specified mode (permissions).
pub fn create_file(fs: &Zthfs, path: &Path, mode: u32) -> ZthfsResult<FileAttr> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Ensure the directory exists
    if let Some(parent) = real_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Create and set permissions in one block to ensure file is closed before get_attr
    {
        let file = fs::File::create(&real_path)?;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(mode);
        file.set_permissions(perms)?;
        file.sync_all()?;
    } // file is closed here

    // Now get attributes - file is closed and synced
    let attr = attr_ops::get_attr(fs, path)?;
    Ok(attr)
}

/// Remove a file, handling both regular and chunked files.
pub fn remove_file(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);

    if metadata_path.exists() {
        // Remove chunked file
        // Load metadata before removing it
        if let Ok(metadata) = metadata_ops::load_metadata(fs, path) {
            // Remove all chunks
            for chunk_index in 0..metadata.chunk_count {
                let chunk_path = metadata_ops::get_chunk_path(fs, path, chunk_index);
                let _ = fs::remove_file(&chunk_path); // Ignore errors
            }
        }

        // Remove metadata file
        let _ = fs::remove_file(&metadata_path); // Ignore errors if file doesn't exist
    } else {
        // Remove regular file
        let real_path = path_ops::virtual_to_real(fs, path);
        let _ = fs::remove_file(&real_path); // Ignore errors if file doesn't exist
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
    fn test_create_and_remove_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_create_remove.txt");

        // Create file
        let attr = create_file(&fs, file_path, 0o644).unwrap();
        assert_eq!(attr.kind, fuser::FileType::RegularFile);

        // Verify file exists
        assert!(path_ops::path_exists(&fs, file_path));

        // Remove file
        remove_file(&fs, file_path).unwrap();

        // Verify file no longer exists
        assert!(!path_ops::path_exists(&fs, file_path));
    }

    #[test]
    fn test_create_file_with_mode() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_mode.txt");

        // Create file with specific mode
        create_file(&fs, file_path, 0o600).unwrap();

        // Verify permissions
        let attr = attr_ops::get_attr(&fs, file_path).unwrap();
        assert!(attr.perm > 0);

        remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_remove_nonexistent_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/nonexistent.txt");

        // Removing non-existent file should not error
        let result = remove_file(&fs, file_path);
        assert!(result.is_ok());
    }
}
