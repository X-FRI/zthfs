//! Metadata operations for ZTHFS.
//!
//! This module provides functions for managing file and directory metadata,
//! including the ChunkedFileMetadata structure and metadata file paths.

use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::{Zthfs, path_ops};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Metadata file suffix for storing file metadata
pub const METADATA_SUFFIX: &str = ".zthfs_meta";

/// Directory marker file suffix
pub const DIR_MARKER_SUFFIX: &str = ".zthfs_dir";

/// File metadata structure for chunked files
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(private_interfaces)]
pub struct ChunkedFileMetadata {
    /// Original file size
    pub size: u64,
    /// Number of chunks
    pub chunk_count: u32,
    /// Chunk size used
    pub chunk_size: usize,
    /// Last modified time
    pub mtime: u64,
    /// File permissions (POSIX mode)
    pub mode: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Last access time
    pub atime: u64,
    /// Metadata change time
    pub ctime: u64,
    /// Is this a directory?
    pub is_dir: bool,
}

/// Get metadata file path for a chunked file
pub fn get_metadata_path(fs: &Zthfs, path: &Path) -> PathBuf {
    let real_path = path_ops::virtual_to_real(fs, path);
    real_path.with_extension(METADATA_SUFFIX)
}

/// Get directory marker file path
pub fn get_dir_marker_path(fs: &Zthfs, path: &Path) -> PathBuf {
    let real_path = path_ops::virtual_to_real(fs, path);
    real_path.with_extension(DIR_MARKER_SUFFIX)
}

/// Save file metadata to disk
#[allow(private_interfaces)]
pub fn save_metadata(fs: &Zthfs, path: &Path, metadata: &ChunkedFileMetadata) -> ZthfsResult<()> {
    let metadata_path = get_metadata_path(fs, path);
    let json =
        serde_json::to_string(metadata).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    std::fs::write(&metadata_path, json)?;
    Ok(())
}

/// Load file metadata from disk
#[allow(private_interfaces)]
pub fn load_metadata(fs: &Zthfs, path: &Path) -> ZthfsResult<ChunkedFileMetadata> {
    let metadata_path = get_metadata_path(fs, path);
    let json = std::fs::read_to_string(&metadata_path)?;
    let metadata: ChunkedFileMetadata =
        serde_json::from_str(&json).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    Ok(metadata)
}

/// Load directory metadata from marker file
#[allow(private_interfaces)]
pub fn load_dir_metadata(fs: &Zthfs, path: &Path) -> ZthfsResult<ChunkedFileMetadata> {
    let marker_path = get_dir_marker_path(fs, path);
    let json = std::fs::read_to_string(&marker_path)?;
    let metadata: ChunkedFileMetadata =
        serde_json::from_str(&json).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    Ok(metadata)
}

/// Get chunk path for a specific chunk index
pub fn get_chunk_path(fs: &Zthfs, path: &Path, chunk_index: u32) -> PathBuf {
    let real_path = path_ops::virtual_to_real(fs, path);
    real_path.with_extension(format!("{chunk_index}.chunk"))
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
    fn test_get_metadata_path() {
        let (_temp_dir, fs) = create_test_fs();
        let test_path = Path::new("/test/file.txt");
        let metadata_path = get_metadata_path(&fs, test_path);
        assert!(metadata_path.to_string_lossy().ends_with(".zthfs_meta"));
    }

    #[test]
    fn test_get_dir_marker_path() {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/test_dir");
        let marker_path = get_dir_marker_path(&fs, dir_path);
        assert!(marker_path.to_string_lossy().ends_with(".zthfs_dir"));
    }

    #[test]
    fn test_save_and_load_metadata() {
        let (_temp_dir, fs) = create_test_fs();

        let metadata = ChunkedFileMetadata {
            size: 1024,
            chunk_count: 1,
            chunk_size: 1024,
            mtime: 12345,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            atime: 12345,
            ctime: 12345,
            is_dir: false,
        };

        let test_path = Path::new("/test_file.txt");
        save_metadata(&fs, test_path, &metadata).unwrap();
        let loaded = load_metadata(&fs, test_path).unwrap();

        assert_eq!(loaded.size, metadata.size);
        assert_eq!(loaded.chunk_count, metadata.chunk_count);
        assert_eq!(loaded.mode, metadata.mode);
    }

    #[test]
    fn test_get_chunk_path() {
        let (_temp_dir, fs) = create_test_fs();
        let test_path = Path::new("/test/file.dat");
        let chunk_path = get_chunk_path(&fs, test_path, 0);
        assert!(chunk_path.to_string_lossy().ends_with("0.chunk"));
    }
}
