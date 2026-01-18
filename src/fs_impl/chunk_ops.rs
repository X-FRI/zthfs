//! Chunked file operations for ZTHFS.
//!
//! This module provides functions for reading and writing large files
//! in chunks, which improves performance for files larger than the
//! configured chunk size.

use crate::core::integrity::IntegrityHandler;
use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::{Zthfs, metadata_ops, path_ops};
use std::fs;
use std::path::Path;

/// Get chunk size from filesystem configuration
pub fn get_chunk_size(fs: &Zthfs) -> usize {
    fs.config.performance.chunk_size
}

/// Check if chunking is enabled
pub fn is_chunking_enabled(fs: &Zthfs) -> bool {
    fs.config.performance.chunk_size > 0
}

/// Calculate which chunks are needed for a read operation
pub fn get_chunks_for_read(offset: i64, size: u32, chunk_size: usize) -> Vec<u32> {
    let start_chunk = (offset as usize) / chunk_size;
    let end_chunk = ((offset as usize) + size as usize).div_ceil(chunk_size);
    (start_chunk..end_chunk).map(|i| i as u32).collect()
}

/// Read a specific chunk
pub fn read_chunk(fs: &Zthfs, path: &Path, chunk_index: u32) -> ZthfsResult<Vec<u8>> {
    let chunk_path = metadata_ops::get_chunk_path(fs, path, chunk_index);
    let encrypted_data = fs::read(&chunk_path)?;

    // Verify integrity
    if let Some(expected_checksum) =
        IntegrityHandler::get_checksum_from_xattr(&chunk_path, &fs.config.integrity)?
    {
        let is_valid = IntegrityHandler::verify_integrity(
            &encrypted_data,
            &expected_checksum,
            &fs.config.integrity.algorithm,
            &fs.config.integrity.key,
        )?;
        if !is_valid {
            log::warn!("Data integrity check failed for chunk {chunk_index} of {path:?}");
            return Err(ZthfsError::Integrity(format!(
                "Data integrity verification failed for chunk {chunk_index}"
            )));
        }
    }

    // Decrypt data
    let path_str = format!("{}:chunk{}", path.to_string_lossy(), chunk_index);
    let decrypted_data = fs.encryption.decrypt(&encrypted_data, &path_str)?;
    Ok(decrypted_data)
}

/// Write a specific chunk
pub fn write_chunk(fs: &Zthfs, path: &Path, chunk_index: u32, data: &[u8]) -> ZthfsResult<()> {
    let chunk_path = metadata_ops::get_chunk_path(fs, path, chunk_index);

    // Ensure the directory exists
    if let Some(parent) = chunk_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Encrypt data
    let path_str = format!("{}:chunk{}", path.to_string_lossy(), chunk_index);
    let encrypted_data = fs.encryption.encrypt(data, &path_str)?;

    // Compute checksum
    let checksum = IntegrityHandler::compute_checksum(
        &encrypted_data,
        &fs.config.integrity.algorithm,
        &fs.config.integrity.key,
    )?;

    // Write encrypted data
    fs::write(&chunk_path, &encrypted_data)?;

    // Set checksum extended attribute
    IntegrityHandler::set_checksum_xattr(&chunk_path, &checksum, &fs.config.integrity)?;

    Ok(())
}

/// Read file with chunked support
pub fn read_file_chunked(fs: &Zthfs, path: &Path) -> ZthfsResult<Vec<u8>> {
    // Check if it's a chunked file
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    if !metadata_path.exists() {
        // Fall back to old method for non-chunked files
        return crate::fs_impl::file_read::read_file(fs, path);
    }

    let metadata = metadata_ops::load_metadata(fs, path)?;
    let mut result = Vec::with_capacity(metadata.size as usize);

    for chunk_index in 0..metadata.chunk_count {
        let chunk_data = read_chunk(fs, path, chunk_index)?;
        result.extend_from_slice(&chunk_data);
    }

    Ok(result)
}

/// Write file with chunked support
pub fn write_file_chunked(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Ensure the directory exists
    if let Some(parent) = real_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let chunk_size = get_chunk_size(fs);
    let total_chunks = data.len().div_ceil(chunk_size);

    // Create metadata
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let metadata = metadata_ops::ChunkedFileMetadata {
        size: data.len() as u64,
        chunk_count: total_chunks as u32,
        chunk_size,
        mtime: now,
        mode: 0o644, // Default: rw-r--r--
        uid: unsafe { libc::getuid() } as u32,
        gid: unsafe { libc::getgid() } as u32,
        atime: now,
        ctime: now,
        is_dir: false,
    };

    // Write chunks
    for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
        write_chunk(fs, path, i as u32, chunk_data)?;
    }

    // Save metadata
    metadata_ops::save_metadata(fs, path, &metadata)?;

    Ok(())
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
    fn test_get_chunk_size() {
        let (_temp_dir, fs) = create_test_fs();
        let chunk_size = get_chunk_size(&fs);
        assert!(chunk_size > 0);
    }

    #[test]
    fn test_is_chunking_enabled() {
        let (_temp_dir, fs) = create_test_fs();
        assert!(is_chunking_enabled(&fs));
    }

    #[test]
    fn test_get_chunks_for_read() {
        let chunks = get_chunks_for_read(0, 1024, 512);
        assert_eq!(chunks, vec![0, 1]);
    }

    #[test]
    fn test_chunked_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        // Create large file that will be chunked (> 4MB)
        let chunk_size = get_chunk_size(&fs);
        let large_data = vec![0x42u8; chunk_size * 2 + 1024]; // > 8MB

        let test_path = Path::new("/large_file.dat");

        // Write large file using chunked method
        write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Verify file exists
        assert!(crate::fs_impl::path_ops::path_exists(&fs, test_path));

        // Verify file size
        let size = crate::fs_impl::path_ops::get_file_size(&fs, test_path).unwrap();
        assert_eq!(size, large_data.len() as u64);

        // Read file using chunked reading
        let read_data = read_file_chunked(&fs, test_path).unwrap();
        assert_eq!(read_data, large_data);

        // Test partial chunked reading
        let partial_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, test_path, 0, 1024).unwrap();
        assert_eq!(partial_data.len(), 1024);
        assert_eq!(&partial_data[..], &large_data[..1024]);

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
        assert!(!crate::fs_impl::path_ops::path_exists(&fs, test_path));
    }

    #[test]
    fn test_chunked_file_integrity() {
        let (_temp_dir, fs) = create_test_fs();

        // Create large file for chunked storage
        let large_data = vec![0x55u8; get_chunk_size(&fs) + 1000];
        let test_path = Path::new("/chunked_integrity.dat");

        write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Manually corrupt one chunk
        let chunk_path = metadata_ops::get_chunk_path(&fs, test_path, 0);
        let mut chunk_data = std::fs::read(&chunk_path).unwrap();
        if !chunk_data.is_empty() {
            chunk_data[0] ^= 0xFF;
            std::fs::write(&chunk_path, chunk_data).unwrap();
        }

        // Reading should fail due to integrity check
        let result = read_file_chunked(&fs, test_path);
        assert!(result.is_err());

        // Clean up
        let _ = crate::fs_impl::file_create::remove_file(&fs, test_path);
    }

    #[test]
    fn test_chunk_metadata_persistence() {
        let (_temp_dir, fs) = create_test_fs();

        // Create chunked file
        let large_data = vec![0x77u8; get_chunk_size(&fs) * 2 + 500];
        let file_path = Path::new("/chunked_metadata.dat");

        write_file_chunked(&fs, file_path, &large_data).unwrap();

        // Verify metadata file exists
        let metadata_path = metadata_ops::get_metadata_path(&fs, file_path);
        assert!(metadata_path.exists());

        // Load and verify metadata
        let metadata = metadata_ops::load_metadata(&fs, file_path).unwrap();
        assert_eq!(metadata.size, large_data.len() as u64);
        assert_eq!(metadata.chunk_count, 3); // 2 full chunks + 1 partial
        assert_eq!(metadata.chunk_size, get_chunk_size(&fs));
        assert!(metadata.mtime > 0);

        // Verify chunk files exist
        for i in 0..metadata.chunk_count {
            let chunk_path = metadata_ops::get_chunk_path(&fs, file_path, i);
            assert!(chunk_path.exists());
        }

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();

        // Verify all files are removed
        assert!(!metadata_path.exists());
        for i in 0..metadata.chunk_count {
            let chunk_path = metadata_ops::get_chunk_path(&fs, file_path, i);
            assert!(!chunk_path.exists());
        }
    }

    #[test]
    fn test_extended_metadata_fields() {
        let (_temp_dir, fs) = create_test_fs();

        // Test with chunked file to verify metadata is properly stored
        let chunk_size = get_chunk_size(&fs);
        let large_data = vec![0x42u8; chunk_size + 1000];
        let test_path = Path::new("/test_metadata.txt");

        write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Load the metadata directly to verify extended fields
        let metadata = metadata_ops::load_metadata(&fs, test_path).unwrap();

        // Verify new metadata fields exist
        assert!(metadata.mode > 0, "Metadata should have mode");
        assert!(metadata.atime > 0, "Metadata should have atime");
        assert!(metadata.ctime > 0, "Metadata should have ctime");
        assert!(!metadata.is_dir, "File should not be marked as directory");

        // Verify get_attr uses the stored metadata
        let attr = crate::fs_impl::attr_ops::get_attr(&fs, test_path).unwrap();
        assert_eq!(attr.size, large_data.len() as u64);
        assert!(attr.perm > 0, "File should have permissions");

        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
    }
}
