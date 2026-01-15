//! File read operations for ZTHFS.
//!
//! This module provides functions for reading file contents,
//! with support for both regular and chunked files.

use crate::core::integrity::IntegrityHandler;
use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::{Zthfs, chunk_ops, metadata_ops, path_ops};
use std::fs;
use std::path::Path;

/// Read the content of the file (with decryption and integrity verification).
/// This function uses chunked reading for better performance with large files.
pub fn read_file(fs: &Zthfs, path: &Path) -> ZthfsResult<Vec<u8>> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Check if it's a chunked file
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    if metadata_path.exists() {
        // Use chunked reading for better performance
        return chunk_ops::read_file_chunked(fs, path);
    }

    // Fall back to old method for non-chunked files
    let encrypted_data = fs::read(&real_path)?;

    // Verify integrity
    if let Some(expected_checksum) =
        IntegrityHandler::get_checksum_from_xattr(&real_path, &fs.config.integrity)?
    {
        let is_valid = IntegrityHandler::verify_integrity(
            &encrypted_data,
            &expected_checksum,
            &fs.config.integrity.algorithm,
            &fs.config.integrity.key,
        )?;
        if !is_valid {
            log::warn!("Data integrity check failed for {path:?}");
            return Err(ZthfsError::Integrity(
                "Data integrity verification failed".to_string(),
            ));
        }
    }

    // Decrypt data
    let path_str = path.to_string_lossy();
    let decrypted_data = fs.encryption.decrypt(&encrypted_data, &path_str)?;
    Ok(decrypted_data)
}

/// Read partial file with chunked support (for FUSE read operations)
pub fn read_partial_chunked(
    fs: &Zthfs,
    path: &Path,
    offset: i64,
    size: u32,
) -> ZthfsResult<Vec<u8>> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);
    if !metadata_path.exists() {
        // Fall back to old method for non-chunked files
        let full_data = read_file(fs, path)?;
        let start = offset as usize;
        let end = std::cmp::min(start + size as usize, full_data.len());
        return Ok(full_data[start..end].to_vec());
    }

    let metadata = metadata_ops::load_metadata(fs, path)?;
    let chunk_size = metadata.chunk_size;

    // Get required chunks
    let needed_chunks = chunk_ops::get_chunks_for_read(offset, size, chunk_size);

    let mut result = Vec::new();
    let mut current_offset = offset as usize;

    for chunk_index in needed_chunks {
        let chunk_data = chunk_ops::read_chunk(fs, path, chunk_index)?;

        let chunk_start = (chunk_index as usize) * chunk_size;
        let chunk_end = chunk_start + chunk_data.len();

        if current_offset < chunk_end {
            let data_start = std::cmp::max(current_offset, chunk_start);
            let data_end = std::cmp::min(current_offset + size as usize, chunk_end);

            if data_start < data_end {
                let slice_start = data_start - chunk_start;
                let slice_end = data_end - chunk_start;
                result.extend_from_slice(&chunk_data[slice_start..slice_end]);
            }
        }

        current_offset += chunk_data.len();
    }

    Ok(result)
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
    fn test_basic_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/test.txt");

        // Test path existence check
        assert!(!crate::fs_impl::path_ops::path_exists(&fs, test_path));

        // Create test file
        let test_data = b"Hello, world!";
        crate::fs_impl::file_write::write_file(&fs, test_path, test_data).unwrap();

        // Verify file existence
        assert!(crate::fs_impl::path_ops::path_exists(&fs, test_path));

        // Verify file size (should be the original data size)
        let size = crate::fs_impl::path_ops::get_file_size(&fs, test_path).unwrap();
        assert_eq!(size, test_data.len() as u64);

        // Read file to verify content
        let read_data = read_file(&fs, test_path).unwrap();
        assert_eq!(read_data, test_data);

        // Delete file
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
        assert!(!crate::fs_impl::path_ops::path_exists(&fs, test_path));
    }

    #[test]
    fn test_data_integrity_verification() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/integrity_test.txt");
        let test_data = b"Critical medical data that must remain intact";

        // Write file
        crate::fs_impl::file_write::write_file(&fs, test_path, test_data).unwrap();

        // Manually corrupt the encrypted data to test integrity verification
        let real_path = path_ops::virtual_to_real(&fs, test_path);
        let mut encrypted_data = std::fs::read(&real_path).unwrap();
        if !encrypted_data.is_empty() {
            // Flip a bit in the encrypted data
            encrypted_data[0] ^= 0xFF;
            std::fs::write(&real_path, encrypted_data).unwrap();
        }

        // Attempt to read should fail due to integrity check
        let result = read_file(&fs, test_path);
        assert!(result.is_err());

        // Clean up
        let _ = crate::fs_impl::file_create::remove_file(&fs, test_path);
    }

    #[test]
    fn test_empty_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let empty_path = Path::new("/empty.txt");

        // Write empty file
        crate::fs_impl::file_write::write_file(&fs, empty_path, &[]).unwrap();

        // Verify empty file exists
        assert!(crate::fs_impl::path_ops::path_exists(&fs, empty_path));

        // Verify size is 0 (empty file)
        let size = crate::fs_impl::path_ops::get_file_size(&fs, empty_path).unwrap();
        assert_eq!(size, 0);

        // Read empty file
        let data = read_file(&fs, empty_path).unwrap();
        assert!(data.is_empty());

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, empty_path).unwrap();
    }

    #[test]
    fn test_single_byte_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/single_byte.dat");
        let data = vec![0xBBu8; 1]; // 1 byte

        crate::fs_impl::file_write::write_file(&fs, file_path, &data).unwrap();

        // Verify size
        let reported_size = crate::fs_impl::path_ops::get_file_size(&fs, file_path).unwrap();
        assert_eq!(reported_size, 1u64);

        // Verify content
        let read_data = read_file(&fs, file_path).unwrap();
        println!(
            "DEBUG: Wrote 1 byte, read {} bytes: {:?}",
            read_data.len(),
            &read_data
        );
        assert_eq!(read_data.len(), 1);
        assert_eq!(read_data, data);

        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_large_file_partial_reads() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a file larger than chunk size
        let chunk_size = fs.config.performance.chunk_size;
        let file_size = chunk_size * 3 + 500;
        let large_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

        let test_path = Path::new("/large_partial.dat");
        chunk_ops::write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Test reading from different offsets
        let test_cases = vec![
            (0, 100),                             // Beginning
            (1000, 2000),                         // Middle of first chunk
            (chunk_size as i64, 100),             // Start of second chunk
            ((chunk_size * 2 + 100) as i64, 300), // Middle of third chunk
            ((file_size - 50) as i64, 50),        // End of file
        ];

        for (offset, size) in test_cases {
            let partial_data = read_partial_chunked(&fs, test_path, offset, size as u32).unwrap();
            let expected_size = std::cmp::min(size, (file_size as i64 - offset) as usize);
            assert_eq!(partial_data.len(), expected_size);

            // Verify content matches
            let start = offset as usize;
            let end = start + partial_data.len();
            assert_eq!(&partial_data[..], &large_data[start..end]);
        }

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_chunked_vs_regular_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        // Test regular file (< 4MB)
        let small_data = vec![0x41u8; 1024];
        let small_path = Path::new("/small_file.txt");

        crate::fs_impl::file_write::write_file(&fs, small_path, &small_data).unwrap();
        let small_read = read_file(&fs, small_path).unwrap();
        assert_eq!(small_read, small_data);

        // Test chunked file (> 4MB)
        let large_data = vec![0x42u8; chunk_ops::get_chunk_size(&fs) + 1024];
        let large_path = Path::new("/large_file.dat");

        crate::fs_impl::file_write::write_file(&fs, large_path, &large_data).unwrap();
        let large_read = read_file(&fs, large_path).unwrap();
        assert_eq!(large_read, large_data);

        // Both should exist
        assert!(crate::fs_impl::path_ops::path_exists(&fs, small_path));
        assert!(crate::fs_impl::path_ops::path_exists(&fs, large_path));

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, small_path).unwrap();
        crate::fs_impl::file_create::remove_file(&fs, large_path).unwrap();
    }

    #[test]
    fn test_error_handling() {
        let (_temp_dir, fs) = create_test_fs();

        // Test reading non-existent file
        let nonexistent_path = Path::new("/does_not_exist.txt");
        let result = read_file(&fs, nonexistent_path);
        assert!(result.is_err());

        // Test getting size of non-existent file
        let result = crate::fs_impl::path_ops::get_file_size(&fs, nonexistent_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_unicode_filename_support() {
        let (_temp_dir, fs) = create_test_fs();

        // Test various Unicode filenames
        let test_cases = vec![
            "文件.txt",
            "médical_data.dat",
            "тестовый_файл.txt",
            "📁📄.txt",
            "café_résumé.pdf",
        ];

        for filename in test_cases {
            let file_path_str = format!("/{filename}");
            let file_path = Path::new(&file_path_str);
            let data = format!("Content for {filename}").into_bytes();

            crate::fs_impl::file_write::write_file(&fs, file_path, &data).unwrap();

            // Verify file exists
            assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

            // Verify content
            let read_data = read_file(&fs, file_path).unwrap();
            assert_eq!(read_data, data);

            crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        }
    }
}
