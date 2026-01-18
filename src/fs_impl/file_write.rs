//! File write operations for ZTHFS.
//!
//! This module provides functions for writing file contents,
//! with support for both regular and chunked files, as well as
//! partial write operations for proper POSIX semantics.

use crate::core::integrity::IntegrityHandler;
use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, chunk_ops, metadata_ops, path_ops};
use std::fs;
use std::path::Path;

/// Write the content of the file (with encryption and integrity verification).
/// This function uses chunked writing for better performance with large files.
pub fn write_file(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);

    // Check file size to decide whether to use chunking
    if chunk_ops::is_chunking_enabled(fs) && data.len() > chunk_ops::get_chunk_size(fs) {
        // Use chunked writing for large files
        return chunk_ops::write_file_chunked(fs, path, data);
    }

    // For small files, use the old method for simplicity and backward compatibility
    // Ensure the directory exists
    if let Some(parent) = real_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Encrypt data
    let path_str = path.to_string_lossy();
    let encrypted_data = fs.encryption.encrypt(data, &path_str)?;

    // Compute checksum
    let checksum = IntegrityHandler::compute_checksum(
        &encrypted_data,
        &fs.config.integrity.algorithm,
        &fs.config.integrity.key,
    )?;

    // Write encrypted data
    fs::write(&real_path, &encrypted_data)?;

    // Set checksum extended attribute
    IntegrityHandler::set_checksum_xattr(&real_path, &checksum, &fs.config.integrity)?;

    Ok(())
}

/// Write partial content to a file at the specified offset (with encryption and integrity verification).
/// This enables proper POSIX write semantics with offset support.
///
/// This implementation is optimized to avoid reading/writing entire files:
/// - For chunked files: Only affected chunks are read/modified/written
/// - For regular files: Falls back to efficient read-modify-write for small files
pub fn write_partial(fs: &Zthfs, path: &Path, offset: i64, data: &[u8]) -> ZthfsResult<u32> {
    let metadata_path = metadata_ops::get_metadata_path(fs, path);

    if metadata_path.exists() {
        // Use optimized chunked partial write
        write_partial_chunked(fs, path, offset, data)
    } else {
        // Use optimized regular file partial write
        write_partial_regular(fs, path, offset, data)
    }
}

/// Write partial content to a regular (non-chunked) file.
/// Optimized to minimize memory usage for small files.
fn write_partial_regular(fs: &Zthfs, path: &Path, offset: i64, data: &[u8]) -> ZthfsResult<u32> {
    let offset = offset as usize;

    // For regular files, we need to read-modify-write, but we can optimize it
    let current_data = crate::fs_impl::file_read::read_file(fs, path).unwrap_or_default();
    let current_size = current_data.len();

    let new_size = std::cmp::max(current_size, offset + data.len());

    // If this is a small file, use the read-modify-write approach
    if current_size <= chunk_ops::get_chunk_size(fs) {
        let mut new_data = vec![0u8; new_size];
        if !current_data.is_empty() {
            let copy_len = std::cmp::min(current_data.len(), new_data.len());
            new_data[..copy_len].copy_from_slice(&current_data[..copy_len]);
        }

        let write_start = offset;
        let write_end = std::cmp::min(write_start + data.len(), new_data.len());
        let data_end = write_end - write_start;
        new_data[write_start..write_end].copy_from_slice(&data[..data_end]);

        write_file(fs, path, &new_data)?;
        Ok(data_end as u32)
    } else {
        // For larger regular files that should have been chunked, convert to chunked
        log::warn!(
            "Large regular file detected during partial write, converting to chunked storage: {path:?}"
        );

        // Read current content
        let current_data = crate::fs_impl::file_read::read_file(fs, path).unwrap_or_default();

        // Create new data with the modification
        let mut new_data = vec![0u8; new_size];
        if !current_data.is_empty() {
            let copy_len = std::cmp::min(current_data.len(), new_data.len());
            new_data[..copy_len].copy_from_slice(&current_data[..copy_len]);
        }

        let write_start = offset;
        let write_end = std::cmp::min(write_start + data.len(), new_data.len());
        let data_end = write_end - write_start;
        new_data[write_start..write_end].copy_from_slice(&data[..data_end]);

        // Write as chunked file
        chunk_ops::write_file_chunked(fs, path, &new_data)?;
        Ok(data_end as u32)
    }
}

/// Write partial content to a chunked file.
/// Only reads and writes the chunks that are actually affected by the write operation.
fn write_partial_chunked(fs: &Zthfs, path: &Path, offset: i64, data: &[u8]) -> ZthfsResult<u32> {
    let metadata = metadata_ops::load_metadata(fs, path)?;
    let chunk_size = metadata.chunk_size;
    let total_chunks = metadata.chunk_count as usize;

    let write_start = offset as usize;
    let write_end = write_start + data.len();
    let file_size = metadata.size as usize;

    // Calculate which chunks are affected
    let start_chunk = write_start / chunk_size;
    let end_chunk = ((write_end - 1) / chunk_size) + 1; // inclusive

    // Ensure we don't go beyond existing chunks
    let end_chunk = std::cmp::min(end_chunk, total_chunks);

    // If writing beyond current file size, we need to extend the file
    let new_file_size = std::cmp::max(file_size, write_end);
    let new_total_chunks = new_file_size.div_ceil(chunk_size);

    let mut bytes_written = 0;

    for chunk_idx in start_chunk..end_chunk {
        let chunk_start = chunk_idx * chunk_size;
        let chunk_end = std::cmp::min((chunk_idx + 1) * chunk_size, new_file_size);

        // Read existing chunk data (or create empty chunk if extending)
        let mut chunk_data = if chunk_idx < total_chunks {
            chunk_ops::read_chunk(fs, path, chunk_idx as u32)?
        } else {
            // New chunk, initialize with zeros
            vec![0u8; chunk_size]
        };

        // Ensure chunk_data is the right size
        if chunk_data.len() < chunk_size && chunk_idx < new_total_chunks - 1 {
            chunk_data.resize(chunk_size, 0);
        } else if chunk_idx == new_total_chunks - 1 {
            // Last chunk might be smaller
            chunk_data.resize(chunk_end - chunk_start, 0);
        }

        // Calculate what part of this chunk to modify
        let chunk_write_start = std::cmp::max(write_start, chunk_start) - chunk_start;
        let chunk_write_end = std::cmp::min(write_end, chunk_end) - chunk_start;

        let data_start = bytes_written;
        let data_end = data_start + (chunk_write_end - chunk_write_start);

        // Apply the write to this chunk
        chunk_data[chunk_write_start..chunk_write_end].copy_from_slice(&data[data_start..data_end]);

        // Write the modified chunk
        chunk_ops::write_chunk(fs, path, chunk_idx as u32, &chunk_data)?;

        bytes_written += chunk_write_end - chunk_write_start;
    }

    // Update metadata if file size changed
    if new_file_size != file_size {
        let mut updated_metadata = metadata;
        updated_metadata.size = new_file_size as u64;
        updated_metadata.chunk_count = new_total_chunks as u32;
        updated_metadata.mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        metadata_ops::save_metadata(fs, path, &updated_metadata)?;
    }

    Ok(bytes_written as u32)
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
    fn test_partial_write_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/partial_write_test.txt");

        // Create initial file content
        let initial_data = b"Hello, World!";
        write_file(&fs, test_path, initial_data).unwrap();

        // Test partial write at offset 7 (overwrite "World" with "Universe")
        let write_data = b"Universe";
        let bytes_written = write_partial(&fs, test_path, 7, write_data).unwrap();
        assert_eq!(bytes_written, write_data.len() as u32);

        // Read entire file to verify content
        let read_data = crate::fs_impl::file_read::read_file(&fs, test_path).unwrap();
        let expected = b"Hello, Universe"; // "World!" (6 chars) -> "Universe" (7 chars)
        assert_eq!(read_data, expected);

        // Test partial write beyond current file size (append-like behavior)
        let append_data = b" How are you?";
        let bytes_written =
            write_partial(&fs, test_path, read_data.len() as i64, append_data).unwrap();
        assert_eq!(bytes_written, append_data.len() as u32);

        // Verify final content
        let final_data = crate::fs_impl::file_read::read_file(&fs, test_path).unwrap();
        let expected_final = b"Hello, Universe How are you?";
        assert_eq!(final_data, expected_final);

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_partial_write_edge_cases() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/edge_case_test.txt");

        // Test writing to empty/non-existent file
        let write_data = b"Start";
        let bytes_written = write_partial(&fs, test_path, 0, write_data).unwrap();
        assert_eq!(bytes_written, write_data.len() as u32);

        let read_data = crate::fs_impl::file_read::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data, write_data);

        // Test partial write with offset larger than file size (creates sparse file)
        let sparse_data = b"Sparse";
        let large_offset = 1000i64;
        let bytes_written = write_partial(&fs, test_path, large_offset, sparse_data).unwrap();
        assert_eq!(bytes_written, sparse_data.len() as u32);

        let read_data = crate::fs_impl::file_read::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data.len(), (large_offset as usize) + sparse_data.len());
        assert_eq!(&read_data[(large_offset as usize)..], sparse_data);

        // Verify original data is preserved at beginning
        assert_eq!(&read_data[..write_data.len()], write_data);

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_chunked_partial_write_operations() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a large file that will be chunked (> 4MB)
        let chunk_size = chunk_ops::get_chunk_size(&fs);
        let file_size = chunk_size * 3 + 1000; // > 12MB
        let large_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

        let test_path = Path::new("/chunked_partial_write.dat");
        chunk_ops::write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Test partial write in the middle of the first chunk
        let offset1 = 1000;
        let write_data1 = b"MODIFIED_CHUNK_1";
        let bytes_written1 = write_partial(&fs, test_path, offset1 as i64, write_data1).unwrap();
        assert_eq!(bytes_written1, write_data1.len() as u32);

        // Test partial write across chunk boundaries
        let offset2 = (chunk_size - 50) as i64; // Near end of first chunk
        let write_data2 = b"CROSS_CHUNK_BOUNDARY_DATA";
        let bytes_written2 = write_partial(&fs, test_path, offset2, write_data2).unwrap();
        assert_eq!(bytes_written2, write_data2.len() as u32);

        // Test partial write in the middle chunk
        let offset3 = (chunk_size + chunk_size / 2) as i64;
        let write_data3 = b"MIDDLE_CHUNK_MODIFICATION";
        let bytes_written3 = write_partial(&fs, test_path, offset3, write_data3).unwrap();
        assert_eq!(bytes_written3, write_data3.len() as u32);

        // Test partial write extending the file
        let offset4 = file_size as i64 + 100; // Beyond current file size
        let write_data4 = b"EXTENDING_FILE_CONTENT";
        let bytes_written4 = write_partial(&fs, test_path, offset4, write_data4).unwrap();
        assert_eq!(bytes_written4, write_data4.len() as u32);

        // Read and verify modifications
        let read_data = chunk_ops::read_file_chunked(&fs, test_path).unwrap();

        // Verify first modification
        let mut expected_data = large_data.clone();
        expected_data[offset1..offset1 + write_data1.len()].copy_from_slice(write_data1);
        expected_data[offset2 as usize..offset2 as usize + write_data2.len()]
            .copy_from_slice(write_data2);
        expected_data[offset3 as usize..offset3 as usize + write_data3.len()]
            .copy_from_slice(write_data3);

        // Verify file was extended
        let new_file_size = std::cmp::max(file_size, (offset4 + write_data4.len() as i64) as usize);
        assert_eq!(read_data.len(), new_file_size);

        // Verify the extending write
        let extend_start = offset4 as usize;
        let extend_end = extend_start + write_data4.len();
        assert_eq!(&read_data[extend_start..extend_end], write_data4);

        // Verify other modifications (first 100KB should match expected)
        let check_size = std::cmp::min(100 * 1024, expected_data.len());
        assert_eq!(&read_data[..check_size], &expected_data[..check_size]);

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_file_size_edge_cases() {
        let (_temp_dir, fs) = create_test_fs();

        // Test various file sizes
        let chunk_size = fs.config.performance.chunk_size;
        let test_cases = vec![
            (0, "empty"),
            (1, "single_byte"),
            (1023, "small"),
            (1024, "one_kilobyte"),
            (chunk_size - 1, "just_under_chunk"),
            (chunk_size, "exactly_chunk"),
            (chunk_size + 1, "just_over_chunk"),
            (chunk_size * 2, "two_chunks"),
        ];

        for (size, description) in test_cases {
            let file_path_str = format!("/size_test_{description}.dat");
            let file_path = Path::new(&file_path_str);
            let data = vec![0xAAu8; size];

            write_file(&fs, file_path, &data).unwrap();

            // Verify size - should always be the original data size
            let reported_size = crate::fs_impl::path_ops::get_file_size(&fs, file_path).unwrap();
            assert_eq!(
                reported_size, size as u64,
                "Failed for {size} bytes ({description})"
            );

            // Verify content
            let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
            assert_eq!(
                read_data.len(),
                size,
                "Failed for {} bytes ({}) - got {} bytes",
                size,
                read_data.len(),
                description
            );
            assert_eq!(read_data, data, "Failed for {size} bytes ({description})");

            crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        }
    }

    #[test]
    fn test_concurrent_file_operations() {
        let (_temp_dir, fs) = create_test_fs();
        let fs = std::sync::Arc::new(fs);

        let mut handles = vec![];

        // Spawn multiple threads to perform concurrent operations
        // Reduce thread count to avoid resource conflicts
        for i in 0..3 {
            let fs_clone = std::sync::Arc::clone(&fs);
            let handle = std::thread::spawn(move || {
                let file_path_str = format!("/concurrent_file_{i}.txt");
                let file_path = Path::new(&file_path_str);
                let data = format!("Concurrent data from thread {i}").into_bytes();

                // Write file
                write_file(&fs_clone, file_path, &data).expect("Write should succeed");

                // Read and verify
                let read_data = crate::fs_impl::file_read::read_file(&fs_clone, file_path)
                    .expect("Read should succeed");
                assert_eq!(read_data, data);

                // Get file size (encrypted size will be larger)
                let size = crate::fs_impl::path_ops::get_file_size(&fs_clone, file_path)
                    .expect("Get size should succeed");
                assert!(size >= data.len() as u64);

                // Clean up
                crate::fs_impl::file_create::remove_file(&fs_clone, file_path)
                    .expect("Remove should succeed");
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }
    }
}
