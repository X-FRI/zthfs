//! Tests for FUSE write() callback

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, crate::fs_impl::Zthfs) {
        crate::fs_impl::tests::fuse_test_utils::create_test_fs()
    }

    #[test]
    fn test_write_new_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write.txt");
        let test_data = b"Hello, World! Writing new file content.";

        // Write a new file
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Verify the file was written correctly
        assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

        // Read it back to verify
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read_data, test_data, "Written data should match read data");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_with_offset() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_offset.txt");
        let initial_data = b"000000000011111111112222222222"; // 30 bytes

        // Write initial file
        crate::fs_impl::file_write::write_file(&fs, file_path, initial_data).unwrap();

        // Write at offset 10 (overwriting some 1s with Xs)
        let offset = 10i64;
        let write_data = b"XXXXXXXXXX";
        crate::fs_impl::file_write::write_partial(&fs, file_path, offset, write_data).unwrap();

        // Read back and verify
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        let expected = b"0000000000XXXXXXXXXX2222222222";
        assert_eq!(
            read_data, expected,
            "Write at offset should modify correct portion"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_append() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_append.txt");
        let initial_data = b"Initial content. ";

        // Write initial file
        crate::fs_impl::file_write::write_file(&fs, file_path, initial_data).unwrap();

        // Append more data by writing at the end
        let initial_size = initial_data.len() as i64;
        let append_data = b"Appended more data!";
        crate::fs_impl::file_write::write_partial(&fs, file_path, initial_size, append_data)
            .unwrap();

        // Read back and verify
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        let expected = b"Initial content. Appended more data!";
        assert_eq!(
            read_data, expected,
            "Append should extend file with new data"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_large_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_large.dat");
        // Create 1 MB of data (larger than default chunk size)
        let large_data = vec![0xABu8; 1024 * 1024];

        // Write large file
        crate::fs_impl::file_write::write_file(&fs, file_path, &large_data).unwrap();

        // Verify file size
        let file_size = crate::fs_impl::path_ops::get_file_size(&fs, file_path).unwrap();
        assert_eq!(file_size, 1024 * 1024, "File should have correct size");

        // Read back and verify content
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read_data, large_data, "Large file content should match");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_encrypted() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_encrypted.txt");
        let test_data = b"Secret patient data: SSN, Diagnosis, Treatment Plan";

        // Write data (should be encrypted)
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Verify disk data is encrypted (not the same as original)
        let real_path = crate::fs_impl::path_ops::virtual_to_real(&fs, file_path);
        let disk_data = std::fs::read(&real_path).unwrap();
        assert_ne!(
            disk_data, test_data,
            "Data on disk should be encrypted (different from original)"
        );

        // But read back gives the original decrypted data
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(
            read_data, test_data,
            "Decrypted read should match original data"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_empty_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_empty.txt");

        // Write empty data
        let empty_data = b"";
        crate::fs_impl::file_write::write_file(&fs, file_path, empty_data).unwrap();

        // Verify file exists
        assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

        // Verify size is 0
        let file_size = crate::fs_impl::path_ops::get_file_size(&fs, file_path).unwrap();
        assert_eq!(file_size, 0, "Empty file should have size 0");

        // Read back
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert!(read_data.is_empty(), "Read data should be empty");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_overwrite_existing() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_overwrite.txt");
        let initial_data = b"Initial data that will be overwritten";

        // Write initial data
        crate::fs_impl::file_write::write_file(&fs, file_path, initial_data).unwrap();

        // Overwrite with completely different data
        let new_data = b"New data that replaces the old content";
        crate::fs_impl::file_write::write_file(&fs, file_path, new_data).unwrap();

        // Verify the new data replaced the old
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read_data, new_data, "Should have new data, not old");
        assert_ne!(read_data, initial_data, "Old data should be gone");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_with_offset_beyond_file_size() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_sparse.txt");
        let initial_data = b"START";

        // Write initial data
        crate::fs_impl::file_write::write_file(&fs, file_path, initial_data).unwrap();

        // Write at offset beyond current file size (creates sparse-like file)
        let large_offset = 1000i64;
        let sparse_data = b"END";
        crate::fs_impl::file_write::write_partial(&fs, file_path, large_offset, sparse_data)
            .unwrap();

        // Read back and verify size
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        let expected_size = large_offset as usize + sparse_data.len();
        assert_eq!(
            read_data.len(),
            expected_size,
            "File should be extended to accommodate write at offset"
        );

        // Verify start data is preserved
        assert_eq!(
            &read_data[..initial_data.len()],
            initial_data,
            "Original data should be preserved at start"
        );

        // Verify sparse data is at correct position
        assert_eq!(
            &read_data[large_offset as usize..],
            sparse_data,
            "Sparse data should be at correct offset"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_multiple_updates() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_multiple.txt");
        let initial_data = b"AAAABBBBCCCCDDDD";

        // Write initial data
        crate::fs_impl::file_write::write_file(&fs, file_path, initial_data).unwrap();

        // Perform multiple partial writes
        crate::fs_impl::file_write::write_partial(&fs, file_path, 4, b"1111").unwrap(); // Replace BBBB
        crate::fs_impl::file_write::write_partial(&fs, file_path, 8, b"2222").unwrap(); // Replace CCCC
        crate::fs_impl::file_write::write_partial(&fs, file_path, 12, b"3333").unwrap(); // Replace DDDD

        // Verify all modifications
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        let expected = b"AAAA111122223333";
        assert_eq!(read_data, expected, "Multiple writes should all be applied");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_write_chunked_file_integrity() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_write_chunked.txt");
        let chunk_size = crate::fs_impl::chunk_ops::get_chunk_size(&fs);

        // Create data that spans multiple chunks
        let large_data: Vec<u8> = (0..chunk_size * 2).map(|i| (i % 256) as u8).collect();

        // Write (will be chunked)
        crate::fs_impl::file_write::write_file(&fs, file_path, &large_data).unwrap();

        // Verify chunked metadata exists
        let metadata_path = crate::fs_impl::metadata_ops::get_metadata_path(&fs, file_path);
        assert!(
            metadata_path.exists(),
            "Chunked file should have metadata file"
        );

        // Read back and verify
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(read_data, large_data, "Chunked file should match original");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }
}
