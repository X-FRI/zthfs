//! Tests for FUSE read() callback

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, crate::fs_impl::Zthfs) {
        crate::fs_impl::tests::fuse_test_utils::create_test_fs()
    }

    #[test]
    fn test_read_existing_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read.txt");
        let test_data = b"Hello, World! This is test content for reading.";

        // Write a file first
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Read the file back
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();

        assert_eq!(read_data, test_data, "Read data should match written data");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_with_offset() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_offset.txt");
        let test_data = b"0123456789ABCDEFGHIJ";

        // Write a file first
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Read from offset 10 (should get "ABCDEFGHIJ")
        let offset = 10i64;
        let size = 10u32;
        let read_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, offset, size).unwrap();

        assert_eq!(read_data, b"ABCDEFGHIJ", "Should read from correct offset");

        // Read from offset 5 (should get "56789ABCDEFGHIJ")
        let offset = 5i64;
        let read_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, offset, 20u32).unwrap();

        assert_eq!(
            read_data, b"56789ABCDEFGHIJ",
            "Should read from offset 5 to end"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_partial() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_partial.txt");
        let test_data = b"Small content";

        // Write a small file
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Try to read more data than the file contains
        let buffer_size = 100u32;
        let read_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, 0, buffer_size)
                .unwrap();

        assert_eq!(
            read_data, test_data,
            "Should only return actual file content"
        );
        assert!(
            read_data.len() < buffer_size as usize,
            "Read size should be limited by file size"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_nonexistent_file() {
        let (_temp_dir, fs) = create_test_fs();

        let nonexistent_path = Path::new("/does_not_exist.txt");

        // Try to read a file that doesn't exist
        let result = crate::fs_impl::file_read::read_file(&fs, nonexistent_path);

        assert!(
            result.is_err(),
            "Reading nonexistent file should return an error"
        );

        // Verify the error type
        match result {
            Err(crate::errors::ZthfsError::Io(_)) => (),
            Err(crate::errors::ZthfsError::Fs(_)) => (),
            _ => panic!("Expected Io or Fs error for nonexistent file"),
        }
    }

    #[test]
    fn test_read_encrypted_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_encrypted_read.txt");
        let test_data = b"Secret patient data: John Doe, Diagnosis: Cold";

        // Write encrypted data
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Verify disk data is encrypted (not the same as original)
        let real_path = crate::fs_impl::path_ops::virtual_to_real(&fs, file_path);
        let disk_data = std::fs::read(&real_path).unwrap();
        assert_ne!(
            disk_data, test_data,
            "Data on disk should be encrypted (different from original)"
        );

        // But reading back gives the original decrypted data
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(
            read_data, test_data,
            "Decrypted read should match original data"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_empty_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_empty.txt");

        // Write empty data to create an empty file (properly encrypted)
        crate::fs_impl::file_write::write_file(&fs, file_path, b"").unwrap();

        // Read the empty file
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();

        assert!(read_data.is_empty(), "Empty file should return empty data");

        // Read with offset/partial should also work
        let partial_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, 0, 100).unwrap();
        assert!(
            partial_data.is_empty(),
            "Partial read of empty file should be empty"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_large_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_large.txt");
        // Create data larger than chunk size to test chunked reading
        let chunk_size = crate::fs_impl::chunk_ops::get_chunk_size(&fs);
        let test_data = vec![0xABu8; chunk_size + 1000];

        // Write large file (will be chunked)
        crate::fs_impl::file_write::write_file(&fs, file_path, &test_data).unwrap();

        // Read entire file
        let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
        assert_eq!(
            read_data, test_data,
            "Should read entire chunked file correctly"
        );

        // Read from middle of first chunk
        let offset = 100i64;
        let size = 200u32;
        let partial_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, offset, size).unwrap();
        assert_eq!(
            partial_data,
            &test_data[offset as usize..offset as usize + size as usize],
            "Partial read should match expected slice"
        );

        // Read from second chunk
        let offset = chunk_size as i64;
        let size = 100u32;
        let partial_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, offset, size).unwrap();
        assert_eq!(
            partial_data,
            &test_data[offset as usize..offset as usize + size as usize],
            "Should read from second chunk correctly"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_across_chunk_boundary() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_boundary.txt");
        let chunk_size = crate::fs_impl::chunk_ops::get_chunk_size(&fs);

        // Create data that spans exactly 2 chunks
        let test_data = vec![0xCCu8; chunk_size * 2];

        // Write file (will be chunked)
        crate::fs_impl::file_write::write_file(&fs, file_path, &test_data).unwrap();

        // Read across chunk boundary
        let offset = (chunk_size - 50) as i64;
        let size = 100u32;
        let partial_data =
            crate::fs_impl::file_read::read_partial_chunked(&fs, file_path, offset, size).unwrap();

        let expected = &test_data[offset as usize..offset as usize + size as usize];
        assert_eq!(
            partial_data, expected,
            "Should correctly read across chunk boundary"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_read_multiple_times_consistency() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_read_consistency.txt");
        let test_data = b"Consistent test data that should be the same every time we read it.";

        // Write file
        crate::fs_impl::file_write::write_file(&fs, file_path, test_data).unwrap();

        // Read multiple times and verify consistency
        for _ in 0..5 {
            let read_data = crate::fs_impl::file_read::read_file(&fs, file_path).unwrap();
            assert_eq!(
                read_data, test_data,
                "Multiple reads should return consistent data"
            );
        }

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }
}
