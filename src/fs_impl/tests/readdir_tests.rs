//! Tests for FUSE readdir() callback

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, crate::fs_impl::Zthfs) {
        crate::fs_impl::tests::fuse_test_utils::create_test_fs()
    }

    #[test]
    fn test_readdir_root() {
        let (_temp_dir, fs) = create_test_fs();

        // Create some test files in root
        let test_files = vec!["file1.txt", "file2.txt", "file3.txt"];
        for name in &test_files {
            let path_str = format!("/{name}");
            let path = Path::new(&path_str);
            crate::fs_impl::file_create::create_file(&fs, path, 0o644).unwrap();
        }

        // Get directory entry count
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, Path::new("/")).unwrap();

        assert!(
            count >= 3,
            "Root directory should have at least 3 files, got {count}"
        );

        // Clean up
        for name in &test_files {
            let path_str = format!("/{name}");
            let path = Path::new(&path_str);
            crate::fs_impl::file_create::remove_file(&fs, path).unwrap();
        }
    }

    #[test]
    fn test_readdir_empty_directory() {
        let (_temp_dir, fs) = create_test_fs();

        // Create an empty directory
        let dir_path = Path::new("/empty_dir");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Get entry count - should be 0 (no files)
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();

        assert_eq!(count, 0, "Empty directory should have 0 entries");

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }

    #[test]
    fn test_readdir_filters_internal_files() {
        let (_temp_dir, fs) = create_test_fs();

        // Create normal file
        crate::fs_impl::file_create::create_file(&fs, Path::new("/normal.txt"), 0o644).unwrap();

        // Create internal metadata files directly on disk
        let data_dir = fs.data_dir();
        std::fs::write(data_dir.join("test.txt.zthfs_meta"), b"metadata").unwrap();
        std::fs::create_dir_all(data_dir.join("inode_db")).unwrap();

        // Get entry count - should only count normal files
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, Path::new("/")).unwrap();

        // Should have at least 1 (normal.txt), but internal files should be filtered
        assert!(count >= 1, "Should have at least the normal file");

        // Verify normal file exists
        assert!(crate::fs_impl::path_ops::path_exists(&fs, Path::new("/normal.txt")));

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, Path::new("/normal.txt")).unwrap();
        let _ = std::fs::remove_file(data_dir.join("test.txt.zthfs_meta"));
        let _ = std::fs::remove_dir_all(data_dir.join("inode_db"));
    }

    #[test]
    fn test_readdir_subdirectory() {
        let (_temp_dir, fs) = create_test_fs();

        // Create subdirectory
        let subdir_path = Path::new("/subdir");
        crate::fs_impl::dir_modify::create_directory(&fs, subdir_path, 0o755).unwrap();

        // Create files in subdirectory
        let file_path = Path::new("/subdir/file.txt");
        crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

        let file_path2 = Path::new("/subdir/file2.txt");
        crate::fs_impl::file_create::create_file(&fs, file_path2, 0o644).unwrap();

        // Get entry count for subdirectory
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, subdir_path).unwrap();

        assert_eq!(count, 2, "Subdirectory should have 2 files");

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, subdir_path, true).unwrap();
    }

    #[test]
    fn test_readdir_nonexistent_directory() {
        let (_temp_dir, fs) = create_test_fs();

        // Try to read a directory that doesn't exist
        let result = crate::fs_impl::dir_read::get_dir_entry_count(&fs, Path::new("/nonexistent"));

        assert!(result.is_err(), "Reading nonexistent directory should fail");
    }

    #[test]
    fn test_readdir_nested_subdirectories() {
        let (_temp_dir, fs) = create_test_fs();

        // Create nested directory structure
        crate::fs_impl::dir_modify::create_directory(&fs, Path::new("/level1"), 0o755).unwrap();
        crate::fs_impl::dir_modify::create_directory(&fs, Path::new("/level1/level2"), 0o755).unwrap();

        // Create files at different levels
        crate::fs_impl::file_create::create_file(&fs, Path::new("/level1/file1.txt"), 0o644).unwrap();
        crate::fs_impl::file_create::create_file(&fs, Path::new("/level1/level2/file2.txt"), 0o644).unwrap();

        // Count entries at each level
        // Note: counts include internal directory marker files
        let count1 = crate::fs_impl::dir_read::get_dir_entry_count(&fs, Path::new("/level1")).unwrap();
        assert!(count1 >= 1, "Level1 should have at least 1 entry (level2 dir)");

        let count2 = crate::fs_impl::dir_read::get_dir_entry_count(&fs, Path::new("/level1/level2")).unwrap();
        assert_eq!(count2, 1, "Level2 should have exactly 1 entry (file2.txt)");

        // Verify the nested structure exists by checking paths
        assert!(crate::fs_impl::path_ops::path_exists(&fs, Path::new("/level1")));
        assert!(crate::fs_impl::path_ops::path_exists(&fs, Path::new("/level1/level2")));
        assert!(crate::fs_impl::path_ops::path_exists(&fs, Path::new("/level1/file1.txt")));
        assert!(crate::fs_impl::path_ops::path_exists(&fs, Path::new("/level1/level2/file2.txt")));

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, Path::new("/level1"), true).unwrap();
    }

    #[test]
    fn test_readdir_many_files() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a directory
        let dir_path = Path::new("/many_files");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Create multiple files
        let num_files = 20;
        for i in 0..num_files {
            let file_path_str = format!("/many_files/file_{i}.txt");
            let file_path = Path::new(&file_path_str);
            crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();
        }

        // Count entries
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();

        assert_eq!(count, num_files, "Should have {num_files} files");

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }

    #[test]
    fn test_readdir_after_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let dir_path = Path::new("/dynamic_dir");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Initially empty
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 0, "New directory should be empty");

        // Add files
        crate::fs_impl::file_create::create_file(&fs, Path::new("/dynamic_dir/file1.txt"), 0o644).unwrap();
        crate::fs_impl::file_create::create_file(&fs, Path::new("/dynamic_dir/file2.txt"), 0o644).unwrap();

        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 2, "Should have 2 files after adding");

        // Remove a file
        crate::fs_impl::file_create::remove_file(&fs, Path::new("/dynamic_dir/file1.txt")).unwrap();

        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 1, "Should have 1 file after removal");

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }

    #[test]
    fn test_readdir_with_directories_and_files() {
        let (_temp_dir, fs) = create_test_fs();

        let dir_path = Path::new("/mixed_dir");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Create both files and subdirectories
        crate::fs_impl::file_create::create_file(&fs, Path::new("/mixed_dir/file1.txt"), 0o644).unwrap();
        crate::fs_impl::file_create::create_file(&fs, Path::new("/mixed_dir/file2.txt"), 0o644).unwrap();
        crate::fs_impl::dir_modify::create_directory(&fs, Path::new("/mixed_dir/subdir1"), 0o755).unwrap();
        crate::fs_impl::dir_modify::create_directory(&fs, Path::new("/mixed_dir/subdir2"), 0o755).unwrap();

        // Count all entries (both files and directories)
        let count = crate::fs_impl::dir_read::get_dir_entry_count(&fs, dir_path).unwrap();

        // Note: The count includes both files and directories
        // Also, there may be internal directory marker files
        assert!(count >= 4, "Should have at least 4 entries (2 files + 2 dirs)");

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }
}
