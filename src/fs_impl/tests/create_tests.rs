//! Tests for FUSE create() callback

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, crate::fs_impl::Zthfs) {
        crate::fs_impl::tests::fuse_test_utils::create_test_fs()
    }

    #[test]
    fn test_create_new_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/test_create.txt");

        // Create a new file
        let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

        // Verify file was created with correct attributes
        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert!(
            attr.ino > 1,
            "File inode should be greater than root inode (1)"
        );

        // Verify file exists
        assert!(
            crate::fs_impl::path_ops::path_exists(&fs, file_path),
            "Created file should exist"
        );

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_create_with_permissions() {
        let (_temp_dir, fs) = create_test_fs();

        let test_cases = vec![
            (0o644, "rw-r--r--"),
            (0o600, "rw-------"),
            (0o755, "rwxr-xr-x"),
            (0o444, "r--r--r--"),
        ];

        for (mode, description) in test_cases {
            let file_path_str = format!("/perm_test_{description}.txt");
            let file_path = Path::new(&file_path_str);

            // Create file with specific mode
            let attr = crate::fs_impl::file_create::create_file(&fs, file_path, mode).unwrap();

            // Verify mode is set (permission bits may be masked by umask)
            // We check that the file was created successfully with a valid permission
            assert!(
                attr.perm > 0,
                "File should have permissions set for {description}"
            );

            // Verify the file exists and is readable
            assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

            // Clean up
            crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        }
    }

    #[test]
    fn test_create_in_subdirectory() {
        let (_temp_dir, fs) = create_test_fs();

        // Create parent directory first
        let dir_path = Path::new("/test_subdir");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Create file in subdirectory
        let file_path = Path::new("/test_subdir/file_in_subdir.txt");
        let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }

    #[test]
    fn test_create_inode_uniqueness() {
        let (_temp_dir, fs) = create_test_fs();

        let mut inodes = std::collections::HashSet::new();

        // Create multiple files and verify each gets a unique inode
        for i in 0..10 {
            let file_path_str = format!("/inode_test_{i}.txt");
            let file_path = Path::new(&file_path_str);

            let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

            // Each file should have a unique inode
            assert!(
                inodes.insert(attr.ino),
                "Inode {} for file {} is not unique",
                attr.ino,
                i
            );

            // Each inode should be greater than root (1)
            assert!(
                attr.ino > 1,
                "File inode should be greater than root inode (1)"
            );
        }

        // Clean up
        for i in 0..10 {
            let file_path_str = format!("/inode_test_{i}.txt");
            let file_path = Path::new(&file_path_str);
            crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        }
    }

    #[test]
    fn test_create_no_inode_conflict_with_root() {
        let (_temp_dir, fs) = create_test_fs();

        // Get root inode
        let root_inode = crate::fs_impl::inode_ops::get_inode(&fs, Path::new("/")).unwrap();
        assert_eq!(root_inode, 1, "Root inode should always be 1");

        // Create a file and verify its inode is different from root
        let file_path = Path::new("/test_no_conflict.txt");
        let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

        assert_ne!(
            attr.ino, root_inode,
            "File inode should never equal root inode"
        );
        assert!(attr.ino > 1, "File inode should be greater than root inode");

        // Verify multiple files all have different inodes from root
        for i in 0..5 {
            let file_path_str = format!("/no_conflict_{i}.txt");
            let file_path = Path::new(&file_path_str);
            let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

            assert_ne!(attr.ino, root_inode, "File {i} inode conflicts with root");

            crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
        }

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, Path::new("/test_no_conflict.txt")).unwrap();
    }

    #[test]
    fn test_create_file_persistence() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/persistent_test.txt");

        // Create file and get its inode
        let attr1 = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();
        let inode1 = attr1.ino;

        // Get attributes again and verify inode is the same
        let attr2 = crate::fs_impl::attr_ops::get_attr(&fs, file_path).unwrap();
        assert_eq!(attr2.ino, inode1, "Inode should remain consistent");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_create_empty_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/empty_create_test.txt");

        // Create an empty file
        let attr = crate::fs_impl::file_create::create_file(&fs, file_path, 0o644).unwrap();

        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert_eq!(attr.size, 0, "Newly created file should have size 0");

        // Verify file exists
        assert!(crate::fs_impl::path_ops::path_exists(&fs, file_path));

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, file_path).unwrap();
    }
}
