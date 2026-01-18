//! Tests for FUSE getattr() callback
//!
//! The getattr() callback retrieves file attributes (size, mode, uid, gid, etc.).
//! In zthfs, this is handled by the attr_ops module.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::fs_impl::tests::fuse_test_utils::create_test_fs;

    /// Helper to create a test file at a given path in the real data directory
    fn setup_test_file(fs: &crate::fs_impl::Zthfs, path: &Path) {
        let real_path = fs.data_dir().join(
            path.to_str()
                .unwrap()
                .strip_prefix('/')
                .unwrap_or(path.to_str().unwrap()),
        );

        // Create parent directories if needed
        if let Some(parent) = real_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&real_path, b"test data").unwrap();
    }

    #[test]
    fn test_getattr_existing_file() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = Path::new("/test_attr.txt");
        let real_path = fs.data_dir().join("test_attr.txt");
        fs::write(&real_path, b"test data").unwrap();

        // Get attributes through attr_ops::get_attr
        let result = crate::fs_impl::attr_ops::get_attr(&fs, test_path);

        assert!(
            result.is_ok(),
            "Should get attributes for existing file: {:?}",
            result
        );

        let attr = result.unwrap();
        // For non-chunked files, size is the actual file size (9 bytes for "test data")
        assert_eq!(attr.size, 9, "File size should match");
        assert!(attr.ino > 1, "Inode should be greater than root");
        assert_eq!(
            attr.kind,
            fuser::FileType::RegularFile,
            "Should be regular file"
        );
    }

    #[test]
    fn test_getattr_nonexistent_file() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/nonexistent.txt");

        let result = crate::fs_impl::attr_ops::get_attr(&fs, test_path);

        assert!(
            result.is_err(),
            "Should return error for nonexistent file: {:?}",
            result
        );
    }

    #[test]
    fn test_getattr_directory() {
        let (_temp_dir, fs) = create_test_fs();

        // Test root directory
        let result = crate::fs_impl::attr_ops::get_attr(&fs, Path::new("/"));

        assert!(
            result.is_ok(),
            "Should get attributes for root directory: {:?}",
            result
        );

        let attr = result.unwrap();
        assert_eq!(attr.ino, 1, "Root directory should have inode 1");
        assert_eq!(
            attr.kind,
            fuser::FileType::Directory,
            "Should be directory type"
        );
    }

    #[test]
    fn test_getattr_permission_denied() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a file
        let test_path = Path::new("/test_perm.txt");
        let real_path = fs.data_dir().join("test_perm.txt");
        fs::write(&real_path, b"data").unwrap();

        // Note: Current implementation doesn't enforce per-file permissions
        // This test documents current behavior
        // TODO: Update when per-file permission checking is implemented
        let result = crate::fs_impl::attr_ops::get_attr(&fs, test_path);
        assert!(
            result.is_ok(),
            "Current implementation allows all access to authorized users"
        );
    }

    #[test]
    fn test_getattr_file_attributes() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = Path::new("/test_attrs.txt");
        setup_test_file(&fs, test_path);

        let attr = crate::fs_impl::attr_ops::get_attr(&fs, test_path).unwrap();

        // Verify basic file attributes
        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert_eq!(attr.nlink, 1, "Regular file should have 1 link");
        assert_eq!(attr.rdev, 0, "Regular file should have rdev 0");
        assert_eq!(attr.blksize, 4096, "Block size should be 4096");
        assert_eq!(attr.flags, 0, "Flags should be 0");

        // Verify inode is consistent
        let inode = crate::fs_impl::inode_ops::get_inode(&fs, test_path).unwrap();
        assert_eq!(attr.ino, inode, "Inode should match");
    }

    #[test]
    fn test_getattr_nested_directory() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a nested directory structure
        let nested_path = Path::new("/parent/child");
        let real_path = fs.data_dir().join("parent/child");
        fs::create_dir_all(&real_path).unwrap();

        // Get attributes for the nested directory
        let result = crate::fs_impl::attr_ops::get_attr(&fs, nested_path);

        assert!(
            result.is_ok(),
            "Should get attributes for nested directory: {:?}",
            result
        );

        let attr = result.unwrap();
        assert_eq!(
            attr.kind,
            fuser::FileType::Directory,
            "Should be directory type"
        );
        assert!(attr.ino > 1, "Nested directory should have valid inode");
    }

    #[test]
    fn test_getattr_consistency() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = Path::new("/test_consistency.txt");
        setup_test_file(&fs, test_path);

        // Get attributes multiple times
        let attr1 = crate::fs_impl::attr_ops::get_attr(&fs, test_path).unwrap();
        let attr2 = crate::fs_impl::attr_ops::get_attr(&fs, test_path).unwrap();
        let attr3 = crate::fs_impl::attr_ops::get_attr(&fs, test_path).unwrap();

        // All attributes should be consistent
        assert_eq!(attr1.ino, attr2.ino, "Inode should be consistent");
        assert_eq!(attr2.ino, attr3.ino, "Inode should be consistent");
        assert_eq!(attr1.size, attr2.size, "Size should be consistent");
        assert_eq!(attr2.size, attr3.size, "Size should be consistent");
        assert_eq!(attr1.kind, attr2.kind, "File type should be consistent");
        assert_eq!(attr2.kind, attr3.kind, "File type should be consistent");
    }

    #[test]
    fn test_getattr_root_always_inode_one() {
        let (_temp_dir, fs) = create_test_fs();

        // Root directory should always have inode 1 (FUSE requirement)
        let attr = crate::fs_impl::attr_ops::get_attr(&fs, Path::new("/")).unwrap();
        assert_eq!(attr.ino, 1, "Root directory must always be inode 1");
    }

    #[test]
    fn test_getattr_different_files_different_inodes() {
        let (_temp_dir, fs) = create_test_fs();

        // Create multiple files
        let path1 = Path::new("/file1.txt");
        let path2 = Path::new("/file2.txt");
        let path3 = Path::new("/file3.txt");

        setup_test_file(&fs, path1);
        setup_test_file(&fs, path2);
        setup_test_file(&fs, path3);

        // Get attributes for each file
        let attr1 = crate::fs_impl::attr_ops::get_attr(&fs, path1).unwrap();
        let attr2 = crate::fs_impl::attr_ops::get_attr(&fs, path2).unwrap();
        let attr3 = crate::fs_impl::attr_ops::get_attr(&fs, path3).unwrap();

        // All inodes should be different (and greater than root)
        assert!(attr1.ino > 1);
        assert!(attr2.ino > 1);
        assert!(attr3.ino > 1);
        assert_ne!(
            attr1.ino, attr2.ino,
            "Different files should have different inodes"
        );
        assert_ne!(
            attr2.ino, attr3.ino,
            "Different files should have different inodes"
        );
        assert_ne!(
            attr1.ino, attr3.ino,
            "Different files should have different inodes"
        );
    }
}
