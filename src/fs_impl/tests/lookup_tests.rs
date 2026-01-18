//! Tests for FUSE lookup() callback
//!
//! The lookup() callback is called to look up a directory entry by name
//! and get its attributes. In zthfs, this maps to getting/creating inodes
//! for file paths.

use std::path::Path;

/// Helper to create a test file at a given path in the real data directory
fn setup_test_file(fs: &crate::fs_impl::Zthfs, path: &Path) {
    let real_path = fs.data_dir().join(
        path.to_str()
            .unwrap()
            .strip_prefix('/')
            .unwrap_or(path.to_str().unwrap())
    );

    // Create parent directories if needed
    if let Some(parent) = real_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&real_path, b"test data").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_impl::tests::fuse_test_utils::create_test_fs;

    #[test]
    fn test_lookup_root_inode() {
        let (_temp_dir, fs) = create_test_fs();

        // Root directory should always be inode 1 (FUSE requirement)
        let root_inode = fs.get_or_create_inode(Path::new("/")).unwrap();
        assert_eq!(root_inode, 1, "Root directory must always be inode 1");

        // Multiple calls should always return the same inode
        let root_inode2 = fs.get_or_create_inode(Path::new("/")).unwrap();
        assert_eq!(root_inode, root_inode2, "Root inode should be consistent");
    }

    #[test]
    fn test_lookup_get_or_create_inode_existing_file() {
        let (_temp_dir, fs) = create_test_fs();

        // Setup: Create a test file in the data directory
        let test_path = Path::new("/test_file.txt");
        setup_test_file(&fs, test_path);

        // Get inode for the file
        let result = fs.get_or_create_inode(test_path);

        assert!(result.is_ok(), "Should successfully get inode for existing file");

        let inode = result.unwrap();
        assert!(inode > 1, "File inode should be greater than root (1)");

        // Verify we can get the same inode again (consistency)
        let result2 = fs.get_or_create_inode(test_path);
        assert!(result2.is_ok());
        assert_eq!(inode, result2.unwrap(), "Should get the same inode for the same path");
    }

    #[test]
    fn test_lookup_get_or_create_inode_new_file() {
        let (_temp_dir, fs) = create_test_fs();

        // Request inode for a path that doesn't exist yet
        let test_path = Path::new("/new_file.txt");
        let result = fs.get_or_create_inode(test_path);

        // This should succeed and allocate a new inode
        assert!(result.is_ok(), "get_or_create_inode should create new inode for new path");

        let inode = result.unwrap();
        assert!(inode > 1, "New file inode should be greater than root (1)");
    }

    #[test]
    fn test_lookup_get_path_for_inode_root() {
        let (_temp_dir, fs) = create_test_fs();

        // Root inode (1) should map to "/"
        let result = fs.get_path_for_inode(1);
        assert!(result.is_some(), "Root inode should return a path");

        let path = result.unwrap();
        assert_eq!(path, Path::new("/"), "Root inode should map to /");
    }

    #[test]
    fn test_lookup_get_path_for_invalid_inode() {
        let (_temp_dir, fs) = create_test_fs();

        // Nonexistent inode should return None
        let result = fs.get_path_for_inode(99999);
        assert!(result.is_none(), "Nonexistent inode should return None");
    }

    #[test]
    fn test_lookup_get_path_for_inode_roundtrip() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a file and get its inode
        let test_path = Path::new("/roundtrip_test.txt");
        setup_test_file(&fs, test_path);

        let inode = fs.get_or_create_inode(test_path).unwrap();

        // Now try to get the path back from the inode
        let retrieved_path = fs.get_path_for_inode(inode);
        assert!(
            retrieved_path.is_some(),
            "Should be able to retrieve path from inode"
        );

        // Note: The path might not match exactly due to how paths are stored
        // but we should get back some path
        assert!(retrieved_path.unwrap().to_string_lossy().contains("roundtrip_test"));
    }

    #[test]
    fn test_lookup_permission_authorized_user() {
        let (_temp_dir, fs) = create_test_fs();

        // Get current user's uid/gid
        let current_uid = unsafe { libc::getuid() };
        let current_gid = unsafe { libc::getgid() };

        // Current user should have permission (configured in create_test_fs)
        assert!(
            fs.check_permission(current_uid, current_gid),
            "Current user should have permission"
        );
    }

    #[test]
    fn test_lookup_permission_root_user() {
        let (_temp_dir, fs) = create_test_fs();

        // Root (uid=0) should always have access
        assert!(
            fs.check_permission(0, 0),
            "Root user should have permission"
        );
    }

    #[test]
    fn test_lookup_permission_unauthorized_user() {
        let (_temp_dir, fs) = create_test_fs();

        // Random user that's not in allowed_users should not have access
        let unauthorized_uid = 99999;
        let unauthorized_gid = 99999;

        assert!(
            !fs.check_permission(unauthorized_uid, unauthorized_gid),
            "Unauthorized user should not have permission"
        );
    }

    #[test]
    fn test_lookup_permission_authorized_group() {
        let (_temp_dir, fs) = create_test_fs();

        // Get current user's gid (which is in allowed_groups)
        let current_gid = unsafe { libc::getgid() };

        // A user with an authorized GID should have access
        assert!(
            fs.check_permission(99999, current_gid),
            "User with authorized GID should have permission"
        );
    }

    #[test]
    fn test_lookup_inode_allocation_sequential() {
        let (_temp_dir, fs) = create_test_fs();

        // Create multiple paths and verify inodes are different
        let path1 = Path::new("/file1.txt");
        let path2 = Path::new("/file2.txt");
        let path3 = Path::new("/file3.txt");

        let inode1 = fs.get_or_create_inode(path1).unwrap();
        let inode2 = fs.get_or_create_inode(path2).unwrap();
        let inode3 = fs.get_or_create_inode(path3).unwrap();

        // All inodes should be different (and greater than root)
        assert!(inode1 > 1);
        assert!(inode2 > 1);
        assert!(inode3 > 1);
        assert_ne!(inode1, inode2, "Different paths should have different inodes");
        assert_ne!(inode2, inode3, "Different paths should have different inodes");
        assert_ne!(inode1, inode3, "Different paths should have different inodes");
    }

    #[test]
    fn test_lookup_nested_path() {
        let (_temp_dir, fs) = create_test_fs();

        // Test nested path
        let nested_path = Path::new("/parent/child/grandchild.txt");
        setup_test_file(&fs, nested_path);

        let result = fs.get_or_create_inode(nested_path);
        assert!(result.is_ok(), "Should handle nested paths");

        let inode = result.unwrap();
        assert!(inode > 1, "Nested file should have valid inode");
    }

    #[test]
    fn test_lookup_inode_persistence() {
        let (_temp_dir, fs) = create_test_fs();

        // Get inode for a path
        let path1 = Path::new("/persistent.txt");
        let inode1 = fs.get_or_create_inode(path1).unwrap();

        // Get the same path again - should return the same inode
        let inode2 = fs.get_or_create_inode(path1).unwrap();

        assert_eq!(inode1, inode2, "Inode should be persistent for the same path");
    }
}
