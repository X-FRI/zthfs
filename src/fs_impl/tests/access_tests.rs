//! Tests for FUSE access() callback
//!
//! The access() callback is called to check if a file can be accessed
//! with the given permissions (read, write, execute). In zthfs, this maps
//! to permission checking against the allowed_users and allowed_groups lists.

#[cfg(test)]
mod tests {
    use crate::fs_impl::security::FileAccess;
    use crate::fs_impl::tests::fuse_test_utils::create_test_fs;

    /// Helper to create a test file at a given path in the real data directory
    fn setup_test_file(fs: &crate::fs_impl::Zthfs, path: &std::path::Path) {
        let real_path = fs.data_dir().join(
            path.to_str()
                .unwrap()
                .strip_prefix('/')
                .unwrap_or(path.to_str().unwrap()),
        );

        // Create parent directories if needed
        if let Some(parent) = real_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&real_path, b"test data").unwrap();
    }

    #[test]
    fn test_access_authorized_user() {
        let (_temp_dir, fs) = create_test_fs();

        // Current user should have access
        // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
        // succeed and return valid uid_t/gid_t values. They have no preconditions.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        assert!(
            fs.check_permission(uid, gid),
            "Current user should have permission"
        );
    }

    #[test]
    fn test_access_unauthorized_user() {
        let (_temp_dir, fs) = create_test_fs();

        // Random user should not have access
        assert!(
            !fs.check_permission(99999, 99999),
            "Unauthorized user should not have permission"
        );
    }

    #[test]
    fn test_access_root_always_authorized() {
        let (_temp_dir, fs) = create_test_fs();

        // Root (uid=0) should always have access in current implementation
        assert!(fs.check_permission(0, 0), "Root should have permission");
    }

    #[test]
    fn test_access_group_authorized() {
        let (_temp_dir, fs) = create_test_fs();

        // SAFETY: getgid() is an async-signal-safe libc function that always succeeds
        // and returns a valid gid_t value. It has no preconditions.
        let gid = unsafe { libc::getgid() };

        // User in allowed group should have access
        assert!(
            fs.check_permission(99999, gid),
            "User with authorized GID should have permission"
        );
    }

    #[test]
    fn test_access_read_mask() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file to get file attributes
        let test_path = std::path::Path::new("/test_read_file.txt");
        setup_test_file(&fs, test_path);

        // Get file attributes for the test file
        let file_attr = match fs.get_path_for_inode(fs.get_or_create_inode(test_path).unwrap()) {
            Some(_) => {
                // Use get_attr through the filesystem's attr_ops module
                // For this test, we'll use check_permission which returns true for authorized users
                None
            }
            None => None,
        };

        // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
        // succeed and return valid uid_t/gid_t values. They have no preconditions.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Test R_OK access mask (4) - Current implementation allows all for authorized users
        let has_access = fs.check_file_access(uid, gid, FileAccess::Read, file_attr.as_ref());

        assert!(has_access, "Authorized user should have read access");
    }

    #[test]
    fn test_access_write_mask() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file to get file attributes
        let test_path = std::path::Path::new("/test_write_file.txt");
        setup_test_file(&fs, test_path);

        // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
        // succeed and return valid uid_t/gid_t values. They have no preconditions.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Test W_OK access mask (2)
        let has_access = fs.check_file_access(uid, gid, FileAccess::Write, None);

        assert!(has_access, "Authorized user should have write access");
    }

    #[test]
    fn test_access_execute_mask() {
        let (_temp_dir, fs) = create_test_fs();

        // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
        // succeed and return valid uid_t/gid_t values. They have no preconditions.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // Test X_OK access mask (1)
        let has_access = fs.check_file_access(uid, gid, FileAccess::Execute, None);

        assert!(has_access, "Authorized user should have execute access");
    }

    #[test]
    fn test_access_unauthorized_user_read_denied() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = std::path::Path::new("/test_unauthorized.txt");
        setup_test_file(&fs, test_path);

        // Unauthorized user should not have access
        let has_access = fs.check_file_access(99999, 99999, FileAccess::Read, None);

        assert!(!has_access, "Unauthorized user should not have read access");
    }

    #[test]
    fn test_access_unauthorized_user_write_denied() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = std::path::Path::new("/test_unauthorized_write.txt");
        setup_test_file(&fs, test_path);

        // Unauthorized user should not have write access
        let has_access = fs.check_file_access(99999, 99999, FileAccess::Write, None);

        assert!(
            !has_access,
            "Unauthorized user should not have write access"
        );
    }

    #[test]
    fn test_access_unauthorized_user_execute_denied() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a test file
        let test_path = std::path::Path::new("/test_unauthorized_execute.txt");
        setup_test_file(&fs, test_path);

        // Unauthorized user should not have execute access
        let has_access = fs.check_file_access(99999, 99999, FileAccess::Execute, None);

        assert!(
            !has_access,
            "Unauthorized user should not have execute access"
        );
    }

    #[test]
    fn test_access_root_has_all_permissions() {
        let (_temp_dir, fs) = create_test_fs();

        // Root should have all types of access
        assert!(
            fs.check_file_access(0, 0, FileAccess::Read, None),
            "Root should have read access"
        );
        assert!(
            fs.check_file_access(0, 0, FileAccess::Write, None),
            "Root should have write access"
        );
        assert!(
            fs.check_file_access(0, 0, FileAccess::Execute, None),
            "Root should have execute access"
        );
    }

    #[test]
    fn test_access_fallback_to_basic_permission() {
        let (_temp_dir, fs) = create_test_fs();

        // SAFETY: getuid() and getgid() are async-signal-safe libc functions that always
        // succeed and return valid uid_t/gid_t values. They have no preconditions.
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        // When file_attr is None, check_file_access falls back to check_permission
        // Current user should pass the fallback check
        assert!(
            fs.check_file_access(uid, gid, FileAccess::Read, None),
            "Should fallback to basic permission check when file_attr is None"
        );
    }
}
