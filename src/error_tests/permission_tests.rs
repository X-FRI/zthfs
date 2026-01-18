//! Permission denied error tests
//!
//! Tests various permission denial scenarios in the filesystem.
//! These tests verify that the filesystem correctly handles unauthorized access attempts.

use crate::config::{EncryptionConfig, FilesystemConfigBuilder, LogConfig, SecurityConfig};
use crate::fs_impl::Zthfs;
use crate::fs_impl::security::{FileAccess, SecurityValidator};
use tempfile::TempDir;

/// Helper to create a test filesystem with specific security config
fn create_fs_with_security(security: SecurityConfig) -> (TempDir, Zthfs) {
    let temp_dir = TempDir::new().unwrap();

    let config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .encryption(EncryptionConfig::with_random_keys())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .security(security)
        .build()
        .unwrap();

    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}

#[test]
fn test_unauthorized_user_access() {
    // Test that a user not in allowed_users is denied access
    let security = SecurityConfig {
        allowed_users: vec![1000, 1001], // Only users 1000 and 1001 allowed
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let (_temp_dir, fs) = create_fs_with_security(security);

    // User 9999 is not in allowed_users or allowed_groups
    assert!(!fs.check_permission(9999, 9999));

    // User 2000 is not in allowed list
    assert!(!fs.check_permission(2000, 2000));

    // But user 1000 should have access
    assert!(fs.check_permission(1000, 1000));

    // User 1001 should also have access
    assert!(fs.check_permission(1001, 1001));
}

#[test]
fn test_unauthorized_group_access() {
    // Test that a user with unauthorized group is denied access
    let security = SecurityConfig {
        allowed_users: vec![1000],  // Only user 1000 allowed
        allowed_groups: vec![1000], // Only group 1000 allowed
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let (_temp_dir, fs) = create_fs_with_security(security);

    // User 2000 with group 2000 - neither user nor group is allowed
    assert!(!fs.check_permission(2000, 2000));

    // User 2000 even with group 1000 - user is not allowed, group is
    // The check allows either user OR group, so this should pass
    assert!(fs.check_permission(2000, 1000));

    // User 1000 with group 2000 - user is allowed
    assert!(fs.check_permission(1000, 2000));
}

#[test]
fn test_empty_allowed_users() {
    // Test behavior when allowed_users is empty
    let security = SecurityConfig {
        allowed_users: vec![],      // No users explicitly allowed
        allowed_groups: vec![1000], // But group 1000 is allowed
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let (_temp_dir, fs) = create_fs_with_security(security);

    // User 1000 is not in allowed_users but group 1000 is in allowed_groups
    assert!(fs.check_permission(1000, 1000));

    // User with group 1000 should have access
    assert!(fs.check_permission(9999, 1000));

    // User with different group should be denied
    assert!(!fs.check_permission(9999, 9999));
}

#[test]
fn test_file_access_without_attributes() {
    // Test fallback permission check when file attributes are not available
    let security = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let (_temp_dir, fs) = create_fs_with_security(security);

    // When no file attributes are provided, check_file_access falls back
    // to check_permission (basic user/group check)
    let allowed = fs.check_file_access(1000, 1000, FileAccess::Read, None);
    assert!(allowed, "User 1000 should have access");

    let not_allowed = fs.check_file_access(2000, 2000, FileAccess::Read, None);
    assert!(!not_allowed, "User 2000 should not have access");
}

#[test]
fn test_security_validator_unauthorized_user() {
    // Test SecurityValidator directly for unauthorized user access
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 is not in allowed_users
    // Even with permissive file permissions (0o777), should be denied
    assert!(!validator.check_file_permission(
        2000,  // user_uid
        2000,  // user_gid
        1000,  // file_uid
        1000,  // file_gid
        0o777, // file_mode (all permissions)
        FileAccess::Read,
        None, // no file path
    ));

    // Same for write access
    assert!(!validator.check_file_permission(
        2000,
        2000,
        1000,
        1000,
        0o777,
        FileAccess::Write,
        None,
    ));
}

#[test]
fn test_security_validator_unauthorized_group() {
    // Test SecurityValidator for unauthorized group access
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![1000], // Only group 1000 allowed
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 with group 2000 - group is not in allowed_groups
    assert!(!validator.check_file_permission(
        2000,
        2000,
        1000,
        1000,
        0o777,
        FileAccess::Read,
        None,
    ));
}

#[test]
fn test_zero_trust_root_denied_without_permissions() {
    // Test that in zero-trust mode, root is denied if not in allowed_users
    let config = SecurityConfig {
        allowed_users: vec![1000], // Root NOT included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config); // Default is zero-trust

    // Root (uid=0) is NOT in allowed_users, so should be denied
    // even with permissive file permissions
    assert!(!validator.check_file_permission(0, 0, 1000, 1000, 0o777, FileAccess::Read, None,));
}

#[test]
fn test_zero_trust_root_with_permissions() {
    // Test that in zero-trust mode, root must have proper file permissions
    let config = SecurityConfig {
        allowed_users: vec![0, 1000], // Root IS included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config); // Zero-trust mode

    // File with no permissions - root should be denied in zero-trust mode
    assert!(!validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Read, None,));

    // With proper permissions, root can access
    assert!(validator.check_file_permission(0, 0, 1000, 1000, 0o644, FileAccess::Read, None,));
}

#[test]
fn test_legacy_root_bypass() {
    // Test that in legacy mode, root bypasses file permission checks
    let config = SecurityConfig {
        allowed_users: vec![0, 1000], // Root IS included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::with_legacy_root(config);

    // In legacy mode, root bypasses all file permissions
    assert!(validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Read, None,));

    assert!(validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Write, None,));

    assert!(validator.check_file_permission(0, 0, 1000, 1000, 0o000, FileAccess::Execute, None,));
}

#[test]
fn test_permission_denied_all_operations() {
    // Test that unauthorized users are denied for all operation types
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 is not authorized
    let operations = vec![FileAccess::Read, FileAccess::Write, FileAccess::Execute];

    for op in operations {
        assert!(
            !validator.check_file_permission(2000, 2000, 1000, 1000, 0o644, op, None),
            "User 2000 should be denied for {:?}",
            op
        );
    }
}

#[test]
fn test_authorized_user_with_insufficient_file_permissions() {
    // Test that even authorized users respect file permissions
    let config = SecurityConfig {
        allowed_users: vec![1000, 2000], // Both users authorized
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 is authorized, but file is owned by user 1000 with mode 0o600
    // User 2000 is "other" (not owner, not in group 1000)
    // Mode 0o600 = rw------- (owner: rw, group: ---, other: ---)
    assert!(!validator.check_file_permission(
        2000,
        2000,
        1000,
        1000,
        0o600,
        FileAccess::Read,
        None,
    ));

    assert!(!validator.check_file_permission(
        2000,
        2000,
        1000,
        1000,
        0o600,
        FileAccess::Write,
        None,
    ));
}
