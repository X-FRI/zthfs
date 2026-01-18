//! Access control security tests.
//!
//! These tests verify the security properties of access control:
//! - Zero-trust mode: root has no special privileges
//! - Legacy mode: root bypasses permission checks
//! - POSIX permission enforcement (read-only, group, world)
//! - Authorization based on allowed_users/allowed_groups lists

use crate::config::SecurityConfig;
use crate::fs_impl::security::{FileAccess, SecurityValidator};

/// Test that in zero-trust mode, root has no special privileges.
///
/// Zero-trust is the default and recommended mode for production.
/// Root must be explicitly allowed and still must pass file permission checks.
#[test]
fn test_zero_trust_root_no_special_privileges() {
    // SAFETY: Configure zero-trust mode with root NOT in allowed list.
    let config = SecurityConfig {
        allowed_users: vec![1000], // Root NOT included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    // SecurityValidator::new() defaults to zero-trust mode
    let validator = SecurityValidator::new(config);

    // Root (uid=0) should NOT bypass permission check in zero-trust mode
    // File owned by user 1000 with no permissions
    let result = validator.check_file_permission_legacy(
        0,      // root uid
        0,      // root gid
        1000,   // file owner
        1000,   // file group
        0o000,  // no permissions
        FileAccess::Read,
    );

    // SAFETY: Root should be denied in zero-trust mode when not in allowed_users
    assert!(!result, "Root should be denied in zero-trust mode when not in allowed list");

    // Even with permissive file permissions, root should be denied if not in allowed list
    let result2 = validator.check_file_permission_legacy(
        0, 0, 1000, 1000, 0o777, FileAccess::Read,
    );
    assert!(!result2, "Root should be denied if not in allowed_users, even with 0o777");
}

/// Test that legacy mode grants root special privileges.
///
/// WARNING: Legacy mode violates zero-trust principles and is only
/// for backward compatibility.
#[test]
fn test_legacy_root_has_privileges() {
    // SAFETY: Configure legacy mode with root explicitly allowed.
    let config = SecurityConfig {
        allowed_users: vec![0, 1000], // Root IS included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    // Use with_legacy_root for legacy mode
    let validator = SecurityValidator::with_legacy_root(config);

    // Verify root bypass is enabled
    assert!(
        validator.is_root_bypass_enabled(),
        "Legacy mode should have root bypass enabled"
    );

    // In legacy mode, root bypasses all file permission checks
    let result = validator.check_file_permission_legacy(
        0,      // root uid
        0,      // root gid
        1000,   // file owner (not root)
        1000,   // file group (not root)
        0o000,  // no permissions at all
        FileAccess::Read,
    );

    assert!(result, "Root should bypass permission checks in legacy mode");

    // Test write and execute as well
    assert!(
        validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Write),
        "Root should bypass write permission checks in legacy mode"
    );

    assert!(
        validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Execute),
        "Root should bypass execute permission checks in legacy mode"
    );
}

/// Test read-only file permission enforcement.
///
/// Files with read-only permissions should reject write access.
#[test]
fn test_access_mask_read_only() {
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    let file_mode = 0o444; // Read-only: r--r--r--

    // User 1000 owns the file
    // Check read access - should succeed
    let can_read = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Read,
    );
    assert!(can_read, "Owner should have read access on 0o444 file");

    // Check write access - should fail
    let can_write = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Write,
    );
    assert!(!can_write, "Owner should NOT have write access on 0o444 file");

    // Check execute access - should fail
    let can_execute = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Execute,
    );
    assert!(!can_execute, "Owner should NOT have execute access on 0o444 file");
}

/// Test group-based access control.
///
/// Users in the file's group should get group permissions.
#[test]
fn test_group_access_control() {
    let config = SecurityConfig {
        allowed_users: vec![1000, 1001],
        allowed_groups: vec![1000, 2000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // File with group read-only permissions
    let file_mode = 0o040; // -----r--- (group can only read)

    // User 1001 is in group 1000, file is owned by user 1000:1000
    let can_read = validator.check_file_permission_legacy(
        1001,   // user uid (not owner)
        1000,   // user gid (matches file group)
        1000,   // file owner uid
        1000,   // file group gid
        file_mode,
        FileAccess::Read,
    );
    assert!(can_read, "User in file's group should have group read access");

    let can_write = validator.check_file_permission_legacy(
        1001, 1000, 1000, 1000, file_mode, FileAccess::Write,
    );
    assert!(!can_write, "User in file's group should NOT have write when group perms are 0o040");

    // User 2000 is NOT in group 1000, should not get group permissions
    let cannot_read = validator.check_file_permission_legacy(
        2000,   // user uid (not owner)
        2000,   // user gid (not file group)
        1000,   // file owner uid
        1000,   // file group gid
        file_mode,
        FileAccess::Read,
    );
    assert!(!cannot_read, "User not in file's group should not get group access");
}

/// Test that users with no permissions are denied access.
///
/// "World" permissions (other bits) control access for users who
/// are neither the owner nor in the file's group.
#[test]
fn test_world_access_denied() {
    let config = SecurityConfig {
        allowed_users: vec![1000, 2000],
        allowed_groups: vec![1000, 2000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // File with no world permissions
    let file_mode = 0o600; // rw------- (owner only, no group or world access)

    // User 2000 is NOT the owner (1000) and NOT in group 1000
    // So they get "other" permissions, which are 0
    let no_read = validator.check_file_permission_legacy(
        2000,   // user uid (not owner)
        2000,   // user gid (not file group)
        1000,   // file owner uid
        1000,   // file group gid
        file_mode,
        FileAccess::Read,
    );
    assert!(!no_read, "User with no matching permissions should be denied read");

    let no_write = validator.check_file_permission_legacy(
        2000, 2000, 1000, 1000, file_mode, FileAccess::Write,
    );
    assert!(!no_write, "User with no matching permissions should be denied write");

    let no_execute = validator.check_file_permission_legacy(
        2000, 2000, 1000, 1000, file_mode, FileAccess::Execute,
    );
    assert!(!no_execute, "User with no matching permissions should be denied execute");
}

/// Test that the owner permission bits take precedence.
///
/// POSIX specifies that owner permissions override group permissions,
/// even if the user is also in the file's group.
#[test]
fn test_owner_permission_precedence() {
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // File where owner has no write, but group does
    let file_mode = 0o470; // rwxrwx--- (owner: r--, group: rwx, other: ---)
                          // Actually in octal: 4 (r) 7 (rwx) 0 (---)
    // Wait, let me recalculate:
    // 0o470 = 0b100_111_000
    // Owner: r-- (4)
    // Group: rwx (7)
    // Other: --- (0)

    // User 1000 owns the file and is in group 1000
    // Owner permissions should apply (read only)
    let can_read = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Read,
    );
    assert!(can_read, "Owner should have read access");

    let cannot_write = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Write,
    );
    assert!(!cannot_write, "Owner permissions should override group permissions");

    let cannot_execute = validator.check_file_permission_legacy(
        1000, 1000, 1000, 1000, file_mode, FileAccess::Execute,
    );
    assert!(!cannot_execute, "Owner permissions should override group permissions");
}

/// test that users not in allowed_users are denied even with file permissions.
///
/// This is filesystem-level access control before file permissions are checked.
#[test]
fn test_allowed_users_enforcement() {
    let config = SecurityConfig {
        allowed_users: vec![1000],    // Only user 1000 allowed
        allowed_groups: vec![],       // No groups allowed
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 is NOT in allowed_users, even though file has 0o777 permissions
    let file_mode = 0o777; // All permissions for everyone

    let denied_read = validator.check_file_permission_legacy(
        2000, 2000, 2000, 2000, file_mode, FileAccess::Read,
    );
    assert!(!denied_read, "User not in allowed_users should be denied");

    let denied_write = validator.check_file_permission_legacy(
        2000, 2000, 2000, 2000, file_mode, FileAccess::Write,
    );
    assert!(!denied_write, "User not in allowed_users should be denied");

    let denied_execute = validator.check_file_permission_legacy(
        2000, 2000, 2000, 2000, file_mode, FileAccess::Execute,
    );
    assert!(!denied_execute, "User not in allowed_users should be denied");
}

/// Test that users in allowed_groups are granted access.
///
/// Group-based access control allows managing access by group membership.
#[test]
fn test_allowed_groups_enforcement() {
    let config = SecurityConfig {
        allowed_users: vec![],       // No individual users allowed
        allowed_groups: vec![1000],  // Group 1000 allowed
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User 2000 is in group 1000, which is allowed
    let file_mode = 0o600; // Owner only

    let has_access = validator.check_file_permission_legacy(
        2000,   // User uid
        1000,   // User gid (in allowed_groups)
        2000,   // File owner
        2000,   // File group
        file_mode,
        FileAccess::Read,
    );
    assert!(has_access, "User in allowed_groups should have access");
}

/// Test zero-trust mode with root explicitly allowed.
///
/// Even when root is in allowed_users, zero-trust mode requires
/// proper file permissions.
#[test]
fn test_zero_trust_root_with_permissions() {
    let config = SecurityConfig {
        allowed_users: vec![0, 1000], // Root IS included
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config); // Zero-trust mode is default

    // File with no permissions - root should be denied in zero-trust mode
    let no_access = validator.check_file_permission_legacy(
        0,      // root uid
        0,      // root gid
        1000,   // file owner
        1000,   // file group
        0o000,  // no permissions
        FileAccess::Read,
    );
    assert!(!no_access, "Root should be denied with 0o000 in zero-trust mode");

    // With proper permissions, root can access
    let has_access = validator.check_file_permission_legacy(
        0, 0, 1000, 1000, 0o644, FileAccess::Read,
    );
    assert!(has_access, "Root should have access with proper permissions in zero-trust mode");
}

/// Test all permission combinations.
///
/// Comprehensive test of read, write, execute permission bits.
#[test]
fn test_all_permission_combinations() {
    let config = SecurityConfig {
        allowed_users: vec![1000, 1001, 2000],
        allowed_groups: vec![1000, 2000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // Test cases: (file_mode, uid, gid, can_read, can_write, can_execute)
    let test_cases = vec![
        // Owner-only permissions
        (0o600, 1000, 1000, true, true, false),   // Owner
        (0o600, 1001, 1000, false, false, false), // In group but not owner
        (0o600, 2000, 2000, false, false, false), // Other
        // Group-only permissions
        (0o060, 1000, 1000, false, false, false), // Owner (no owner perms)
        (0o060, 1001, 1000, true, true, false),   // In group
        (0o060, 2000, 2000, false, false, false), // Other
        // World permissions
        (0o006, 1000, 1000, false, false, false), // Owner (no owner perms)
        (0o006, 1001, 1000, false, false, false), // In group (no group perms)
        (0o006, 2000, 2000, true, true, false),   // Other
        // Full permissions
        (0o755, 1000, 1000, true, true, true),    // Owner
        (0o755, 1001, 1000, true, false, true),   // Group (r-x)
        (0o755, 2000, 2000, true, false, true),   // Other (r-x)
    ];

    for (file_mode, uid, gid, expected_read, expected_write, expected_execute) in test_cases {
        let can_read = validator.check_file_permission_legacy(
            uid, gid, 1000, 1000, file_mode, FileAccess::Read,
        );
        let can_write = validator.check_file_permission_legacy(
            uid, gid, 1000, 1000, file_mode, FileAccess::Write,
        );
        let can_execute = validator.check_file_permission_legacy(
            uid, gid, 1000, 1000, file_mode, FileAccess::Execute,
        );

        assert_eq!(
            can_read, expected_read,
            "Read access mismatch for uid={}, gid={}, mode={:04o}",
            uid, gid, file_mode
        );
        assert_eq!(
            can_write, expected_write,
            "Write access mismatch for uid={}, gid={}, mode={:04o}",
            uid, gid, file_mode
        );
        assert_eq!(
            can_execute, expected_execute,
            "Execute access mismatch for uid={}, gid={}, mode={:04o}",
            uid, gid, file_mode
        );
    }
}

/// Test switching between zero-trust and legacy modes.
///
/// The respect_root flag controls whether root bypasses permission checks.
#[test]
fn test_mode_switching() {
    let config = SecurityConfig {
        allowed_users: vec![0, 1000],
        allowed_groups: vec![1000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let mut validator = SecurityValidator::with_legacy_root(config.clone());

    // Start in legacy mode - root bypasses
    assert!(validator.is_root_bypass_enabled());
    assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));

    // Switch to zero-trust mode
    validator.set_respect_root(true);

    assert!(!validator.is_root_bypass_enabled());
    assert!(!validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));

    // Switch back to legacy mode
    validator.set_respect_root(false);

    assert!(validator.is_root_bypass_enabled());
    assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));
}

/// Test that validate_user_access checks both users and groups.
///
/// This is a preliminary check before file permission evaluation.
#[test]
fn test_validate_user_access() {
    let config = SecurityConfig {
        allowed_users: vec![1000],
        allowed_groups: vec![2000],
        encryption_strength: "high".to_string(),
        access_control_level: "strict".to_string(),
    };

    let validator = SecurityValidator::new(config);

    // User in allowed_users
    assert!(validator.validate_user_access(1000, 3000));

    // User's group in allowed_groups
    assert!(validator.validate_user_access(3000, 2000));

    // User in both
    assert!(validator.validate_user_access(1000, 2000));

    // User in neither
    assert!(!validator.validate_user_access(3000, 3000));
}
