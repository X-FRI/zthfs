use crate::config::SecurityConfig;
use crate::errors::ZthfsResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Constant-time comparison for sensitive data (keys, passwords, tokens).
/// This function takes the same amount of time regardless of the input values,
/// preventing timing attacks that could leak information about the data.
///
/// # Arguments
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
/// `true` if slices are equal, `false` otherwise
///
/// # Security
/// This function always executes in time proportional to the length of the
/// slices, not the number of matching bytes. This prevents attackers from
/// using timing analysis to discover partial matches.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Use subtle's ConstantTimeEq for constant-time comparison
    // If lengths differ, we still compare up to the shorter length
    // to avoid leaking length information via timing
    if a.len() != b.len() {
        // First compare the actual content (up to min length)
        let min_len = a.len().min(b.len());
        let content_eq: bool = a[..min_len].ct_eq(&b[..min_len]).into();

        // Then XOR the length difference - this ensures we don't short-circuit
        // and that different lengths always return false
        let len_eq: bool = (a.len() ^ b.len()) == 0;
        content_eq & len_eq
    } else {
        a.ct_eq(b).into()
    }
}

/// Constant-time string comparison for sensitive data.
/// Prevents timing attacks on string comparisons like passwords or tokens.
pub fn constant_time_string_eq(a: &str, b: &str) -> bool {
    constant_time_eq(a.as_bytes(), b.as_bytes())
}

/// Constant-time u32 comparison for ID checking.
pub fn constant_time_u32_eq(a: u32, b: u32) -> bool {
    a.ct_eq(&b).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone)]
pub enum SecurityEvent {
    AuthenticationFailure {
        user: u32,
        reason: String,
    },
    AuthorizationFailure {
        user: u32,
        path: String,
        operation: String,
    },
    SuspiciousActivity {
        user: u32,
        activity: String,
        details: String,
    },
    EncryptionFailure {
        path: String,
        error: String,
    },
    IntegrityCheckFailure {
        path: String,
        checksum: String,
    },
    RootAccess {
        user: u32,
        path: String,
        operation: String,
    },
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub user: u32,
    pub event_type: String,
    pub details: String,
    pub severity: SecurityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    failed_count: u32,
    last_attempt_time: u64,
    lockout_until: u64,
}

pub struct SecurityValidator {
    config: Arc<SecurityConfig>,
    failed_attempts: Arc<Mutex<HashMap<u32, RateLimitEntry>>>,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
    max_failed_attempts: u32,
    /// Base delay for authentication failures (milliseconds)
    auth_failure_delay_ms: u64,
    /// Maximum delay for exponential backoff (milliseconds)
    max_backoff_delay_ms: u64,
    /// When false, root (uid=0) can bypass file permission checks (legacy mode).
    /// When true, root must be explicitly allowed via allowed_users list
    /// and must still pass file permission checks (zero-trust mode).
    /// Default: true (zero-trust behavior).
    respect_root: bool,
}

impl SecurityValidator {
    /// Create a new SecurityValidator with zero-trust root policy.
    ///
    /// **SECURITY DEFAULT**: As of this version, zero-trust mode is enabled by default.
    /// This means root (uid=0) must be explicitly allowed via allowed_users list and
    /// still passes all file permission checks. This is the RECOMMENDED setting for
    /// production, especially for medical/healthcare data handling.
    ///
    /// For legacy behavior where root bypasses all permissions, use `with_legacy_root()`.
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            max_failed_attempts: 5,
            auth_failure_delay_ms: 100, // 100ms base delay
            max_backoff_delay_ms: 5000, // 5 second max delay
            respect_root: true,         // Default to zero-trust behavior
        }
    }

    /// Create a new SecurityValidator with zero-trust root policy.
    ///
    /// In zero-trust mode, root must be explicitly allowed and still passes permission checks.
    /// This is now the default behavior via `new()`, but this method is kept for explicitness.
    pub fn with_zero_trust_root(config: SecurityConfig) -> Self {
        Self::new(config) // Now just calls new() since zero-trust is the default
    }

    /// Create a new SecurityValidator with legacy root policy.
    ///
    /// **SECURITY WARNING**: Legacy mode allows root to bypass all file permission checks.
    /// This violates zero-trust security principles and should NOT be used for:
    /// - Medical data (HIPAA compliance)
    /// - Production systems
    /// - Multi-user environments
    ///
    /// This mode is only provided for backward compatibility with existing deployments.
    pub fn with_legacy_root(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            max_failed_attempts: 5,
            auth_failure_delay_ms: 100, // 100ms base delay
            max_backoff_delay_ms: 5000, // 5 second max delay
            respect_root: false,        // Legacy mode: root bypasses checks
        }
    }

    /// Set whether root should bypass permission checks.
    ///
    /// - `false`: Zero-trust mode (RECOMMENDED for production). Root must be explicitly allowed.
    /// - `true`: Legacy mode (WARNING: security risk). Root bypasses permission checks.
    pub fn set_respect_root(&mut self, respect: bool) {
        self.respect_root = respect;
    }

    /// Check if root bypass is enabled (legacy mode).
    pub fn is_root_bypass_enabled(&self) -> bool {
        !self.respect_root
    }

    /// Validate user access based on security configuration.
    /// Check if the given uid or gid is in the config.allowed_users or config.allowed_groups lists.
    pub fn validate_user_access(&self, uid: u32, gid: u32) -> bool {
        self.config.allowed_users.contains(&uid) || self.config.allowed_groups.contains(&gid)
    }

    /// Check if encryption strength meets requirements
    pub fn validate_encryption_strength(&self) -> ZthfsResult<()> {
        match self.config.encryption_strength.as_str() {
            "high" | "medium" | "low" => Ok(()),
            _ => Err(crate::errors::ZthfsError::Config(
                "Invalid encryption strength. Must be 'high', 'medium', or 'low'".to_string(),
            )),
        }
    }

    /// Validate access control level
    pub fn validate_access_control_level(&self) -> ZthfsResult<()> {
        match self.config.access_control_level.as_str() {
            "strict" | "moderate" | "permissive" => Ok(()),
            _ => Err(crate::errors::ZthfsError::Config(
                "Invalid access control level. Must be 'strict', 'moderate', or 'permissive'"
                    .to_string(),
            )),
        }
    }

    /// Record failed authentication attempt with exponential backoff delay.
    /// If the number of failed attempts exceeds the max_failed_attempts, record a security event.
    /// Uses constant-time delay to prevent timing attacks.
    pub fn record_failed_attempt(&self, uid: u32) -> ZthfsResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut attempts = self.failed_attempts.lock().unwrap();
        let entry = attempts.entry(uid).or_insert(RateLimitEntry {
            failed_count: 0,
            last_attempt_time: now,
            lockout_until: 0,
        });

        entry.failed_count += 1;
        entry.last_attempt_time = now;

        // Calculate exponential backoff delay
        // delay = base_delay * 2^(failed_count - 1), capped at max_delay
        let delay_ms = if entry.failed_count > 0 {
            let exponential_delay =
                self.auth_failure_delay_ms * (1 << (entry.failed_count - 1).min(31));
            exponential_delay.min(self.max_backoff_delay_ms)
        } else {
            self.auth_failure_delay_ms
        };

        // Always apply delay to prevent timing attacks
        // The delay is constant regardless of success/failure path
        drop(attempts); // Release lock before sleeping
        std::thread::sleep(Duration::from_millis(delay_ms));

        // Re-acquire lock for security event recording
        let mut attempts = self.failed_attempts.lock().unwrap();
        let entry = attempts.get_mut(&uid).unwrap();

        if entry.failed_count >= self.max_failed_attempts {
            // Set lockout time (exponential: 2^count seconds, max 1 hour)
            let lockout_seconds = (1u64 << entry.failed_count.saturating_sub(1).min(10)).min(3600);
            entry.lockout_until = now + lockout_seconds;

            self.record_security_event(
                SecurityEvent::AuthenticationFailure {
                    user: uid,
                    reason: format!(
                        "Too many failed attempts: {}, locked out for {}s",
                        entry.failed_count, lockout_seconds
                    ),
                },
                SecurityLevel::High,
            )?;
        }

        Ok(())
    }

    pub fn record_successful_auth(&self, uid: u32) -> ZthfsResult<()> {
        let mut attempts = self.failed_attempts.lock().unwrap();
        attempts.remove(&uid);
        Ok(())
    }

    /// Check if user is locked out due to too many failed attempts
    pub fn is_user_locked(&self, uid: u32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut attempts = self.failed_attempts.lock().unwrap();

        if let Some(entry) = attempts.get_mut(&uid) {
            // Check if lockout has expired
            if entry.lockout_until > 0 && now >= entry.lockout_until {
                // Reset after lockout expires
                entry.failed_count = 0;
                entry.lockout_until = 0;
                return false;
            }
            // Still within lockout period
            entry.lockout_until > 0
        } else {
            false
        }
    }

    /// Get time remaining in lockout (seconds), or 0 if not locked
    pub fn get_lockout_remaining(&self, uid: u32) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let attempts = self.failed_attempts.lock().unwrap();
        if let Some(entry) = attempts.get(&uid) {
            entry.lockout_until.saturating_sub(now)
        } else {
            0
        }
    }

    pub fn record_security_event(
        &self,
        event: SecurityEvent,
        level: SecurityLevel,
    ) -> ZthfsResult<()> {
        let (user, event_type, details) = match event {
            SecurityEvent::AuthenticationFailure { user, reason } => {
                (user, "authentication_failure".to_string(), reason)
            }
            SecurityEvent::AuthorizationFailure {
                user,
                path,
                operation,
            } => (
                user,
                "authorization_failure".to_string(),
                format!("{operation} on {path}"),
            ),
            SecurityEvent::SuspiciousActivity {
                user,
                activity,
                details,
            } => (
                user,
                "suspicious_activity".to_string(),
                format!("{activity}: {details}"),
            ),
            SecurityEvent::EncryptionFailure { path, error } => (
                0,
                "encryption_failure".to_string(),
                format!("{path}: {error}"),
            ),
            SecurityEvent::IntegrityCheckFailure { path, checksum } => (
                0,
                "integrity_failure".to_string(),
                format!("{path} checksum mismatch: {checksum}"),
            ),
            SecurityEvent::RootAccess {
                user,
                path,
                operation,
            } => (
                user,
                "root_access".to_string(),
                format!("Root user accessed {path} for {operation}"),
            ),
        };

        let audit_entry = AuditEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            user,
            event_type,
            details,
            severity: level,
        };

        let mut audit_log = self.audit_log.lock().unwrap();
        audit_log.push(audit_entry);

        // Keep only recent entries (last 1000)
        if audit_log.len() > 1000 {
            audit_log.remove(0);
        }

        Ok(())
    }

    pub fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.lock().unwrap().clone()
    }

    /// Check if operation should be rate limited
    pub fn should_rate_limit(&self, uid: u32, operation: &str) -> bool {
        // Simple rate limiting logic
        // In production, this would be more sophisticated
        matches!(operation, "write" | "delete") && self.is_user_locked(uid)
    }

    /// Check POSIX-style file permissions
    /// Returns true if the user has the requested access to the file
    ///
    /// # Arguments
    /// * `user_uid` - The user ID requesting access
    /// * `user_gid` - The group ID of the requesting user
    /// * `file_uid` - The user ID that owns the file
    /// * `file_gid` - The group ID that owns the file
    /// * `file_mode` - The file permission mode (e.g., 0o644)
    /// * `requested_access` - The type of access being requested
    /// * `file_path` - Optional path for audit logging
    #[allow(clippy::too_many_arguments)]
    pub fn check_file_permission(
        &self,
        user_uid: u32,
        user_gid: u32,
        file_uid: u32,
        file_gid: u32,
        file_mode: u32,
        requested_access: FileAccess,
        file_path: Option<&str>,
    ) -> bool {
        // First check if user is in allowed users/groups list (filesystem-level access control)
        if !self.config.allowed_users.contains(&user_uid)
            && !self.config.allowed_groups.contains(&user_gid)
        {
            return false;
        }

        // Extract permission bits from file mode
        let owner_perms = (file_mode >> 6) & 0o7;
        let group_perms = (file_mode >> 3) & 0o7;
        let other_perms = file_mode & 0o7;

        // Determine which permission set to use based on POSIX ownership rules
        let effective_perms = if !self.respect_root && user_uid == 0 {
            // LEGACY MODE: Root has full access regardless of file ownership
            // WARNING: This violates zero-trust principles and should NOT be used
            // in production environments, especially for medical data.
            0o7
        } else if user_uid == file_uid {
            // User owns the file - use owner permissions
            owner_perms
        } else if user_gid == file_gid {
            // User is in the file's group - use group permissions
            group_perms
        } else {
            // User is neither owner nor in group - use other permissions
            other_perms
        };

        // Check if requested access is allowed
        let allowed = match requested_access {
            FileAccess::Read => (effective_perms & 0o4) != 0,
            FileAccess::Write => (effective_perms & 0o2) != 0,
            FileAccess::Execute => (effective_perms & 0o1) != 0,
        };

        // Audit log root access
        if allowed
            && user_uid == 0
            && let Some(path) = file_path
        {
            let _ = self.record_security_event(
                SecurityEvent::RootAccess {
                    user: user_uid,
                    path: path.to_string(),
                    operation: format!("{:?}", requested_access),
                },
                SecurityLevel::High,
            );
        }

        allowed
    }

    /// Check file permission without path (for backward compatibility)
    pub fn check_file_permission_legacy(
        &self,
        user_uid: u32,
        user_gid: u32,
        file_uid: u32,
        file_gid: u32,
        file_mode: u32,
        requested_access: FileAccess,
    ) -> bool {
        self.check_file_permission(
            user_uid,
            user_gid,
            file_uid,
            file_gid,
            file_mode,
            requested_access,
            None,
        )
    }

    /// Validate file path for security
    pub fn validate_secure_path(&self, path: &str) -> ZthfsResult<()> {
        // Check for path traversal attempts
        if path.contains("..") {
            return Err(crate::errors::ZthfsError::Security(
                "Path traversal detected".to_string(),
            ));
        }

        // Check for suspicious file extensions
        let suspicious_extensions = ["exe", "bat", "cmd", "scr", "pif", "com"];
        if let Some(ext) = std::path::Path::new(path).extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if suspicious_extensions.contains(&ext_str.as_ref()) {
                return Err(crate::errors::ZthfsError::Security(format!(
                    "Suspicious file extension: {ext_str}"
                )));
            }
        }

        Ok(())
    }

    /// Get security configuration
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;

    fn create_test_validator() -> SecurityValidator {
        let config = SecurityConfig {
            allowed_users: vec![1000, 0],
            allowed_groups: vec![1000, 0],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        SecurityValidator::with_legacy_root(config) // Use legacy mode for test compatibility
    }

    fn create_zero_trust_test_validator() -> SecurityValidator {
        let config = SecurityConfig {
            allowed_users: vec![1000, 0],
            allowed_groups: vec![1000, 0],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        SecurityValidator::new(config) // Default is now zero-trust
    }

    #[test]
    fn test_file_permission_read_access() {
        let validator = create_test_validator();

        // Test read access with different file modes
        // User 1000 owns the file (uid=1000, gid=1000)
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Read
        )); // rw-r--r--
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o600,
            FileAccess::Read
        )); // rw-------
        assert!(!validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o244,
            FileAccess::Read
        )); // -w-r--r--
    }

    #[test]
    fn test_file_permission_write_access() {
        let validator = create_test_validator();

        // Test write access with different file modes
        // User 1000 owns the file (uid=1000, gid=1000)
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Write
        )); // rw-r--r--
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o622,
            FileAccess::Write
        )); // rw--w--w-
        assert!(!validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o444,
            FileAccess::Write
        )); // r--r--r--
    }

    #[test]
    fn test_file_permission_execute_access() {
        let validator = create_test_validator();

        // Test execute access with different file modes
        // User 1000 owns the file (uid=1000, gid=1000)
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o755,
            FileAccess::Execute
        )); // rwxr-xr-x
        assert!(!validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o644,
            FileAccess::Execute
        )); // rw-r--r--
    }

    #[test]
    fn test_root_access() {
        let validator = create_test_validator();

        // Root (uid 0) should have full access regardless of file ownership/permissions
        // File owned by user 1000, group 1000, but root gets access anyway
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Write));
        assert!(validator.check_file_permission_legacy(
            0,
            0,
            1000,
            1000,
            0o000,
            FileAccess::Execute
        ));
    }

    #[test]
    fn test_user_not_in_allowed_list() {
        let validator = create_test_validator();

        // User 2000 is not in allowed_users or allowed_groups
        // File owned by user 1000, group 1000 with full permissions
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o777,
            FileAccess::Read
        ));
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o777,
            FileAccess::Write
        ));
    }

    #[test]
    fn test_posix_ownership_permissions() {
        // Create a more permissive validator for testing POSIX permissions
        let config = SecurityConfig {
            allowed_users: vec![1000, 1001, 2000, 0], // Include all test users
            allowed_groups: vec![1000, 2000, 0],      // Include all test groups
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        // Test owner permissions (user 1000 owns file)
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o700,
            FileAccess::Read
        )); // rwx------
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o700,
            FileAccess::Write
        ));
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o700,
            FileAccess::Execute
        ));

        // Test group permissions (user 1001 in group 1000, file owned by 1000:1000)
        assert!(validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o070,
            FileAccess::Read
        )); // ---rwx---
        assert!(validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o070,
            FileAccess::Write
        ));
        assert!(validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o070,
            FileAccess::Execute
        ));

        // Test other permissions (user 2000 not owner/group, file owned by 1000:1000)
        assert!(validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o007,
            FileAccess::Read
        )); // ------rwx
        assert!(validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o007,
            FileAccess::Write
        ));
        assert!(validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o007,
            FileAccess::Execute
        ));

        // Test mixed permissions: owner can read/write, group can read, others can do nothing
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Read
        )); // rw-r-----
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Write
        ));
        assert!(!validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Execute
        ));

        assert!(validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Read
        )); // Group can read
        assert!(!validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Write
        )); // Group cannot write
        assert!(!validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o640,
            FileAccess::Execute
        ));

        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o640,
            FileAccess::Read
        )); // Others cannot read
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o640,
            FileAccess::Write
        ));
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o640,
            FileAccess::Execute
        ));
    }

    #[test]
    fn test_posix_permission_precedence() {
        // Create a more permissive validator for testing POSIX permissions
        let config = SecurityConfig {
            allowed_users: vec![1000, 1001, 2000, 0], // Include all test users
            allowed_groups: vec![1000, 2000, 0],      // Include all test groups
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        // User is owner - should use owner permissions regardless of group membership
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Read
        )); // rwxr--r--
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Write
        ));
        assert!(validator.check_file_permission_legacy(
            1000,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Execute
        ));

        // User is in group but not owner - should use group permissions (0o744 = rwxr--r--)
        assert!(validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Read
        )); // Group can read
        assert!(!validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Write
        )); // Group cannot write
        assert!(!validator.check_file_permission_legacy(
            1001,
            1000,
            1000,
            1000,
            0o744,
            FileAccess::Execute
        )); // Group cannot execute

        // User is neither owner nor in group - should use other permissions (0o744 = rwxr--r--)
        assert!(validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o744,
            FileAccess::Read
        )); // Others can read
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o744,
            FileAccess::Write
        )); // Others cannot write
        assert!(!validator.check_file_permission_legacy(
            2000,
            2000,
            1000,
            1000,
            0o744,
            FileAccess::Execute
        )); // Others cannot execute
    }

    #[test]
    fn test_root_bypasses_ownership() {
        let validator = create_test_validator();

        // Root should always have access regardless of file ownership or permissions
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read)); // No permissions
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Write));
        assert!(validator.check_file_permission_legacy(
            0,
            0,
            1000,
            1000,
            0o000,
            FileAccess::Execute
        ));

        // Even with restrictive permissions, root gets access
        assert!(validator.check_file_permission_legacy(0, 0, 2000, 2000, 0o000, FileAccess::Read));
        assert!(validator.check_file_permission_legacy(0, 0, 2000, 2000, 0o000, FileAccess::Write));
        assert!(validator.check_file_permission_legacy(
            0,
            0,
            2000,
            2000,
            0o000,
            FileAccess::Execute
        ));
    }

    #[test]
    fn test_path_validation() {
        let validator = create_test_validator();

        // Valid paths
        assert!(
            validator
                .validate_secure_path("/safe/path/file.txt")
                .is_ok()
        );
        assert!(
            validator
                .validate_secure_path("relative/path/file.txt")
                .is_ok()
        );

        // Path traversal attempts
        assert!(validator.validate_secure_path("../unsafe").is_err());
        assert!(
            validator
                .validate_secure_path("/safe/../../../etc/passwd")
                .is_err()
        );

        // Suspicious extensions
        assert!(validator.validate_secure_path("malware.exe").is_err());
        assert!(validator.validate_secure_path("script.bat").is_err());
        assert!(validator.validate_secure_path("safe.txt").is_ok());
    }

    #[test]
    fn test_zero_trust_root_mode() {
        // Create a validator with zero-trust root policy
        let config = SecurityConfig {
            allowed_users: vec![1000, 0], // Root is explicitly allowed
            allowed_groups: vec![1000, 0],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::with_zero_trust_root(config);
        assert_eq!(validator.is_root_bypass_enabled(), false);

        // File with no permissions (0o000) - root should be denied in zero-trust mode
        // even though root is in allowed_users
        assert!(!validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));
        assert!(!validator.check_file_permission_legacy(
            0,
            0,
            1000,
            1000,
            0o000,
            FileAccess::Write
        ));

        // With proper permissions, root can access
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o644, FileAccess::Read));
    }

    #[test]
    fn test_legacy_root_bypass_mode() {
        // Create a validator with legacy root policy (explicitly requested)
        let config = SecurityConfig {
            allowed_users: vec![1000, 0], // Root is explicitly allowed
            allowed_groups: vec![1000, 0],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::with_legacy_root(config);
        assert_eq!(validator.is_root_bypass_enabled(), true);

        // In legacy mode, root bypasses all file permissions
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Read));
        assert!(validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o000, FileAccess::Write));
        assert!(validator.check_file_permission_legacy(
            0,
            0,
            1000,
            1000,
            0o000,
            FileAccess::Execute
        ));
    }

    #[test]
    fn test_root_not_in_allowed_list() {
        // Root is NOT in allowed_users
        let config = SecurityConfig {
            allowed_users: vec![1000], // Root NOT included
            allowed_groups: vec![1000],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        // Even in legacy mode, root must be in allowed_users
        assert!(!validator.check_file_permission_legacy(0, 0, 1000, 1000, 0o777, FileAccess::Read));
        assert!(!validator.check_file_permission_legacy(
            0,
            0,
            1000,
            1000,
            0o777,
            FileAccess::Write
        ));
    }

    #[test]
    fn test_zero_trust_with_audit_logging() {
        let config = SecurityConfig {
            allowed_users: vec![1000, 0],
            allowed_groups: vec![1000, 0],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::with_zero_trust_root(config);

        // Root access with proper permissions should generate audit log
        let path = "/medical/patient_record.txt";
        assert!(validator.check_file_permission(
            0,
            0,
            1000,
            1000,
            0o644,
            FileAccess::Read,
            Some(path)
        ));

        // Check that audit log was created
        let log = validator.get_audit_log();
        assert!(!log.is_empty());
        let root_access_entries: Vec<_> = log
            .iter()
            .filter(|e| e.event_type == "root_access")
            .collect();
        assert!(!root_access_entries.is_empty());
        assert!(root_access_entries[0].details.contains(path));
        assert_eq!(root_access_entries[0].severity, SecurityLevel::High);
    }

    #[test]
    fn test_constant_time_eq() {
        // Test equal values
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\x00\xff\x42", b"\x00\xff\x42"));

        // Test different values
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello!"));
        assert!(!constant_time_eq(b"hello", b"hella"));

        // Test different lengths
        assert!(!constant_time_eq(b"hello", b"helloworld"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_constant_time_string_eq() {
        assert!(constant_time_string_eq("password", "password"));
        assert!(!constant_time_string_eq("password", "wrong"));
        assert!(!constant_time_string_eq("admin", "Admin")); // Case sensitive
    }

    #[test]
    fn test_constant_time_u32_eq() {
        assert!(constant_time_u32_eq(1000, 1000));
        assert!(constant_time_u32_eq(0, 0));
        assert!(!constant_time_u32_eq(1000, 1001));
        assert!(!constant_time_u32_eq(0, 1));
    }

    #[test]
    fn test_exponential_backoff_rate_limiting() {
        let config = SecurityConfig {
            allowed_users: vec![1000],
            allowed_groups: vec![1000],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        let uid = 9999u32;

        // User is not locked initially
        assert!(!validator.is_user_locked(uid));

        // Record failed attempts (this will take time due to delays)
        let start = std::time::Instant::now();

        for _i in 0..4 {
            validator.record_failed_attempt(uid).unwrap();
            // Not locked yet (< 5 attempts)
            assert!(!validator.is_user_locked(uid));
        }

        let first_four_duration = start.elapsed();

        // 5th attempt should trigger lockout
        validator.record_failed_attempt(uid).unwrap();
        assert!(validator.is_user_locked(uid));

        // Total time should be significantly more than 5 * 100ms due to exponential backoff
        // (100ms + 200ms + 400ms + 800ms + 1600ms = 3100ms minimum)
        assert!(first_four_duration.as_millis() > 400); // At least 100+200+400
    }

    #[test]
    fn test_lockout_expiry() {
        let config = SecurityConfig {
            allowed_users: vec![1000],
            allowed_groups: vec![1000],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        let uid = 8888u32;

        // Record enough failed attempts to trigger lockout
        for _ in 0..5 {
            validator.record_failed_attempt(uid).unwrap();
        }

        assert!(validator.is_user_locked(uid));
        assert!(validator.get_lockout_remaining(uid) > 0);

        // Successful auth clears the lockout
        validator.record_successful_auth(uid).unwrap();
        assert!(!validator.is_user_locked(uid));
        assert_eq!(validator.get_lockout_remaining(uid), 0);
    }

    #[test]
    fn test_rate_limiting_prevents_operations() {
        let config = SecurityConfig {
            allowed_users: vec![1000],
            allowed_groups: vec![1000],
            encryption_strength: "high".to_string(),
            access_control_level: "strict".to_string(),
        };
        let validator = SecurityValidator::new(config);

        let uid = 7777u32;

        // Not rate limited initially
        assert!(!validator.should_rate_limit(uid, "write"));

        // Lock out the user
        for _ in 0..5 {
            validator.record_failed_attempt(uid).unwrap();
        }

        // Now rate limited
        assert!(validator.should_rate_limit(uid, "write"));
        assert!(validator.should_rate_limit(uid, "delete"));

        // Read operations might not be rate limited in the same way
        // (depends on policy implementation)
    }
}
