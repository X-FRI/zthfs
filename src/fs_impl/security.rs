use crate::config::SecurityConfig;
use crate::errors::ZthfsResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub struct SecurityValidator {
    config: Arc<SecurityConfig>,
    failed_attempts: Arc<Mutex<HashMap<u32, u32>>>,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
    max_failed_attempts: u32,
}

impl SecurityValidator {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config: Arc::new(config),
            failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            max_failed_attempts: 5,
        }
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

    /// Record failed authentication attempt.
    /// If the number of failed attempts exceeds the max_failed_attempts, record a security event.
    pub fn record_failed_attempt(&self, uid: u32) -> ZthfsResult<()> {
        let mut attempts = self.failed_attempts.lock().unwrap();
        let count = attempts.entry(uid).or_insert(0);
        *count += 1;

        if *count >= self.max_failed_attempts {
            self.record_security_event(
                SecurityEvent::AuthenticationFailure {
                    user: uid,
                    reason: format!("Too many failed attempts: {count}"),
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
        let attempts = self.failed_attempts.lock().unwrap();
        attempts.get(&uid).unwrap_or(&0) >= &self.max_failed_attempts
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
    pub fn check_file_permission(
        &self,
        uid: u32,
        gid: u32,
        file_mode: u32,
        requested_access: FileAccess,
    ) -> bool {
        // First check if user is in allowed users/groups list (filesystem-level access control)
        if !self.config.allowed_users.contains(&uid) && !self.config.allowed_groups.contains(&gid) {
            return false;
        }

        // Extract permission bits from file mode
        let owner_perms = (file_mode >> 6) & 0o7;
        let _group_perms = (file_mode >> 3) & 0o7;
        let _other_perms = file_mode & 0o7;

        // Determine which permission set to use
        let effective_perms = if uid == 0 {
            // Root has full access
            0o7
        } else {
            // Check ownership and apply appropriate permissions
            // TODO: For simplicity, we'll assume the file owner/group matches the process owner/group
            // In a real implementation, you'd get this from file metadata
            owner_perms // Default to owner permissions for now
        };

        // Check if requested access is allowed
        match requested_access {
            FileAccess::Read => (effective_perms & 0o4) != 0,
            FileAccess::Write => (effective_perms & 0o2) != 0,
            FileAccess::Execute => (effective_perms & 0o1) != 0,
        }
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
        SecurityValidator::new(config)
    }

    #[test]
    fn test_file_permission_read_access() {
        let validator = create_test_validator();

        // Test read access with different file modes
        assert!(validator.check_file_permission(1000, 1000, 0o644, FileAccess::Read)); // rw-r--r--
        assert!(validator.check_file_permission(1000, 1000, 0o600, FileAccess::Read)); // rw-------
        assert!(!validator.check_file_permission(1000, 1000, 0o244, FileAccess::Read)); // -w-r--r--
    }

    #[test]
    fn test_file_permission_write_access() {
        let validator = create_test_validator();

        // Test write access with different file modes
        assert!(validator.check_file_permission(1000, 1000, 0o644, FileAccess::Write)); // rw-r--r--
        assert!(validator.check_file_permission(1000, 1000, 0o622, FileAccess::Write)); // rw--w--w-
        assert!(!validator.check_file_permission(1000, 1000, 0o444, FileAccess::Write)); // r--r--r--
    }

    #[test]
    fn test_file_permission_execute_access() {
        let validator = create_test_validator();

        // Test execute access with different file modes
        assert!(validator.check_file_permission(1000, 1000, 0o755, FileAccess::Execute)); // rwxr-xr-x
        assert!(!validator.check_file_permission(1000, 1000, 0o644, FileAccess::Execute)); // rw-r--r--
    }

    #[test]
    fn test_root_access() {
        let validator = create_test_validator();

        // Root (uid 0) should have full access regardless of file permissions
        assert!(validator.check_file_permission(0, 0, 0o000, FileAccess::Read));
        assert!(validator.check_file_permission(0, 0, 0o000, FileAccess::Write));
        assert!(validator.check_file_permission(0, 0, 0o000, FileAccess::Execute));
    }

    #[test]
    fn test_user_not_in_allowed_list() {
        let validator = create_test_validator();

        // User 2000 is not in allowed_users or allowed_groups
        assert!(!validator.check_file_permission(2000, 2000, 0o777, FileAccess::Read));
        assert!(!validator.check_file_permission(2000, 2000, 0o777, FileAccess::Write));
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
}
