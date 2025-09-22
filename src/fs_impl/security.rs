use crate::config::SecurityConfig;
use crate::errors::ZthfsResult;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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
                    reason: format!("Too many failed attempts: {}", count),
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
                format!("{} on {}", operation, path),
            ),
            SecurityEvent::SuspiciousActivity {
                user,
                activity,
                details,
            } => (
                user,
                "suspicious_activity".to_string(),
                format!("{}: {}", activity, details),
            ),
            SecurityEvent::EncryptionFailure { path, error } => (
                0,
                "encryption_failure".to_string(),
                format!("{}: {}", path, error),
            ),
            SecurityEvent::IntegrityCheckFailure { path, checksum } => (
                0,
                "integrity_failure".to_string(),
                format!("{} checksum mismatch: {}", path, checksum),
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

    /// Validate file path for security
    pub fn validate_secure_path(&self, path: &str) -> ZthfsResult<()> {
        // Check for path traversal attempts
        if path.contains("..") {
            return Err(crate::errors::ZthfsError::Security(
                "Path traversal detected".to_string(),
            ));
        }

        // Check for suspicious file extensions
        let suspicious_extensions = vec!["exe", "bat", "cmd", "scr", "pif", "com"];
        if let Some(ext) = std::path::Path::new(path).extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if suspicious_extensions.contains(&ext_str.as_ref()) {
                return Err(crate::errors::ZthfsError::Security(format!(
                    "Suspicious file extension: {}",
                    ext_str
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
