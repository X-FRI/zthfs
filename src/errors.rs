use std::fmt;

#[derive(Debug)]
pub enum ZthfsError {
    /// Encryption/Decryption error
    Crypto(String),
    /// Filesystem operation error
    Fs(String),
    /// Configuration error
    Config(String),
    /// Integrity verification error
    Integrity(String),
    /// Logging error
    Log(String),
    /// Permission error
    Permission(String),
    /// Path error
    Path(String),
    /// Serialization error
    Serialization(String),
    /// Security error
    Security(String),
    /// I/O error
    Io(std::io::Error),
}

impl fmt::Display for ZthfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZthfsError::Crypto(msg) => write!(f, "Encryption/Decryption error: {msg}"),
            ZthfsError::Fs(msg) => write!(f, "Filesystem error: {msg}"),
            ZthfsError::Config(msg) => write!(f, "Configuration error: {msg}"),
            ZthfsError::Integrity(msg) => write!(f, "Integrity verification error: {msg}"),
            ZthfsError::Log(msg) => write!(f, "Logging error: {msg}"),
            ZthfsError::Permission(msg) => write!(f, "Permission error: {msg}"),
            ZthfsError::Path(msg) => write!(f, "Path error: {msg}"),
            ZthfsError::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            ZthfsError::Security(msg) => write!(f, "Security error: {msg}"),
            ZthfsError::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for ZthfsError {}

impl From<std::io::Error> for ZthfsError {
    fn from(err: std::io::Error) -> Self {
        ZthfsError::Io(err)
    }
}

impl From<serde_json::Error> for ZthfsError {
    fn from(err: serde_json::Error) -> Self {
        ZthfsError::Serialization(err.to_string())
    }
}

impl From<aes_gcm::Error> for ZthfsError {
    fn from(err: aes_gcm::Error) -> Self {
        ZthfsError::Crypto(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ZthfsError {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ZthfsError::Fs(err.to_string())
    }
}

impl PartialEq for ZthfsError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ZthfsError::Crypto(a), ZthfsError::Crypto(b)) => a == b,
            (ZthfsError::Fs(a), ZthfsError::Fs(b)) => a == b,
            (ZthfsError::Config(a), ZthfsError::Config(b)) => a == b,
            (ZthfsError::Integrity(a), ZthfsError::Integrity(b)) => a == b,
            (ZthfsError::Log(a), ZthfsError::Log(b)) => a == b,
            (ZthfsError::Permission(a), ZthfsError::Permission(b)) => a == b,
            (ZthfsError::Path(a), ZthfsError::Path(b)) => a == b,
            (ZthfsError::Serialization(a), ZthfsError::Serialization(b)) => a == b,
            (ZthfsError::Security(a), ZthfsError::Security(b)) => a == b,
            // For Io errors, we compare the error messages since std::io::Error doesn't implement PartialEq
            (ZthfsError::Io(a), ZthfsError::Io(b)) => a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl From<sled::Error> for ZthfsError {
    fn from(err: sled::Error) -> Self {
        ZthfsError::Fs(format!("Database error: {err}"))
    }
}

impl From<std::string::FromUtf8Error> for ZthfsError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ZthfsError::Fs(format!("UTF-8 conversion error: {err}"))
    }
}

pub type ZthfsResult<T> = Result<T, ZthfsError>;
