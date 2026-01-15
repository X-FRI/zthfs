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

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Display tests ==========
    #[test]
    fn test_display_crypto() {
        let err = ZthfsError::Crypto("test crypto error".to_string());
        assert_eq!(
            format!("{err}"),
            "Encryption/Decryption error: test crypto error"
        );
    }

    #[test]
    fn test_display_fs() {
        let err = ZthfsError::Fs("test fs error".to_string());
        assert_eq!(format!("{err}"), "Filesystem error: test fs error");
    }

    #[test]
    fn test_display_config() {
        let err = ZthfsError::Config("test config error".to_string());
        assert_eq!(format!("{err}"), "Configuration error: test config error");
    }

    #[test]
    fn test_display_integrity() {
        let err = ZthfsError::Integrity("test integrity error".to_string());
        assert_eq!(
            format!("{err}"),
            "Integrity verification error: test integrity error"
        );
    }

    #[test]
    fn test_display_log() {
        let err = ZthfsError::Log("test log error".to_string());
        assert_eq!(format!("{err}"), "Logging error: test log error");
    }

    #[test]
    fn test_display_permission() {
        let err = ZthfsError::Permission("test permission error".to_string());
        assert_eq!(format!("{err}"), "Permission error: test permission error");
    }

    #[test]
    fn test_display_path() {
        let err = ZthfsError::Path("test path error".to_string());
        assert_eq!(format!("{err}"), "Path error: test path error");
    }

    #[test]
    fn test_display_serialization() {
        let err = ZthfsError::Serialization("test serialization error".to_string());
        assert_eq!(
            format!("{err}"),
            "Serialization error: test serialization error"
        );
    }

    #[test]
    fn test_display_security() {
        let err = ZthfsError::Security("test security error".to_string());
        assert_eq!(format!("{err}"), "Security error: test security error");
    }

    #[test]
    fn test_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = ZthfsError::Io(io_err);
        assert_eq!(format!("{err}"), "I/O error: file not found");
    }

    // ========== From trait tests ==========
    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let zthfs_err: ZthfsError = io_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Io(_)));
        assert_eq!(format!("{zthfs_err}"), "I/O error: access denied");
    }

    #[test]
    fn test_from_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let zthfs_err: ZthfsError = json_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Serialization(_)));
    }

    #[test]
    fn test_from_utf8_error() {
        let invalid_vec = vec![0xff, 0xfe];
        let result = String::from_utf8(invalid_vec);
        assert!(result.is_err());

        let utf8_err = result.unwrap_err();
        let zthfs_err: ZthfsError = utf8_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Fs(_)));
        assert!(format!("{zthfs_err}").contains("UTF-8 conversion error"));
    }

    #[test]
    fn test_from_box_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "boxed error");
        let boxed_err: Box<dyn std::error::Error + Send + Sync> = io_err.into();
        let zthfs_err: ZthfsError = boxed_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Fs(_)));
    }

    #[test]
    fn test_from_aes_gcm_error() {
        // Create an aes_gcm::Error by attempting to decrypt invalid data
        use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Create a key directly using GenericArray
        let key_bytes: [u8; 32] = *b"00000000000000000000000000000001";
        let key: &Key<Aes256Gcm> = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Use a valid nonce (12 bytes)
        let nonce = Nonce::from_slice(b"123456789012");

        // Create ciphertext with an invalid tag (corrupted data)
        let mut ciphertext_and_tag = vec![0u8; 20]; // Some data + invalid tag
        ciphertext_and_tag[0..16].copy_from_slice(b"somedatasomedata");

        let result = cipher.decrypt(nonce, ciphertext_and_tag.as_ref());
        assert!(result.is_err());

        let aes_err = result.unwrap_err();
        let zthfs_err: ZthfsError = aes_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Crypto(_)));
    }

    #[test]
    fn test_from_sled_error() {
        // Use sled::Error::Io which wraps an io::Error
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "db not found");
        let sled_err = sled::Error::Io(io_err);
        let zthfs_err: ZthfsError = sled_err.into();
        assert!(matches!(zthfs_err, ZthfsError::Fs(_)));
        assert!(format!("{zthfs_err}").contains("Database error"));
    }

    // ========== PartialEq tests ==========
    #[test]
    fn test_partial_eq_crypto() {
        let err1 = ZthfsError::Crypto("same".to_string());
        let err2 = ZthfsError::Crypto("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Crypto("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_fs() {
        let err1 = ZthfsError::Fs("same".to_string());
        let err2 = ZthfsError::Fs("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Fs("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_config() {
        let err1 = ZthfsError::Config("same".to_string());
        let err2 = ZthfsError::Config("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Config("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_integrity() {
        let err1 = ZthfsError::Integrity("same".to_string());
        let err2 = ZthfsError::Integrity("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Integrity("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_log() {
        let err1 = ZthfsError::Log("same".to_string());
        let err2 = ZthfsError::Log("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Log("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_permission() {
        let err1 = ZthfsError::Permission("same".to_string());
        let err2 = ZthfsError::Permission("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Permission("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_path() {
        let err1 = ZthfsError::Path("same".to_string());
        let err2 = ZthfsError::Path("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Path("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_serialization() {
        let err1 = ZthfsError::Serialization("same".to_string());
        let err2 = ZthfsError::Serialization("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Serialization("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_security() {
        let err1 = ZthfsError::Security("same".to_string());
        let err2 = ZthfsError::Security("same".to_string());
        assert_eq!(err1, err2);

        let err3 = ZthfsError::Security("different".to_string());
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_io() {
        let io_err1 = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let io_err2 = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err1 = ZthfsError::Io(io_err1);
        let err2 = ZthfsError::Io(io_err2);
        assert_eq!(err1, err2);

        let io_err3 = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err3 = ZthfsError::Io(io_err3);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_partial_eq_different_variants() {
        let crypto_err = ZthfsError::Crypto("same".to_string());
        let fs_err = ZthfsError::Fs("same".to_string());
        assert_ne!(crypto_err, fs_err);
    }

    // ========== Error trait ==========
    #[test]
    fn test_error_trait_impl() {
        let err = ZthfsError::Crypto("test".to_string());
        // Just verify it implements std::error::Error
        let _dyn_err: &dyn std::error::Error = &err;
    }

    // ========== ZthfsResult type ==========
    #[test]
    fn test_zthfs_result_ok() {
        let result: ZthfsResult<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_zthfs_result_err() {
        let result: ZthfsResult<i32> = Err(ZthfsError::Config("bad config".to_string()));
        assert!(result.is_err());
        assert!(matches!(result, Err(ZthfsError::Config(_))));
    }
}
