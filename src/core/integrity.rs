use crate::config::IntegrityConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use crc32c::crc32c;
use std::path::Path;

pub struct IntegrityHandler;

impl IntegrityHandler {
    pub fn compute_checksum(data: &[u8]) -> u32 {
        crc32c(data)
    }

    /// Verify the integrity of the data
    pub fn verify_integrity(data: &[u8], expected_checksum: u32) -> bool {
        Self::compute_checksum(data) == expected_checksum
    }

    /// Read the checksum from the extended attribute.
    /// Use xattr library to access the extended attributes of the file system.
    /// The checksum is stored in the extended attribute in little-endian u32 format, prefixed with config.xattr_namespace.
    pub fn get_checksum_from_xattr(
        real_path: &Path,
        config: &IntegrityConfig,
    ) -> ZthfsResult<Option<u32>> {
        if !config.enabled {
            return Ok(None);
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);
        match xattr::get(real_path, &xattr_name) {
            Ok(Some(value)) => {
                if value.len() == 4 {
                    let checksum = u32::from_le_bytes(value.try_into().unwrap());
                    Ok(Some(checksum))
                } else {
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                // If the file does not exist or for other reasons, ignore the error
                log::debug!("Failed to read checksum xattr: {e}");
                Ok(None)
            }
        }
    }

    /// Write the computed checksum to the extended attribute of the file.
    pub fn set_checksum_xattr(
        real_path: &Path,
        checksum: u32,
        config: &IntegrityConfig,
    ) -> ZthfsResult<()> {
        if !config.enabled {
            return Ok(());
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);
        let checksum_bytes = checksum.to_le_bytes();

        xattr::set(real_path, &xattr_name, &checksum_bytes)
            .map_err(|e| ZthfsError::Integrity(format!("Failed to set checksum xattr: {e}")))?;

        Ok(())
    }

    /// Remove the checksum extended attribute.
    pub fn remove_checksum_xattr(real_path: &Path, config: &IntegrityConfig) -> ZthfsResult<()> {
        if !config.enabled {
            return Ok(());
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);
        match xattr::remove(real_path, &xattr_name) {
            Ok(()) => Ok(()),
            Err(e) => {
                // If the extended attribute does not exist, ignore the error
                log::debug!("Failed to remove checksum xattr (may not exist): {e}");
                Ok(())
            }
        }
    }

    /// Validate the integrity configuration.
    pub fn validate_config(config: &IntegrityConfig) -> ZthfsResult<()> {
        if config.enabled && config.xattr_namespace.is_empty() {
            return Err(ZthfsError::Config(
                "xattr namespace cannot be empty when integrity is enabled".to_string(),
            ));
        }
        Ok(())
    }

    /// Supported checksum algorithms.
    pub fn supported_algorithms() -> Vec<&'static str> {
        vec!["crc32c", "sha256", "blake2"]
    }

    /// Check if the algorithm is supported.
    pub fn is_algorithm_supported(algorithm: &str) -> bool {
        matches!(algorithm.to_lowercase().as_str(), "crc32c")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IntegrityConfig;

    #[test]
    fn test_checksum_computation() {
        let data = b"Hello, world!";
        let checksum = IntegrityHandler::compute_checksum(data);
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_integrity_verification() {
        let data = b"Hello, world!";
        let checksum = IntegrityHandler::compute_checksum(data);

        assert!(IntegrityHandler::verify_integrity(data, checksum));
        assert!(!IntegrityHandler::verify_integrity(
            b"Hello, world",
            checksum
        ));
    }

    #[test]
    fn test_config_validation() {
        // Disabling integrity verification should always be valid
        let config = IntegrityConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(IntegrityHandler::validate_config(&config).is_ok());

        // When enabling integrity verification, the namespace cannot be empty
        let config = IntegrityConfig {
            enabled: true,
            xattr_namespace: String::new(),
            ..Default::default()
        };
        assert!(IntegrityHandler::validate_config(&config).is_err());

        // Valid configuration
        let config = IntegrityConfig::default();
        assert!(IntegrityHandler::validate_config(&config).is_ok());
    }

    #[test]
    fn test_algorithm_support() {
        assert!(IntegrityHandler::is_algorithm_supported("crc32c"));
        assert!(IntegrityHandler::is_algorithm_supported("CRC32C"));
        assert!(!IntegrityHandler::is_algorithm_supported("md5"));
        assert!(!IntegrityHandler::is_algorithm_supported("sha1"));
    }

    #[test]
    fn test_supported_algorithms() {
        let algorithms = IntegrityHandler::supported_algorithms();
        assert!(algorithms.contains(&"crc32c"));
        assert!(!algorithms.is_empty());
    }
}
