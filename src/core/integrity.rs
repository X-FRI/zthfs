use crate::config::IntegrityConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use blake3;
use crc32c::crc32c;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub struct IntegrityHandler;

impl IntegrityHandler {
    /// Compute CRC32c checksum (legacy method for backward compatibility)
    pub fn compute_crc32c_checksum(data: &[u8]) -> u32 {
        crc32c(data)
    }

    /// Compute cryptographically secure checksum using BLAKE3 with keyed hash (MAC)
    pub fn compute_blake3_checksum(data: &[u8], key: &[u8]) -> Vec<u8> {
        // Ensure key is exactly 32 bytes for BLAKE3
        let mut key_array = [0u8; 32];
        let key_len = key.len().min(32);
        key_array[..key_len].copy_from_slice(&key[..key_len]);

        let hash = blake3::keyed_hash(&key_array, data);
        hash.as_bytes().to_vec()
    }

    /// Compute checksum based on algorithm (returns Vec<u8> for variable length)
    ///
    /// # Errors
    /// Returns `ZthfsError::Integrity` if the algorithm is not supported.
    pub fn compute_checksum(data: &[u8], algorithm: &str, key: &[u8]) -> ZthfsResult<Vec<u8>> {
        match algorithm.to_lowercase().as_str() {
            "crc32c" => Ok(Self::compute_crc32c_checksum(data).to_le_bytes().to_vec()),
            "blake3" => Ok(Self::compute_blake3_checksum(data, key)),
            _ => Err(ZthfsError::Integrity(format!(
                "Unsupported algorithm: {algorithm}. Supported algorithms: {:?}",
                Self::supported_algorithms()
            ))),
        }
    }

    /// Legacy method for CRC32c (maintains backward compatibility)
    pub fn compute_checksum_legacy(data: &[u8]) -> u32 {
        Self::compute_crc32c_checksum(data)
    }

    /// Verify the integrity of the data using the specified algorithm
    ///
    /// # Errors
    /// Returns `ZthfsError::Integrity` if the algorithm is not supported.
    pub fn verify_integrity(
        data: &[u8],
        expected_checksum: &[u8],
        algorithm: &str,
        key: &[u8],
    ) -> ZthfsResult<bool> {
        let computed = Self::compute_checksum(data, algorithm, key)?;
        Ok(computed == expected_checksum)
    }

    /// Legacy verification method for CRC32c
    pub fn verify_integrity_legacy(data: &[u8], expected_checksum: u32) -> bool {
        Self::compute_crc32c_checksum(data) == expected_checksum
    }

    /// Read the checksum from the extended attribute.
    /// Returns the checksum as bytes, with length depending on the algorithm.
    /// If HMAC signing is enabled, verifies the signature before returning the checksum.
    pub fn get_checksum_from_xattr(
        real_path: &Path,
        config: &IntegrityConfig,
    ) -> ZthfsResult<Option<Vec<u8>>> {
        if !config.enabled {
            return Ok(None);
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);
        let checksum_value = match xattr::get(real_path, &xattr_name) {
            Ok(Some(value)) => value,
            Ok(None) => return Ok(None),
            Err(e) => {
                log::debug!("Failed to read checksum xattr: {e}");
                return Ok(None);
            }
        };

        // Validate checksum length based on algorithm
        let expected_len = Self::get_checksum_length(&config.algorithm);
        if checksum_value.len() != expected_len {
            log::warn!(
                "Checksum length mismatch for algorithm {}: expected {}, got {}",
                config.algorithm,
                expected_len,
                checksum_value.len()
            );
            return Ok(None);
        }

        // If HMAC signing is enabled, verify the signature
        if let Some(hmac_key) = config.get_hmac_key() {
            let sig_xattr_name = format!("{}.checksum_sig", config.xattr_namespace);
            match xattr::get(real_path, &sig_xattr_name) {
                Ok(Some(signature)) => {
                    match Self::verify_hmac_signature(&checksum_value, &signature, hmac_key) {
                        Ok(true) => {
                            // Signature valid, return checksum
                        }
                        Ok(false) => {
                            log::warn!("HMAC signature verification failed for checksum");
                            return Ok(None);
                        }
                        Err(e) => {
                            log::warn!("HMAC verification error: {e}");
                            return Ok(None);
                        }
                    }
                }
                Ok(None) => {
                    log::warn!("HMAC signing enabled but no signature found");
                    return Ok(None);
                }
                Err(e) => {
                    log::debug!("Failed to read signature xattr: {e}");
                    return Ok(None);
                }
            }
        }

        Ok(Some(checksum_value))
    }

    /// Compute HMAC-SHA256 signature of a checksum
    pub fn compute_hmac_signature(checksum: &[u8], hmac_key: &[u8]) -> ZthfsResult<Vec<u8>> {
        if hmac_key.len() < 32 {
            return Err(ZthfsError::Integrity(
                "HMAC key must be at least 32 bytes".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| ZthfsError::Crypto(format!("HMAC initialization error: {e}")))?;
        mac.update(checksum);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Verify HMAC-SHA256 signature of a checksum
    pub fn verify_hmac_signature(
        checksum: &[u8],
        signature: &[u8],
        hmac_key: &[u8],
    ) -> ZthfsResult<bool> {
        if hmac_key.len() < 32 {
            return Err(ZthfsError::Integrity(
                "HMAC key must be at least 32 bytes".to_string(),
            ));
        }

        let mut mac = HmacSha256::new_from_slice(hmac_key)
            .map_err(|e| ZthfsError::Crypto(format!("HMAC initialization error: {e}")))?;
        mac.update(checksum);

        // Convert signature slice to array for verification
        use hmac::digest::generic_array::GenericArray;
        if signature.len() != 32 {
            return Ok(false);
        }
        let sig_array = GenericArray::clone_from_slice(&signature[..32]);

        match mac.verify(&sig_array) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Write the computed checksum to the extended attribute of the file.
    /// If HMAC signing is enabled, also stores the signature.
    pub fn set_checksum_xattr(
        real_path: &Path,
        checksum: &[u8],
        config: &IntegrityConfig,
    ) -> ZthfsResult<()> {
        if !config.enabled {
            return Ok(());
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);

        // Validate checksum length before storing
        let expected_len = Self::get_checksum_length(&config.algorithm);
        if checksum.len() != expected_len {
            return Err(ZthfsError::Integrity(format!(
                "Checksum length mismatch for algorithm {}: expected {}, got {}",
                config.algorithm,
                expected_len,
                checksum.len()
            )));
        }

        xattr::set(real_path, &xattr_name, checksum)
            .map_err(|e| ZthfsError::Integrity(format!("Failed to set checksum xattr: {e}")))?;

        // If HMAC signing is enabled, compute and store the signature
        if let Some(hmac_key) = config.get_hmac_key() {
            let signature = Self::compute_hmac_signature(checksum, hmac_key)?;
            let sig_xattr_name = format!("{}.checksum_sig", config.xattr_namespace);
            xattr::set(real_path, &sig_xattr_name, &signature)
                .map_err(|e| ZthfsError::Integrity(format!("Failed to set signature xattr: {e}")))?;
        }

        Ok(())
    }

    /// Get the expected checksum length for a given algorithm
    fn get_checksum_length(algorithm: &str) -> usize {
        match algorithm.to_lowercase().as_str() {
            "crc32c" => 4,  // u32
            "blake3" => 32, // BLAKE3 hash length
            _ => 0,         // Unknown algorithm
        }
    }

    /// Remove the checksum extended attribute.
    /// Also removes the HMAC signature if it exists.
    pub fn remove_checksum_xattr(real_path: &Path, config: &IntegrityConfig) -> ZthfsResult<()> {
        if !config.enabled {
            return Ok(());
        }

        let xattr_name = format!("{}.checksum", config.xattr_namespace);
        let _ = xattr::remove(real_path, &xattr_name);
        log::debug!("Removed checksum xattr (or it didn't exist)");

        // Also remove the signature if HMAC signing was enabled
        let sig_xattr_name = format!("{}.checksum_sig", config.xattr_namespace);
        let _ = xattr::remove(real_path, &sig_xattr_name);
        log::debug!("Removed signature xattr (or it didn't exist)");

        Ok(())
    }

    /// Validate the integrity configuration.
    pub fn validate_config(config: &IntegrityConfig) -> ZthfsResult<()> {
        if config.enabled {
            if config.xattr_namespace.is_empty() {
                return Err(ZthfsError::Config(
                    "xattr namespace cannot be empty when integrity is enabled".to_string(),
                ));
            }
            if !Self::is_algorithm_supported(&config.algorithm) {
                return Err(ZthfsError::Config(format!(
                    "Unsupported integrity algorithm: {}. Supported algorithms: {:?}",
                    config.algorithm,
                    Self::supported_algorithms()
                )));
            }
        }
        Ok(())
    }

    /// Supported checksum algorithms.
    /// Includes both legacy and cryptographically secure algorithms.
    pub fn supported_algorithms() -> Vec<&'static str> {
        vec!["crc32c", "blake3"] // CRC32c (legacy) and BLAKE3 (cryptographically secure)
    }

    /// Check if the algorithm is supported.
    /// This method checks against the actually implemented algorithms.
    pub fn is_algorithm_supported(algorithm: &str) -> bool {
        Self::supported_algorithms().contains(&algorithm.to_lowercase().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IntegrityConfig;

    #[test]
    fn test_checksum_computation() {
        let data = b"Hello, world!";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Test CRC32c
        let crc32c_checksum = IntegrityHandler::compute_checksum(data, "crc32c", key).unwrap();
        assert_eq!(crc32c_checksum.len(), 4);

        // Test BLAKE3
        let blake3_checksum = IntegrityHandler::compute_checksum(data, "blake3", key).unwrap();
        assert_eq!(blake3_checksum.len(), 32);

        // Both should be non-zero
        assert!(!crc32c_checksum.iter().all(|&x| x == 0));
        assert!(!blake3_checksum.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_integrity_verification() {
        let data = b"Hello, world!";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Test CRC32c verification
        let crc32c_checksum = IntegrityHandler::compute_checksum(data, "crc32c", key).unwrap();
        assert!(IntegrityHandler::verify_integrity(data, &crc32c_checksum, "crc32c", key).unwrap());
        assert!(
            !IntegrityHandler::verify_integrity(b"Hello, world", &crc32c_checksum, "crc32c", key)
                .unwrap()
        );

        // Test BLAKE3 verification
        let blake3_checksum = IntegrityHandler::compute_checksum(data, "blake3", key).unwrap();
        assert!(IntegrityHandler::verify_integrity(data, &blake3_checksum, "blake3", key).unwrap());
        assert!(
            !IntegrityHandler::verify_integrity(b"Hello, world", &blake3_checksum, "blake3", key)
                .unwrap()
        );
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
        assert!(!IntegrityHandler::is_algorithm_supported("sha256"));
        assert!(!IntegrityHandler::is_algorithm_supported("blake2"));
    }

    #[test]
    fn test_supported_algorithms() {
        let algorithms = IntegrityHandler::supported_algorithms();
        assert!(algorithms.contains(&"crc32c"));
        assert!(algorithms.contains(&"blake3"));
        assert!(!algorithms.is_empty());
        assert_eq!(algorithms.len(), 2); // CRC32c and BLAKE3 are supported
    }

    #[test]
    fn test_config_validation_algorithm_check() {
        // Valid configuration
        let config = IntegrityConfig::default();
        assert!(IntegrityHandler::validate_config(&config).is_ok());

        // Invalid algorithm
        let config = IntegrityConfig {
            enabled: true,
            algorithm: "sha256".to_string(),
            xattr_namespace: "user.zthfs".to_string(),
            key: vec![1; 32], // Dummy key for test
            hmac_key: None,
        };
        assert!(IntegrityHandler::validate_config(&config).is_err());

        // Empty namespace when enabled
        let config = IntegrityConfig {
            enabled: true,
            algorithm: "crc32c".to_string(),
            xattr_namespace: "".to_string(),
            key: vec![1; 32], // Dummy key for test
            hmac_key: None,
        };
        assert!(IntegrityHandler::validate_config(&config).is_err());

        // Disabled integrity should always be valid even with invalid settings
        let config = IntegrityConfig {
            enabled: false,
            algorithm: "invalid".to_string(),
            xattr_namespace: "".to_string(),
            key: vec![1; 32], // Dummy key for test
            hmac_key: None,
        };
        assert!(IntegrityHandler::validate_config(&config).is_ok());
    }

    #[test]
    fn test_cryptographic_vs_non_cryptographic() {
        let data = b"Sensitive medical data that must be protected";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Both algorithms should work for basic integrity
        let crc32c_checksum = IntegrityHandler::compute_checksum(data, "crc32c", key).unwrap();
        let blake3_checksum = IntegrityHandler::compute_checksum(data, "blake3", key).unwrap();

        assert!(IntegrityHandler::verify_integrity(data, &crc32c_checksum, "crc32c", key).unwrap());
        assert!(IntegrityHandler::verify_integrity(data, &blake3_checksum, "blake3", key).unwrap());

        // But they have different properties
        assert_eq!(crc32c_checksum.len(), 4); // CRC32c is only 4 bytes
        assert_eq!(blake3_checksum.len(), 32); // BLAKE3 is 32 bytes

        // CRC32c can be vulnerable to certain attacks
        // BLAKE3 is cryptographically secure and collision-resistant
    }

    #[test]
    fn test_blake3_collision_resistance() {
        // BLAKE3 has strong collision resistance properties
        let data1 = b"Medical record A: Patient has condition X";
        let data2 = b"Medical record B: Patient has condition Y";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        let checksum1 = IntegrityHandler::compute_checksum(data1, "blake3", key).unwrap();
        let checksum2 = IntegrityHandler::compute_checksum(data2, "blake3", key).unwrap();

        // Different inputs should produce different hashes
        assert_ne!(checksum1, checksum2);

        // Verify integrity
        assert!(IntegrityHandler::verify_integrity(data1, &checksum1, "blake3", key).unwrap());
        assert!(IntegrityHandler::verify_integrity(data2, &checksum2, "blake3", key).unwrap());
        assert!(!IntegrityHandler::verify_integrity(data1, &checksum2, "blake3", key).unwrap());
    }

    #[test]
    fn test_checksum_lengths() {
        let data = b"Test data for checksum length verification";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Test CRC32c length
        let crc32c = IntegrityHandler::compute_checksum(data, "crc32c", key).unwrap();
        assert_eq!(crc32c.len(), 4);

        // Test BLAKE3 length
        let blake3 = IntegrityHandler::compute_checksum(data, "blake3", key).unwrap();
        assert_eq!(blake3.len(), 32);

        // Test that lengths are validated
        let config = IntegrityConfig {
            enabled: true,
            algorithm: "crc32c".to_string(),
            xattr_namespace: "user.test".to_string(),
            key: key.to_vec(),
            hmac_key: None,
        };

        // Wrong length for CRC32c should fail
        assert!(
            IntegrityHandler::set_checksum_xattr(
                std::path::Path::new("/tmp/test"),
                &[1, 2, 3], // Only 3 bytes, should be 4
                &config
            )
            .is_err()
        );

        let config_blake3 = IntegrityConfig {
            enabled: true,
            algorithm: "blake3".to_string(),
            xattr_namespace: "user.test".to_string(),
            key: key.to_vec(),
            hmac_key: None,
        };

        // Wrong length for BLAKE3 should fail
        assert!(
            IntegrityHandler::set_checksum_xattr(
                std::path::Path::new("/tmp/test"),
                &[1, 2, 3, 4], // Only 4 bytes, should be 32
                &config_blake3
            )
            .is_err()
        );
    }

    #[test]
    fn test_backward_compatibility() {
        let data = b"Legacy data with CRC32c checksum";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Legacy CRC32c method should still work
        let legacy_checksum = IntegrityHandler::compute_checksum_legacy(data);
        assert!(IntegrityHandler::verify_integrity_legacy(
            data,
            legacy_checksum
        ));

        // New method with CRC32c should produce same result
        let new_checksum = IntegrityHandler::compute_checksum(data, "crc32c", key).unwrap();
        let new_checksum_u32 = u32::from_le_bytes(new_checksum.as_slice().try_into().unwrap());
        assert_eq!(legacy_checksum, new_checksum_u32);
    }

    #[test]
    fn test_algorithm_case_insensitivity() {
        let data = b"Case insensitive algorithm test";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Test case insensitivity
        let checksum1 = IntegrityHandler::compute_checksum(data, "BLAKE3", key).unwrap();
        let checksum2 = IntegrityHandler::compute_checksum(data, "blake3", key).unwrap();
        let checksum3 = IntegrityHandler::compute_checksum(data, "BlAkE3", key).unwrap();

        assert_eq!(checksum1, checksum2);
        assert_eq!(checksum2, checksum3);

        assert!(IntegrityHandler::is_algorithm_supported("BLAKE3"));
        assert!(IntegrityHandler::is_algorithm_supported("crc32c"));
        assert!(IntegrityHandler::is_algorithm_supported("CRC32C"));
    }

    #[test]
    fn test_mac_security_different_keys() {
        let data = b"Critical medical data that must be protected";
        let key1 = b"0123456789abcdef0123456789abcdef"; // 32-byte test key 1
        let key2 = b"fedcba9876543210fedcba9876543210"; // 32-byte test key 2

        // Same data with different keys should produce different MACs
        let mac1 = IntegrityHandler::compute_checksum(data, "blake3", key1).unwrap();
        let mac2 = IntegrityHandler::compute_checksum(data, "blake3", key2).unwrap();

        assert_ne!(mac1, mac2);

        // Verify each MAC only works with its corresponding key
        assert!(IntegrityHandler::verify_integrity(data, &mac1, "blake3", key1).unwrap());
        assert!(IntegrityHandler::verify_integrity(data, &mac2, "blake3", key2).unwrap());

        // MAC should fail with wrong key
        assert!(!IntegrityHandler::verify_integrity(data, &mac1, "blake3", key2).unwrap());
        assert!(!IntegrityHandler::verify_integrity(data, &mac2, "blake3", key1).unwrap());
    }

    #[test]
    fn test_mac_prevents_forgery_attack() {
        let original_data = b"Patient record: John Doe, Diagnosis: Normal";
        let tampered_data = b"Patient record: John Doe, Diagnosis: Cancer";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Compute MAC for original data
        let original_mac =
            IntegrityHandler::compute_checksum(original_data, "blake3", key).unwrap();

        // Original data should verify
        assert!(
            IntegrityHandler::verify_integrity(original_data, &original_mac, "blake3", key)
                .unwrap()
        );

        // Tampered data should NOT verify with original MAC
        assert!(
            !IntegrityHandler::verify_integrity(tampered_data, &original_mac, "blake3", key)
                .unwrap()
        );

        // Even if attacker computes a new MAC for tampered data, it won't match the stored MAC
        let tampered_mac =
            IntegrityHandler::compute_checksum(tampered_data, "blake3", key).unwrap();
        assert_ne!(original_mac, tampered_mac);
    }

    #[test]
    fn test_unsupported_algorithm_returns_error() {
        let data = b"Test data";
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte test key

        // Unsupported algorithm should return an error instead of panicking
        let result = IntegrityHandler::compute_checksum(data, "md5", key);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unsupported algorithm")
        );
    }

    // ===== HMAC Signing Tests =====

    #[test]
    fn test_hmac_signature_computation() {
        let checksum = b"test_checksum_value_32_bytes!!!!";
        let hmac_key = b"0123456789abcdef0123456789abcdef"; // 32-byte key

        let signature = IntegrityHandler::compute_hmac_signature(checksum, hmac_key).unwrap();
        assert_eq!(signature.len(), 32); // HMAC-SHA256 produces 32 bytes
    }

    #[test]
    fn test_hmac_signature_verification() {
        let checksum = b"test_checksum_value_32_bytes!!!!";
        let hmac_key = b"0123456789abcdef0123456789abcdef"; // 32-byte key

        let signature = IntegrityHandler::compute_hmac_signature(checksum, hmac_key).unwrap();
        assert!(IntegrityHandler::verify_hmac_signature(checksum, &signature, hmac_key).unwrap());
    }

    #[test]
    fn test_hmac_signature_tampering_detection() {
        let checksum = b"test_checksum_value_32_bytes!!!!";
        let hmac_key = b"0123456789abcdef0123456789abcdef"; // 32-byte key

        let signature = IntegrityHandler::compute_hmac_signature(checksum, hmac_key).unwrap();

        // Tampered checksum should not verify
        let tampered_checksum = b"tampered_checksum_value_32b!!";
        assert!(!IntegrityHandler::verify_hmac_signature(tampered_checksum, &signature, hmac_key).unwrap());

        // Tampered signature should not verify
        let mut tampered_signature = signature.clone();
        tampered_signature[0] ^= 0xFF;
        assert!(!IntegrityHandler::verify_hmac_signature(checksum, &tampered_signature, hmac_key).unwrap());
    }

    #[test]
    fn test_hmac_short_key_rejected() {
        let checksum = b"test_checksum_value_32_bytes!!!!";
        let short_key = b"short"; // Less than 32 bytes

        let result = IntegrityHandler::compute_hmac_signature(checksum, short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_integrity_config_hmac_methods() {
        let key = vec![1u8; 32];
        let hmac_key = vec![2u8; 32];

        let config = IntegrityConfig::with_hmac_signing(key, hmac_key.clone());
        assert!(config.hmac_enabled());
        assert_eq!(config.get_hmac_key(), Some(hmac_key.as_slice()));

        // Default config should not have HMAC enabled
        let default_config = IntegrityConfig::new();
        assert!(!default_config.hmac_enabled());
        assert_eq!(default_config.get_hmac_key(), None);
    }

    #[test]
    fn test_checksum_xattr_with_hmac() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test_file.bin");
        std::fs::write(&test_file, b"test data").unwrap();

        let key = vec![1u8; 32];
        let hmac_key = vec![2u8; 32];
        let config = IntegrityConfig::with_hmac_signing(key, hmac_key);

        let checksum = b"test_checksum_value_32_bytes!!!!";

        // Set checksum with HMAC
        IntegrityHandler::set_checksum_xattr(&test_file, checksum, &config).unwrap();

        // Verify checksum was stored
        let retrieved = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();
        assert_eq!(retrieved, Some(checksum.to_vec()));

        // Tamper with the checksum
        xattr::set(&test_file, "user.zthfs.checksum", b"tampered_checksum_value_32b!!").unwrap();

        // Tampered checksum should be rejected (HMAC verification fails)
        let retrieved_tampered = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();
        assert_eq!(retrieved_tampered, None); // Signature verification fails
    }

    #[test]
    fn test_remove_checksum_with_signature() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let test_file = temp_dir.path().join("test_file.bin");
        std::fs::write(&test_file, b"test data").unwrap();

        let key = vec![1u8; 32];
        let hmac_key = vec![2u8; 32];
        let config = IntegrityConfig::with_hmac_signing(key, hmac_key);

        let checksum = b"test_checksum_value_32_bytes!!!!";

        // Set checksum with HMAC
        IntegrityHandler::set_checksum_xattr(&test_file, checksum, &config).unwrap();

        // Verify both are stored
        assert!(xattr::get(&test_file, "user.zthfs.checksum").unwrap().is_some());
        assert!(xattr::get(&test_file, "user.zthfs.checksum_sig").unwrap().is_some());

        // Remove
        IntegrityHandler::remove_checksum_xattr(&test_file, &config).unwrap();

        // Verify both are removed
        assert!(xattr::get(&test_file, "user.zthfs.checksum").unwrap().is_none());
        assert!(xattr::get(&test_file, "user.zthfs.checksum_sig").unwrap().is_none());
    }

    #[test]
    fn test_hmac_different_checksums_different_signatures() {
        let hmac_key = b"0123456789abcdef0123456789abcdef"; // 32-byte key

        let checksum1 = b"checksum_one_32_bytes_value!!!!";
        let checksum2 = b"checksum_two_32_bytes_value!!!!";

        let sig1 = IntegrityHandler::compute_hmac_signature(checksum1, hmac_key).unwrap();
        let sig2 = IntegrityHandler::compute_hmac_signature(checksum2, hmac_key).unwrap();

        assert_ne!(sig1, sig2);
    }
}
