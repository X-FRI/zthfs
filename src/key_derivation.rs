//! Secure key derivation for ZTHFS master key.
//!
//! This module provides passphrase-based key derivation using Argon2id,
//! a memory-hard KDF that provides strong protection against brute-force
//! attacks and GPU/ASIC-based cracking.

use crate::errors::{ZthfsError, ZthfsResult};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, Algorithm, Params, Version,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Default parameters for Argon2id key derivation.
/// OWASP recommendations for interactive logins.
const DEFAULT_MEMORY_M: u32 = 65536; // 64 MiB
const DEFAULT_T: u32 = 3;
const DEFAULT_P: u32 = 4;

/// Maximum passphrase length (in bytes) to prevent DoS.
const MAX_PASSPHRASE_LEN: usize = 1024;

/// Configuration for key derivation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Salt encoded as base64
    pub salt_b64: String,
    /// Memory cost in KiB
    pub memory_cost: u32,
    /// Time cost (iterations)
    pub time_cost: u32,
    /// Parallelism
    pub parallelism: u32,
}

impl KeyDerivationConfig {
    /// Create a new key derivation config from a passphrase.
    pub fn from_passphrase(passphrase: &str) -> ZthfsResult<Self> {
        Self::from_passphrase_with_params(passphrase, DEFAULT_MEMORY_M, DEFAULT_T, DEFAULT_P)
    }

    /// Create a new key derivation config with custom parameters.
    pub fn from_passphrase_with_params(
        passphrase: &str,
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
    ) -> ZthfsResult<Self> {
        if passphrase.is_empty() {
            return Err(ZthfsError::Config("Passphrase cannot be empty".to_string()));
        }
        if passphrase.len() > MAX_PASSPHRASE_LEN {
            return Err(ZthfsError::Config(format!(
                "Passphrase too long (max {} bytes)",
                MAX_PASSPHRASE_LEN
            )));
        }

        // Generate a random salt
        let salt = SaltString::generate(&mut OsRng);

        Ok(Self {
            salt_b64: salt.as_str().to_string(),
            memory_cost,
            time_cost,
            parallelism,
        })
    }

    /// Get the params for Argon2 from this config.
    fn get_params(&self) -> Result<Params, argon2::Error> {
        Params::new(self.memory_cost, self.time_cost, self.parallelism, None)
    }

    /// Derive the 32-byte master key from the passphrase.
    pub fn derive_key(&self, passphrase: &str) -> ZthfsResult<[u8; 32]> {
        let salt = SaltString::from_b64(&self.salt_b64)
            .map_err(|e| ZthfsError::Crypto(format!("Invalid salt: {e}")))?;
        let mut salt_bytes = [0u8; 16];
        let salt_decoded = salt.decode_b64(&mut salt_bytes)
            .map_err(|e| ZthfsError::Crypto(format!("Failed to decode salt: {e}")))?;

        let params = self.get_params()
            .map_err(|e| ZthfsError::Crypto(format!("Invalid params: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt_decoded, &mut key)
            .map_err(|e| ZthfsError::Crypto(format!("Failed to derive key: {e}")))?;

        Ok(key)
    }

    /// Verify the passphrase by deriving the key and comparing with expected.
    pub fn verify(&self, passphrase: &str, expected_key: &[u8; 32]) -> ZthfsResult<bool> {
        let derived = self.derive_key(passphrase)?;
        Ok(derived == *expected_key)
    }

    /// Save the config to a file.
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> ZthfsResult<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ZthfsError::Io(std::io::Error::other(e)))?;
        std::fs::write(path, json)
            .map_err(|e| ZthfsError::Io(std::io::Error::other(e)))?;
        Ok(())
    }

    /// Load the config from a file.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> ZthfsResult<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| ZthfsError::Io(std::io::Error::other(e)))?;
        serde_json::from_str(&json)
            .map_err(|e| ZthfsError::Config(format!("Failed to parse key derivation config: {e}")))
    }

    /// Get recommended passphrase strength score (0-4).
    pub fn passphrase_strength_score(passphrase: &str) -> u8 {
        let len = passphrase.len();
        if len < 8 { return 0; }
        if len < 12 { return 1; }
        if len < 16 { return 2; }
        if len < 24 { return 3; }
        4
    }

    /// Get a description of passphrase strength.
    pub fn passphrase_strength_description(passphrase: &str) -> &'static str {
        match Self::passphrase_strength_score(passphrase) {
            0 => "Too weak - use at least 12 characters",
            1 => "Weak - consider using a longer passphrase",
            2 => "Moderate - adequate for most purposes",
            3 => "Strong - good security",
            4 => "Very strong - excellent security",
            _ => "Unknown",
        }
    }
}

/// High-security parameters for long-term key storage.
pub fn high_security_params() -> (u32, u32, u32) {
    // m=256 MiB, t=5 iterations, p=2 parallelism
    (262144, 5, 2)
}

/// Fast parameters for testing only - NOT for production.
pub fn fast_params() -> (u32, u32, u32) {
    // m=8 MiB, t=1 iteration, p=1 parallelism
    (8192, 1, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_config_from_passphrase() {
        let passphrase = "correct horse battery staple";
        let config = KeyDerivationConfig::from_passphrase(passphrase).unwrap();

        assert!(!config.salt_b64.is_empty());
        assert_eq!(config.memory_cost, DEFAULT_MEMORY_M);
        assert_eq!(config.time_cost, DEFAULT_T);
        assert_eq!(config.parallelism, DEFAULT_P);
    }

    #[test]
    fn test_key_derivation_derive_key() {
        let passphrase = "correct horse battery staple";
        let config = KeyDerivationConfig::from_passphrase(passphrase).unwrap();

        let key = config.derive_key(passphrase).unwrap();
        assert_eq!(key.len(), 32);

        // Same passphrase produces same key
        let key2 = config.derive_key(passphrase).unwrap();
        assert_eq!(key, key2);

        // Different passphrase produces different key
        let wrong_key = config.derive_key("wrong passphrase").unwrap();
        assert_ne!(key, wrong_key);
    }

    #[test]
    fn test_key_derivation_verify() {
        let passphrase = "correct horse battery staple";
        let config = KeyDerivationConfig::from_passphrase(passphrase).unwrap();
        let key = config.derive_key(passphrase).unwrap();

        assert!(config.verify(passphrase, &key).unwrap());
        assert!(!config.verify("wrong", &key).unwrap());
    }

    #[test]
    fn test_key_derivation_empty_passphrase() {
        let result = KeyDerivationConfig::from_passphrase("");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation_too_long_passphrase() {
        let long_passphrase = "a".repeat(MAX_PASSPHRASE_LEN + 1);
        let result = KeyDerivationConfig::from_passphrase(&long_passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_passphrase_strength_score() {
        assert_eq!(KeyDerivationConfig::passphrase_strength_score("short"), 0);
        assert_eq!(KeyDerivationConfig::passphrase_strength_score("longer12345"), 1);
        assert_eq!(KeyDerivationConfig::passphrase_strength_score("correct horse"), 2);
        assert_eq!(
            KeyDerivationConfig::passphrase_strength_score("correct horse battery"),
            3
        );
        assert_eq!(
            KeyDerivationConfig::passphrase_strength_score("correct horse battery staple"),
            4
        );
    }

    #[test]
    fn test_key_derivation_save_load() {
        use tempfile::tempdir;
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("key_config.json");

        let passphrase = "correct horse battery staple";
        let config = KeyDerivationConfig::from_passphrase(passphrase).unwrap();

        config.save_to_file(&config_path).unwrap();
        let loaded = KeyDerivationConfig::load_from_file(&config_path).unwrap();

        assert_eq!(config.salt_b64, loaded.salt_b64);
        assert_eq!(config.memory_cost, loaded.memory_cost);

        // Loaded config should derive the same key
        let key1 = config.derive_key(passphrase).unwrap();
        let key2 = loaded.derive_key(passphrase).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_passphrases_different_salts() {
        let config1 = KeyDerivationConfig::from_passphrase("passphrase1").unwrap();
        let config2 = KeyDerivationConfig::from_passphrase("passphrase2").unwrap();

        // Different random salts
        assert_ne!(config1.salt_b64, config2.salt_b64);
    }

    #[test]
    fn test_same_passphrase_different_salts() {
        // Each call generates a new salt
        let config1 = KeyDerivationConfig::from_passphrase("same passphrase").unwrap();
        let config2 = KeyDerivationConfig::from_passphrase("same passphrase").unwrap();

        // Different salts
        assert_ne!(config1.salt_b64, config2.salt_b64);

        // But should still derive the same key... wait, that's not right
        // With different salts, the derived keys will be different
        // This is actually the correct behavior - each config is independent
    }

    #[test]
    fn test_high_security_params() {
        let (m, t, p) = high_security_params();
        assert_eq!(m, 262144);
        assert_eq!(t, 5);
        assert_eq!(p, 2);
    }

    #[test]
    fn test_fast_params() {
        let (m, t, p) = fast_params();
        assert_eq!(m, 8192);
        assert_eq!(t, 1);
        assert_eq!(p, 1);
    }

    #[test]
    fn test_custom_params_config() {
        let passphrase = "test passphrase";
        let (m, t, p) = fast_params();
        let config = KeyDerivationConfig::from_passphrase_with_params(passphrase, m, t, p).unwrap();

        assert_eq!(config.memory_cost, m);
        assert_eq!(config.time_cost, t);
        assert_eq!(config.parallelism, p);

        let key = config.derive_key(passphrase).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_invalid_load_from_file() {
        let result = KeyDerivationConfig::load_from_file("/nonexistent/path/config.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_entropy_different_passphrases() {
        let config = KeyDerivationConfig::from_passphrase("test").unwrap();

        let key1 = config.derive_key("passphrase1").unwrap();
        let key2 = config.derive_key("passphrase2").unwrap();

        // Count differing bits
        let diff_count = key1.iter()
            .zip(key2.iter())
            .filter(|(a, b)| a != b)
            .count();

        // Keys should be very different (at least 50% of bytes)
        assert!(diff_count >= 16);
    }
}
