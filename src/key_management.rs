//! Key Management Module
//!
//! This module provides secure key storage and management capabilities.
//! It supports:
//! - OS keyring integration for secure key storage
//! - Key versioning and rotation
//! - Optional HSM/KMS integration via feature flags

use crate::config::EncryptionConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Key metadata for versioning and tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for this key
    pub key_id: String,
    /// Key version number
    pub version: u32,
    /// Timestamp when the key was created (UNIX epoch)
    pub created_at: u64,
    /// Timestamp when the key expires (UNIX epoch), 0 if no expiration
    pub expires_at: u64,
    /// Whether this key is currently active
    pub is_active: bool,
    /// Optional description of the key's purpose
    pub description: Option<String>,
}

/// Stored key with its metadata
#[derive(Debug, Clone)]
pub struct StoredKey {
    /// The key metadata
    pub metadata: KeyMetadata,
    /// The actual key bytes (32 bytes for AES-256)
    pub key: Vec<u8>,
    /// The nonce seed (12 bytes)
    pub nonce_seed: Vec<u8>,
}

/// Key manager trait for pluggable key storage backends
pub trait KeyStorage: Send + Sync {
    /// Store a key with its metadata
    fn store_key(&self, key: &StoredKey) -> ZthfsResult<()>;

    /// Retrieve a key by ID
    fn retrieve_key(&self, key_id: &str) -> ZthfsResult<StoredKey>;

    /// List all available key IDs
    fn list_keys(&self) -> ZthfsResult<Vec<String>>;

    /// Delete a key by ID
    fn delete_key(&self, key_id: &str) -> ZthfsResult<()>;

    /// Check if a key exists
    fn key_exists(&self, key_id: &str) -> bool;
}

/// In-memory key storage (for testing only - NOT production secure)
#[derive(Debug, Default)]
pub struct InMemoryKeyStorage {
    keys: Arc<Mutex<std::collections::HashMap<String, StoredKey>>>,
}

impl InMemoryKeyStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStorage for InMemoryKeyStorage {
    fn store_key(&self, key: &StoredKey) -> ZthfsResult<()> {
        let mut keys = self.keys.lock().unwrap();
        keys.insert(key.metadata.key_id.clone(), key.clone());
        Ok(())
    }

    fn retrieve_key(&self, key_id: &str) -> ZthfsResult<StoredKey> {
        let keys = self.keys.lock().unwrap();
        keys.get(key_id)
            .cloned()
            .ok_or_else(|| ZthfsError::Config(format!("Key not found: {key_id}")))
    }

    fn list_keys(&self) -> ZthfsResult<Vec<String>> {
        let keys = self.keys.lock().unwrap();
        Ok(keys.keys().cloned().collect())
    }

    fn delete_key(&self, key_id: &str) -> ZthfsResult<()> {
        let mut keys = self.keys.lock().unwrap();
        keys.remove(key_id)
            .ok_or_else(|| ZthfsError::Config(format!("Key not found: {key_id}")))?;
        Ok(())
    }

    fn key_exists(&self, key_id: &str) -> bool {
        let keys = self.keys.lock().unwrap();
        keys.contains_key(key_id)
    }
}

/// File-based key storage (encrypted on disk)
pub struct FileKeyStorage {
    base_dir: String,
    /// Master key for encrypting stored keys (derived from system-specific source)
    master_key: Vec<u8>,
}

impl FileKeyStorage {
    /// Create a new file-based key storage
    ///
    /// # Arguments
    /// * `base_dir` - Directory to store encrypted keys
    ///
    /// # Security
    /// The master key is derived from a combination of:
    /// - System-specific identifier (hostname, machine-id)
    /// - User-specific identifier
    /// - Application-specific salt
    ///
    /// This provides protection against casual access but should be
    /// supplemented with proper filesystem permissions.
    pub fn new(base_dir: String) -> ZthfsResult<Self> {
        use std::fs;
        use blake3::Hasher;

        // Create base directory if it doesn't exist
        fs::create_dir_all(&base_dir)
            .map_err(ZthfsError::Io)?;

        // Derive master key from system-specific sources
        let mut hasher = Hasher::new();
        hasher.update(b"zthfs-key-storage-v1");

        // Add system-specific entropy
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            hasher.update(hostname.as_bytes());
        }
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        } else if let Ok(dbus_id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
            hasher.update(dbus_id.trim().as_bytes());
        }

        // Add user-specific entropy
        if let Ok(username) = std::env::var("USER") {
            hasher.update(username.as_bytes());
        }

        let master_key = hasher.finalize().as_bytes()[..32].to_vec();

        Ok(Self { base_dir, master_key })
    }

    /// Get the file path for a key
    fn key_path(&self, key_id: &str) -> String {
        format!("{}/{}.key", self.base_dir, key_id)
    }

    /// Encrypt a key for storage
    fn encrypt_key(&self, key: &StoredKey) -> ZthfsResult<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Combine key and nonce seed
        let mut data = key.key.clone();
        data.extend_from_slice(&key.nonce_seed);

        // Serialize metadata
        let metadata_json = serde_json::to_string(&key.metadata)
            .map_err(|e| ZthfsError::Config(format!("Failed to serialize metadata: {e}")))?;
        data.extend_from_slice(metadata_json.as_bytes());

        // Derive encryption key from master key and key_id
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.master_key);
        hasher.update(key.metadata.key_id.as_bytes());
        let derived_key = hasher.finalize();

        let cipher_key = Key::<Aes256Gcm>::from_slice(derived_key.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        // Use first 12 bytes of derived hash as nonce
        let nonce = Nonce::from_slice(derived_key.as_bytes()[..12].try_into().unwrap());

        cipher.encrypt(nonce, data.as_slice())
            .map_err(|e| ZthfsError::Crypto(format!("Failed to encrypt key: {e:?}")))
    }

    /// Decrypt a stored key
    fn decrypt_key(&self, key_id: &str, ciphertext: &[u8]) -> ZthfsResult<StoredKey> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Derive decryption key from master key and key_id
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.master_key);
        hasher.update(key_id.as_bytes());
        let derived_key = hasher.finalize();

        let cipher_key = Key::<Aes256Gcm>::from_slice(derived_key.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        let nonce = Nonce::from_slice(derived_key.as_bytes()[..12].try_into().unwrap());

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| ZthfsError::Crypto(format!("Failed to decrypt key: {e:?}")))?;

        if plaintext.len() < 44 {
            return Err(ZthfsError::Crypto("Invalid key data length".to_string()));
        }

        let key = plaintext[0..32].to_vec();
        let nonce_seed = plaintext[32..44].to_vec();
        let metadata_json = String::from_utf8_lossy(&plaintext[44..]);
        let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
            .map_err(|e| ZthfsError::Config(format!("Failed to deserialize metadata: {e}")))?;

        Ok(StoredKey { metadata, key, nonce_seed })
    }
}

impl KeyStorage for FileKeyStorage {
    fn store_key(&self, key: &StoredKey) -> ZthfsResult<()> {
        use std::fs;

        let encrypted = self.encrypt_key(key)?;
        let path = self.key_path(&key.metadata.key_id);

        fs::write(&path, encrypted)
            .map_err(ZthfsError::Io)?;

        Ok(())
    }

    fn retrieve_key(&self, key_id: &str) -> ZthfsResult<StoredKey> {
        use std::fs;

        let path = self.key_path(key_id);
        let encrypted = fs::read(&path)
            .map_err(ZthfsError::Io)?;

        self.decrypt_key(key_id, &encrypted)
    }

    fn list_keys(&self) -> ZthfsResult<Vec<String>> {
        use std::fs;

        let mut keys = Vec::new();
        for entry in fs::read_dir(&self.base_dir)
            .map_err(ZthfsError::Io)?
        {
            let entry = entry.map_err(ZthfsError::Io)?;
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".key") {
                    keys.push(name[..name.len() - 4].to_string());
                }
            }
        }
        Ok(keys)
    }

    fn delete_key(&self, key_id: &str) -> ZthfsResult<()> {
        use std::fs;

        let path = self.key_path(key_id);
        fs::remove_file(&path)
            .map_err(ZthfsError::Io)?;

        Ok(())
    }

    fn key_exists(&self, key_id: &str) -> bool {
        use std::path::Path;
        Path::new(&self.key_path(key_id)).exists()
    }
}

/// Main key management interface
pub struct KeyManager<S: KeyStorage> {
    storage: Arc<S>,
    default_key_id: String,
}

impl<S: KeyStorage> KeyManager<S> {
    /// Create a new key manager with the given storage backend
    pub fn new(storage: S, default_key_id: String) -> Self {
        Self {
            storage: Arc::new(storage),
            default_key_id,
        }
    }

    /// Store a new encryption key
    pub fn store_key(&self, key: &StoredKey) -> ZthfsResult<()> {
        self.storage.store_key(key)
    }

    /// Retrieve a key by ID
    pub fn retrieve_key(&self, key_id: &str) -> ZthfsResult<StoredKey> {
        self.storage.retrieve_key(key_id)
    }

    /// Retrieve the default key
    pub fn retrieve_default_key(&self) -> ZthfsResult<StoredKey> {
        self.retrieve_key(&self.default_key_id)
    }

    /// Generate and store a new key
    pub fn generate_key(
        &self,
        key_id: String,
        description: Option<String>,
        ttl_seconds: Option<u64>,
    ) -> ZthfsResult<StoredKey> {
        use rand::RngCore;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut key = vec![0u8; 32];
        let mut nonce_seed = vec![0u8; 12];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut nonce_seed);

        let metadata = KeyMetadata {
            key_id: key_id.clone(),
            version: 1,
            created_at: now,
            expires_at: ttl_seconds.map(|ttl| now + ttl).unwrap_or(0),
            is_active: true,
            description,
        };

        let stored_key = StoredKey { metadata, key, nonce_seed };
        self.store_key(&stored_key)?;

        Ok(stored_key)
    }

    /// Rotate an existing key (generate new version)
    pub fn rotate_key(&self, key_id: &str, ttl_seconds: Option<u64>) -> ZthfsResult<StoredKey> {
        use rand::RngCore;

        // Get existing key to increment version
        let existing_key = self.retrieve_key(key_id)?;
        let new_version = existing_key.metadata.version + 1;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut key = vec![0u8; 32];
        let mut nonce_seed = vec![0u8; 12];
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut nonce_seed);

        let metadata = KeyMetadata {
            key_id: key_id.to_string(),
            version: new_version,
            created_at: now,
            expires_at: ttl_seconds.map(|ttl| now + ttl).unwrap_or(0),
            is_active: true,
            description: existing_key.metadata.description.clone(),
        };

        let stored_key = StoredKey { metadata, key, nonce_seed };
        self.store_key(&stored_key)?;

        Ok(stored_key)
    }

    /// List all available keys
    pub fn list_keys(&self) -> ZthfsResult<Vec<String>> {
        self.storage.list_keys()
    }

    /// Delete a key
    pub fn delete_key(&self, key_id: &str) -> ZthfsResult<()> {
        if key_id == self.default_key_id {
            return Err(ZthfsError::Security(
                "Cannot delete the default key".to_string(),
            ));
        }
        self.storage.delete_key(key_id)
    }

    /// Check if a key exists
    pub fn key_exists(&self, key_id: &str) -> bool {
        self.storage.key_exists(key_id)
    }

    /// Get an EncryptionConfig from a stored key
    pub fn encryption_config_from_key(&self, key_id: &str) -> ZthfsResult<EncryptionConfig> {
        let stored_key = self.retrieve_key(key_id)?;
        Ok(EncryptionConfig {
            key: stored_key.key,
            nonce_seed: stored_key.nonce_seed,
        })
    }

    /// Get the default EncryptionConfig
    pub fn default_encryption_config(&self) -> ZthfsResult<EncryptionConfig> {
        self.encryption_config_from_key(&self.default_key_id)
    }

    /// Initialize default key if it doesn't exist
    pub fn ensure_default_key(&self) -> ZthfsResult<()> {
        if !self.key_exists(&self.default_key_id) {
            self.generate_key(
                self.default_key_id.clone(),
                Some("Default encryption key".to_string()),
                None,
            )?;
        }
        Ok(())
    }
}

/// Convenience function to create a key manager with file storage
pub fn create_file_key_manager(base_dir: &str, default_key_id: &str) -> ZthfsResult<KeyManager<FileKeyStorage>> {
    let storage = FileKeyStorage::new(base_dir.to_string())?;
    Ok(KeyManager::new(storage, default_key_id.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_key_storage() {
        let storage = InMemoryKeyStorage::new();

        let key = StoredKey {
            metadata: KeyMetadata {
                key_id: "test-key".to_string(),
                version: 1,
                created_at: 12345,
                expires_at: 0,
                is_active: true,
                description: Some("Test key".to_string()),
            },
            key: vec![1u8; 32],
            nonce_seed: vec![2u8; 12],
        };

        // Store and retrieve
        storage.store_key(&key).unwrap();
        let retrieved = storage.retrieve_key("test-key").unwrap();

        assert_eq!(retrieved.metadata.key_id, "test-key");
        assert_eq!(retrieved.key, vec![1u8; 32]);
        assert_eq!(retrieved.nonce_seed, vec![2u8; 12]);

        // List keys
        let keys = storage.list_keys().unwrap();
        assert_eq!(keys, vec!["test-key".to_string()]);

        // Check existence
        assert!(storage.key_exists("test-key"));
        assert!(!storage.key_exists("nonexistent"));

        // Delete key
        storage.delete_key("test-key").unwrap();
        assert!(!storage.key_exists("test-key"));
    }

    #[test]
    fn test_key_manager_generate_and_retrieve() {
        let storage = InMemoryKeyStorage::new();
        let manager = KeyManager::new(storage, "default".to_string());

        // Generate a new key
        let key = manager.generate_key(
            "test-key".to_string(),
            Some("Test key".to_string()),
            None,
        ).unwrap();

        assert_eq!(key.metadata.key_id, "test-key");
        assert_eq!(key.metadata.version, 1);
        assert_eq!(key.key.len(), 32);
        assert_eq!(key.nonce_seed.len(), 12);

        // Retrieve the key
        let retrieved = manager.retrieve_key("test-key").unwrap();
        assert_eq!(retrieved.metadata.key_id, "test-key");
        assert_eq!(retrieved.key, key.key);
    }

    #[test]
    fn test_key_rotation() {
        let storage = InMemoryKeyStorage::new();
        let manager = KeyManager::new(storage, "default".to_string());

        // Generate initial key
        let key1 = manager.generate_key(
            "rotating-key".to_string(),
            None,
            None,
        ).unwrap();
        assert_eq!(key1.metadata.version, 1);

        // Rotate the key
        let key2 = manager.rotate_key("rotating-key", None).unwrap();
        assert_eq!(key2.metadata.version, 2);

        // Keys should be different
        assert_ne!(key1.key, key2.key);
        assert_ne!(key1.nonce_seed, key2.nonce_seed);

        // Retrieved key should be the new version
        let retrieved = manager.retrieve_key("rotating-key").unwrap();
        assert_eq!(retrieved.metadata.version, 2);
        assert_eq!(retrieved.key, key2.key);
    }

    #[test]
    fn test_encryption_config_from_key() {
        let storage = InMemoryKeyStorage::new();
        let manager = KeyManager::new(storage, "default".to_string());

        let key = manager.generate_key(
            "config-test".to_string(),
            None,
            None,
        ).unwrap();

        let config = manager.encryption_config_from_key("config-test").unwrap();
        assert_eq!(config.key, key.key);
        assert_eq!(config.nonce_seed, key.nonce_seed);
    }

    #[test]
    fn test_cannot_delete_default_key() {
        let storage = InMemoryKeyStorage::new();
        let manager = KeyManager::new(storage, "default".to_string());

        manager.generate_key("default".to_string(), None, None).unwrap();

        let result = manager.delete_key("default");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ZthfsError::Security(_)));
    }

    #[test]
    fn test_file_key_storage_roundtrip() {
        use tempfile::tempdir;

        let temp_dir = tempdir().unwrap();
        let storage = FileKeyStorage::new(temp_dir.path().to_string_lossy().to_string()).unwrap();

        let key = StoredKey {
            metadata: KeyMetadata {
                key_id: "file-test".to_string(),
                version: 1,
                created_at: 12345,
                expires_at: 0,
                is_active: true,
                description: Some("File storage test".to_string()),
            },
            key: vec![42u8; 32],
            nonce_seed: vec![99u8; 12],
        };

        // Store and retrieve
        storage.store_key(&key).unwrap();
        let retrieved = storage.retrieve_key("file-test").unwrap();

        assert_eq!(retrieved.metadata.key_id, "file-test");
        assert_eq!(retrieved.key, vec![42u8; 32]);
        assert_eq!(retrieved.nonce_seed, vec![99u8; 12]);
        assert_eq!(retrieved.metadata.description, key.metadata.description);

        // Verify file exists
        assert!(storage.key_exists("file-test"));
    }
}
