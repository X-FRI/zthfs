//! Transaction Management Module
//!
//! This module provides atomic transactions and write-ahead logging (WAL)
//! to prevent data corruption during crashes or power failures.
//!
//! ## Features
//! - Write-Ahead Logging (WAL) for crash recovery
//! - Copy-on-Write (COW) for atomic updates
//! - Transaction rollback support
//! - Automatic recovery from incomplete transactions

use crate::errors::{ZthfsError, ZthfsResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Transaction is in progress
    InProgress,
    /// Transaction completed successfully
    Committed,
    /// Transaction was rolled back
    RolledBack,
}

/// Unique transaction identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransactionId(pub u64);

impl TransactionId {
    /// Generate a new transaction ID based on timestamp and random bytes
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Add some randomness to avoid collisions in rapid succession
        let random = rand::random::<u32>() as u64;

        Self(timestamp ^ (random << 32))
    }
}

impl Default for TransactionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Operation type within a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionOp {
    /// Write file operation
    WriteFile {
        path: String,
        temp_path: String,
        size: u64,
        checksum: Vec<u8>,
    },
    /// Delete file operation
    DeleteFile {
        path: String,
        backup_path: Option<String>,
    },
    /// Rename/move operation
    Rename { from: String, to: String },
}

/// A single transaction entry in the WAL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalEntry {
    /// Unique transaction ID
    pub tx_id: TransactionId,
    /// Transaction status
    pub status: TransactionStatus,
    /// Operations in this transaction
    pub ops: Vec<TransactionOp>,
    /// Timestamp when transaction was created
    pub created_at: u64,
    /// Timestamp when transaction was completed (0 if in progress)
    pub completed_at: u64,
}

/// Write-Ahead Log for crash recovery
pub struct WriteAheadLog {
    wal_dir: PathBuf,
    current_tx: Arc<Mutex<Option<TransactionId>>>,
}

impl WriteAheadLog {
    /// Create a new WAL in the specified directory
    pub fn new(wal_dir: PathBuf) -> ZthfsResult<Self> {
        // Create WAL directory if it doesn't exist
        fs::create_dir_all(&wal_dir)?;

        let wal = Self {
            wal_dir,
            current_tx: Arc::new(Mutex::new(None)),
        };

        // Recover any incomplete transactions on startup
        wal.recover()?;

        Ok(wal)
    }

    /// Get the path for a transaction's WAL file
    fn tx_path(&self, tx_id: &TransactionId) -> PathBuf {
        self.wal_dir.join(format!("tx_{}.wal", tx_id.0))
    }

    /// Begin a new transaction
    pub fn begin_transaction(&self) -> ZthfsResult<TransactionId> {
        let tx_id = TransactionId::new();
        let entry = WalEntry {
            tx_id: tx_id.clone(),
            status: TransactionStatus::InProgress,
            ops: Vec::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            completed_at: 0,
        };

        self.write_entry(&entry)?;

        // Set as current transaction
        *self.current_tx.lock().unwrap() = Some(tx_id.clone());

        Ok(tx_id)
    }

    /// Add an operation to the current transaction
    pub fn add_op(&self, tx_id: &TransactionId, op: TransactionOp) -> ZthfsResult<()> {
        let mut entry = self.read_entry(tx_id)?;
        if entry.status != TransactionStatus::InProgress {
            return Err(ZthfsError::Config(
                "Cannot add operations to a non-in-progress transaction".to_string(),
            ));
        }

        entry.ops.push(op);
        self.write_entry(&entry)?;
        Ok(())
    }

    /// Commit a transaction (mark as complete)
    pub fn commit(&self, tx_id: &TransactionId) -> ZthfsResult<()> {
        let mut entry = self.read_entry(tx_id)?;
        entry.status = TransactionStatus::Committed;
        entry.completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.write_entry(&entry)?;

        // Clear current transaction if it's this one
        let mut current = self.current_tx.lock().unwrap();
        if *current == Some(tx_id.clone()) {
            *current = None;
        }

        Ok(())
    }

    /// Rollback a transaction
    pub fn rollback(&self, tx_id: &TransactionId) -> ZthfsResult<()> {
        let mut entry = self.read_entry(tx_id)?;
        entry.status = TransactionStatus::RolledBack;
        entry.completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.write_entry(&entry)?;

        // Clear current transaction if it's this one
        let mut current = self.current_tx.lock().unwrap();
        if *current == Some(tx_id.clone()) {
            *current = None;
        }

        // Clean up temporary files from the transaction
        self.cleanup_transaction(tx_id)?;

        Ok(())
    }

    /// Delete a committed transaction's WAL file
    pub fn delete(&self, tx_id: &TransactionId) -> ZthfsResult<()> {
        let path = self.tx_path(tx_id);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Read a WAL entry
    fn read_entry(&self, tx_id: &TransactionId) -> ZthfsResult<WalEntry> {
        let path = self.tx_path(tx_id);
        if !path.exists() {
            return Err(ZthfsError::Config(format!(
                "Transaction WAL file not found: {}",
                tx_id.0
            )));
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let entry: WalEntry = bincode::deserialize_from(reader).map_err(|e| {
            ZthfsError::Serialization(format!("Failed to deserialize WAL entry: {e}"))
        })?;

        Ok(entry)
    }

    /// Write a WAL entry
    fn write_entry(&self, entry: &WalEntry) -> ZthfsResult<()> {
        let path = self.tx_path(&entry.tx_id);

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;

        let mut writer = BufWriter::new(file);
        bincode::serialize_into(&mut writer, entry).map_err(|e| {
            ZthfsError::Serialization(format!("Failed to serialize WAL entry: {e}"))
        })?;

        // Sync to disk to ensure durability
        writer.flush()?;
        drop(writer); // Drop writer to release the file
        fs::File::open(&path)?.sync_all()?;

        Ok(())
    }

    /// Clean up temporary files from a transaction
    fn cleanup_transaction(&self, tx_id: &TransactionId) -> ZthfsResult<()> {
        let entry = self.read_entry(tx_id)?;

        for op in &entry.ops {
            match op {
                TransactionOp::WriteFile { temp_path, .. } => {
                    // Remove temporary file
                    if Path::new(temp_path).exists() {
                        fs::remove_file(temp_path)?;
                    }
                }
                TransactionOp::DeleteFile {
                    backup_path: Some(backup),
                    ..
                } => {
                    // Remove backup if exists
                    if Path::new(backup).exists() {
                        fs::remove_file(backup)?;
                    }
                }
                TransactionOp::DeleteFile { .. } => {}
                _ => {}
            }
        }

        // Remove the WAL file itself
        self.delete(tx_id)?;

        Ok(())
    }

    /// Recover incomplete transactions after a crash
    fn recover(&self) -> ZthfsResult<()> {
        let entries = fs::read_dir(&self.wal_dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Only process .wal files
            if path.extension().and_then(|s| s.to_str()) != Some("wal") {
                continue;
            }

            // Read the WAL entry
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let wal_entry: WalEntry = match bincode::deserialize_from(reader) {
                Ok(e) => e,
                Err(_) => {
                    // Corrupted WAL file, remove it
                    log::warn!("Removing corrupted WAL file: {:?}", path);
                    fs::remove_file(&path)?;
                    continue;
                }
            };

            match wal_entry.status {
                TransactionStatus::InProgress => {
                    log::warn!("Recovering incomplete transaction: {}", wal_entry.tx_id.0);

                    // Rollback the incomplete transaction
                    for op in &wal_entry.ops {
                        match op {
                            TransactionOp::WriteFile { temp_path, .. } => {
                                if Path::new(temp_path).exists() {
                                    fs::remove_file(temp_path)?;
                                }
                            }
                            TransactionOp::DeleteFile {
                                path,
                                backup_path: Some(backup),
                            } => {
                                // Restore from backup if exists
                                if Path::new(backup).exists() {
                                    fs::rename(backup, path)?;
                                }
                            }
                            TransactionOp::DeleteFile { .. } => {}
                            _ => {}
                        }
                    }

                    // Mark as rolled back
                    let mut recovered = wal_entry.clone();
                    recovered.status = TransactionStatus::RolledBack;
                    recovered.completed_at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let tx_path = self.tx_path(&recovered.tx_id);
                    let file = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&tx_path)?;

                    let mut writer = BufWriter::new(file);
                    bincode::serialize_into(&mut writer, &recovered).map_err(|e| {
                        ZthfsError::Serialization(format!("Failed to serialize WAL entry: {e}"))
                    })?;
                    writer.flush()?;
                }
                TransactionStatus::Committed => {
                    // Transaction completed successfully, clean up WAL file
                    // But keep it around for a bit for safety
                    let age = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .saturating_sub(wal_entry.completed_at);

                    // Remove WAL files older than 1 hour
                    if age > 3600 {
                        fs::remove_file(&path)?;
                    }
                }
                TransactionStatus::RolledBack => {
                    // Clean up rolled back transactions
                    fs::remove_file(&path)?;
                }
            }
        }

        Ok(())
    }

    /// Get all incomplete transactions
    pub fn get_incomplete_transactions(&self) -> ZthfsResult<Vec<TransactionId>> {
        let mut incomplete = Vec::new();

        for entry in fs::read_dir(&self.wal_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) != Some("wal") {
                continue;
            }

            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let wal_entry: WalEntry = bincode::deserialize_from(reader).map_err(|e| {
                ZthfsError::Serialization(format!("Failed to deserialize WAL entry: {e}"))
            })?;

            if wal_entry.status == TransactionStatus::InProgress {
                incomplete.push(wal_entry.tx_id);
            }
        }

        Ok(incomplete)
    }
}

/// Copy-on-Write helper for atomic file operations
pub struct CowHelper;

impl CowHelper {
    /// Write data to a file atomically using copy-on-write
    /// 1. Write to temporary file
    /// 2. Sync temporary file
    /// 3. Rename temporary to target (atomic on POSIX)
    pub fn atomic_write(path: &Path, data: &[u8]) -> ZthfsResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create temporary file in the same directory
        let temp_path = path.with_extension(format!("tmp_{}", rand::random::<u32>()));

        {
            // Write to temporary file
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp_path)?;

            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
        }

        // Atomic rename (on POSIX systems, rename is atomic)
        fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Create a backup of a file before modifying it
    pub fn create_backup(path: &Path) -> ZthfsResult<PathBuf> {
        if !path.exists() {
            return Err(ZthfsError::Path("File does not exist".to_string()));
        }

        let backup_path = path.with_extension(format!("bak_{}", rand::random::<u32>()));
        fs::copy(path, &backup_path)?;
        Ok(backup_path)
    }

    /// Restore a file from its backup
    pub fn restore_from_backup(backup_path: &Path, target_path: &Path) -> ZthfsResult<()> {
        if !backup_path.exists() {
            return Err(ZthfsError::Path("Backup file does not exist".to_string()));
        }

        fs::copy(backup_path, target_path)?;
        fs::remove_file(backup_path)?;
        Ok(())
    }
}

/// Add bincode dependency for serialization
pub fn check_bincode() -> bool {
    // This is a compile-time check - bincode must be available
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_transaction_id_generation() {
        let id1 = TransactionId::new();
        let id2 = TransactionId::new();

        // IDs should be different (very high probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_cow_atomic_write() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let data = b"Hello, world!";

        // Atomic write
        CowHelper::atomic_write(&file_path, data).unwrap();

        // Verify content
        let written = fs::read(&file_path).unwrap();
        assert_eq!(written, data);
    }

    #[test]
    fn test_cow_overwrite() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Write initial content
        CowHelper::atomic_write(&file_path, b"Initial content").unwrap();

        // Overwrite atomically
        CowHelper::atomic_write(&file_path, b"New content").unwrap();

        // Verify final content
        let written = fs::read(&file_path).unwrap();
        assert_eq!(written, b"New content");
    }

    #[test]
    fn test_backup_and_restore() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        // Create original file
        fs::write(&file_path, b"Original data").unwrap();

        // Create backup
        let backup_path = CowHelper::create_backup(&file_path).unwrap();
        assert!(backup_path.exists());

        // Modify original
        fs::write(&file_path, b"Modified data").unwrap();

        // Restore from backup
        CowHelper::restore_from_backup(&backup_path, &file_path).unwrap();

        // Verify restored content
        let content = fs::read(&file_path).unwrap();
        assert_eq!(content, b"Original data");
        assert!(!backup_path.exists()); // Backup should be removed after restore
    }

    #[test]
    fn test_wal_transaction_lifecycle() {
        let temp_dir = tempdir().unwrap();
        let wal_dir = temp_dir.path().join("wal");
        let wal = WriteAheadLog::new(wal_dir.clone()).unwrap();

        // Begin transaction
        let tx_id = wal.begin_transaction().unwrap();
        assert!(wal.get_incomplete_transactions().unwrap().contains(&tx_id));

        // Add operation
        wal.add_op(
            &tx_id,
            TransactionOp::WriteFile {
                path: "/test/file.txt".to_string(),
                temp_path: "/tmp/file.tmp".to_string(),
                size: 100,
                checksum: vec![1, 2, 3],
            },
        )
        .unwrap();

        // Commit transaction
        wal.commit(&tx_id).unwrap();

        // Should no longer be incomplete
        assert!(!wal.get_incomplete_transactions().unwrap().contains(&tx_id));
    }

    #[test]
    fn test_wal_rollback() {
        let temp_dir = tempdir().unwrap();
        let wal_dir = temp_dir.path().join("wal");
        let wal = WriteAheadLog::new(wal_dir).unwrap();

        // Begin transaction
        let tx_id = wal.begin_transaction().unwrap();

        // Add operation
        wal.add_op(
            &tx_id,
            TransactionOp::WriteFile {
                path: "/test/file.txt".to_string(),
                temp_path: temp_dir
                    .path()
                    .join("temp.tmp")
                    .to_string_lossy()
                    .to_string(),
                size: 100,
                checksum: vec![1, 2, 3],
            },
        )
        .unwrap();

        // Create the temp file
        fs::write(temp_dir.path().join("temp.tmp"), b"temp data").unwrap();

        // Rollback
        wal.rollback(&tx_id).unwrap();

        // Temp file should be cleaned up
        assert!(!temp_dir.path().join("temp.tmp").exists());

        // WAL file should be removed
        assert!(!wal.tx_path(&tx_id).exists());
    }
}
