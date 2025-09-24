use crate::config::LogConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessLogEntry {
    pub timestamp: String,
    pub operation: String,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub result: String,
    pub details: Option<String>,
}

impl AccessLogEntry {
    pub fn new(
        operation: String,
        path: String,
        uid: u32,
        gid: u32,
        result: String,
        details: Option<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operation,
            path,
            uid,
            gid,
            result,
            details,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StructuredLogEntry {
    pub timestamp: String,
    pub level: String,
    pub operation: String,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub result: String,
    pub details: Option<String>,
    pub duration_ms: Option<u64>,
    pub file_size: Option<u64>,
    pub checksum: Option<String>,
}

pub struct LogHandler {
    config: LogConfig,
    writer: Arc<Mutex<BufWriter<Box<dyn std::io::Write + Send>>>>,
    pending_logs: Arc<Mutex<VecDeque<StructuredLogEntry>>>,
    batch_size: usize,
}

impl LogHandler {
    /// Create new log handler
    pub fn new(config: &LogConfig) -> ZthfsResult<Self> {
        if !config.enabled {
            // If logging is disabled, return a virtual log handler
            // This handler will not actually write any logs
            let null_writer: Box<dyn std::io::Write + Send> = Box::new(std::io::sink());
            return Ok(Self {
                config: config.clone(),
                writer: Arc::new(Mutex::new(BufWriter::new(null_writer))),
                pending_logs: Arc::new(Mutex::new(VecDeque::new())),
                batch_size: 100,
            });
        }

        // Ensure the log directory exists
        if let Some(parent) = Path::new(&config.file_path).parent() {
            fs::create_dir_all(parent)?;
        }

        // Open the log file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.file_path)?;

        let writer = Arc::new(Mutex::new(BufWriter::new(
            Box::new(file) as Box<dyn std::io::Write + Send>
        )));

        Ok(Self {
            config: config.clone(),
            writer,
            pending_logs: Arc::new(Mutex::new(VecDeque::new())),
            batch_size: 100, // Default batch size
        })
    }

    /// Create log handler with batch size
    pub fn with_batch_size(config: &LogConfig, batch_size: usize) -> ZthfsResult<Self> {
        let mut handler = Self::new(config)?;
        handler.batch_size = batch_size;
        Ok(handler)
    }

    pub fn log_access(
        &self,
        operation: &str,
        path: &str,
        uid: u32,
        gid: u32,
        result: &str,
        details: Option<String>,
    ) -> ZthfsResult<()> {
        self.log_structured(
            LogLevel::Info,
            operation,
            path,
            uid,
            gid,
            result,
            details,
            None,
            None,
            None,
        )
    }

    pub fn log_structured(
        &self,
        level: LogLevel,
        operation: &str,
        path: &str,
        uid: u32,
        gid: u32,
        result: &str,
        details: Option<String>,
        duration_ms: Option<u64>,
        file_size: Option<u64>,
        checksum: Option<String>,
    ) -> ZthfsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let entry = StructuredLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: format!("{level:?}").to_lowercase(),
            operation: operation.to_string(),
            path: path.to_string(),
            uid,
            gid,
            result: result.to_string(),
            details,
            duration_ms,
            file_size,
            checksum,
        };

        // Add to the pending logs queue
        if let Ok(mut logs) = self.pending_logs.lock() {
            logs.push_back(entry);

            // If the number of logs reaches the batch size, write immediately
            if logs.len() >= self.batch_size {
                let logs_to_write: Vec<_> = logs.drain(..self.batch_size).collect();
                drop(logs);
                self.flush_logs(&logs_to_write)?;
            }
        }

        Ok(())
    }

    pub fn log_error(
        &self,
        operation: &str,
        path: &str,
        uid: u32,
        gid: u32,
        error: &str,
        details: Option<String>,
    ) -> ZthfsResult<()> {
        self.log_structured(
            LogLevel::Error,
            operation,
            path,
            uid,
            gid,
            "error",
            Some(error.to_string()),
            None,
            None,
            None,
        )
    }

    pub fn log_performance(
        &self,
        operation: &str,
        path: &str,
        uid: u32,
        gid: u32,
        duration_ms: u64,
        file_size: Option<u64>,
        checksum: Option<String>,
    ) -> ZthfsResult<()> {
        self.log_structured(
            LogLevel::Debug,
            operation,
            path,
            uid,
            gid,
            "success",
            Some(format!("Operation completed in {duration_ms}ms")),
            Some(duration_ms),
            file_size,
            checksum,
        )
    }

    /// Write a batch of log entries to the log file.
    /// It will serialize each log entry to a JSON string, then write it to the file and flush the buffer.
    /// After writing, it will check if the log file needs to be rotated.
    pub fn flush_logs(&self, logs: &[StructuredLogEntry]) -> ZthfsResult<()> {
        if !self.config.enabled || logs.is_empty() {
            return Ok(());
        }

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| ZthfsError::Log("Failed to acquire writer lock".to_string()))?;

        for log in logs {
            let json_line =
                serde_json::to_string(log).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
            writeln!(writer, "{json_line}")?;
        }

        writer.flush()?;

        // Check if the log file needs to be rotated
        self.rotate_if_needed()?;

        Ok(())
    }

    /// Check if the log file needs to be rotated
    pub fn rotate_if_needed(&self) -> ZthfsResult<()> {
        let metadata = std::fs::metadata(&self.config.file_path)?;
        if metadata.len() > self.config.max_size {
            self.rotate_log_file()?;
        }
        Ok(())
    }

    /// Rotate the log file
    pub fn rotate_log_file(&self) -> ZthfsResult<()> {
        let base_path = Path::new(&self.config.file_path);
        let extension = base_path.extension().unwrap_or_default();
        let stem = base_path.file_stem().unwrap_or_default();

        // Delete the oldest log file
        for i in (1..=self.config.rotation_count).rev() {
            let old_file = if i == 1 {
                base_path.with_extension(format!("{}.1", extension.to_string_lossy()))
            } else {
                base_path.with_extension(format!("{}.{}", i, extension.to_string_lossy()))
            };

            if old_file.exists() {
                if i == self.config.rotation_count {
                    fs::remove_file(&old_file)?;
                } else {
                    let new_file = base_path.with_extension(format!(
                        "{}.{}",
                        i + 1,
                        extension.to_string_lossy()
                    ));
                    fs::rename(&old_file, &new_file)?;
                }
            }
        }

        // Rename the current file to .1
        let rotated_file = base_path.with_extension(format!("{}.1", extension.to_string_lossy()));
        fs::rename(&self.config.file_path, &rotated_file)?;

        // Create a new log file
        let new_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&self.config.file_path)?;

        let mut writer = self
            .writer
            .lock()
            .map_err(|_| ZthfsError::Log("Failed to acquire writer lock".to_string()))?;
        *writer = BufWriter::new(Box::new(new_file) as Box<dyn std::io::Write + Send>);

        Ok(())
    }

    /// Flush all pending logs
    pub fn flush_all(&self) -> ZthfsResult<()> {
        if let Ok(mut logs) = self.pending_logs.lock()
            && !logs.is_empty() {
                let logs_to_write = logs.drain(..).collect::<Vec<_>>();
                drop(logs);
                self.flush_logs(&logs_to_write)?;
            }
        Ok(())
    }

    pub fn config(&self) -> &LogConfig {
        &self.config
    }

    pub fn validate_config(config: &LogConfig) -> ZthfsResult<()> {
        if config.enabled {
            if config.file_path.is_empty() {
                return Err(ZthfsError::Config(
                    "Log file path cannot be empty when logging is enabled".to_string(),
                ));
            }
            if config.max_size == 0 {
                return Err(ZthfsError::Config(
                    "Log max size must be greater than 0".to_string(),
                ));
            }
            if config.rotation_count == 0 {
                return Err(ZthfsError::Config(
                    "Log rotation count must be greater than 0".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl Drop for LogHandler {
    fn drop(&mut self) {
        if let Err(e) = self.flush_all() {
            log::error!("Failed to flush logs on drop: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = AccessLogEntry::new(
            "read".to_string(),
            "/test/file.txt".to_string(),
            1000,
            1000,
            "success".to_string(),
            Some("test details".to_string()),
        );

        assert_eq!(entry.operation, "read");
        assert_eq!(entry.path, "/test/file.txt");
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
        assert_eq!(entry.result, "success");
        assert_eq!(entry.details, Some("test details".to_string()));
        assert!(!entry.timestamp.is_empty());
    }

    #[test]
    fn test_log_serialization() {
        let entry = AccessLogEntry::new(
            "write".to_string(),
            "/test/file.txt".to_string(),
            1000,
            1000,
            "success".to_string(),
            None,
        );

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AccessLogEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.operation, deserialized.operation);
        assert_eq!(entry.path, deserialized.path);
    }

    #[test]
    fn test_config_validation() {
        let mut config = LogConfig::default();

        // Disabling logging should always be valid
        config.enabled = false;
        assert!(LogHandler::validate_config(&config).is_ok());

        // When logging is enabled, the file path cannot be empty
        config.enabled = true;
        config.file_path = String::new();
        assert!(LogHandler::validate_config(&config).is_err());

        // Valid configuration
        config.file_path = "/tmp/test.log".to_string();
        assert!(LogHandler::validate_config(&config).is_ok());
    }
}
