use crate::config::LogConfig;
use crate::errors::{ZthfsError, ZthfsResult};
use crossbeam_channel::{Receiver, Sender, bounded};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::thread;

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

#[derive(Clone, Debug)]
pub struct LogParams {
    pub level: LogLevel,
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

#[derive(Clone, Debug)]
pub struct PerformanceLogParams {
    pub operation: String,
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub duration_ms: u64,
    pub file_size: Option<u64>,
    pub checksum: Option<String>,
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
    sender: Sender<LogMessage>,
    _handle: Option<thread::JoinHandle<()>>, // Keep handle to prevent thread from being detached
}

#[derive(Debug)]
enum LogMessage {
    LogEntry(StructuredLogEntry),
    Flush,
    Shutdown,
}

impl LogHandler {
    /// Create new async log handler
    pub fn new(config: &LogConfig) -> ZthfsResult<Self> {
        // Create a bounded channel for log messages (buffered to prevent blocking)
        let (sender, receiver) = bounded::<LogMessage>(1000);

        if !config.enabled {
            // If logging is disabled, create a dummy handler that discards messages
            return Ok(Self {
                config: config.clone(),
                sender,
                _handle: None,
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

        let writer = BufWriter::new(file);
        let config_clone = config.clone();

        // Spawn the logging thread
        let handle = thread::spawn(move || {
            Self::logging_worker(config_clone, receiver, writer);
        });

        Ok(Self {
            config: config.clone(),
            sender,
            _handle: Some(handle),
        })
    }

    /// Create log handler with batch size
    pub fn with_batch_size(config: &LogConfig, _batch_size: usize) -> ZthfsResult<Self> {
        let handler = Self::new(config)?;
        // Batch size is now handled in the worker thread
        Ok(handler)
    }

    /// The logging worker thread that processes log messages asynchronously
    fn logging_worker(
        config: LogConfig,
        receiver: Receiver<LogMessage>,
        mut writer: BufWriter<std::fs::File>,
    ) {
        let mut buffer = VecDeque::new();
        const BATCH_SIZE: usize = 100;

        loop {
            // Collect messages until we have a batch or receive a flush/shutdown
            while buffer.len() < BATCH_SIZE {
                match receiver.recv() {
                    Ok(LogMessage::LogEntry(entry)) => {
                        buffer.push_back(entry);
                    }
                    Ok(LogMessage::Flush) => {
                        // Flush all pending messages
                        if let Err(e) = Self::flush_buffer(&mut writer, &mut buffer, &config) {
                            log::error!("Failed to flush log buffer: {}", e);
                        }
                        break;
                    }
                    Ok(LogMessage::Shutdown) => {
                        // Flush remaining messages and exit
                        if let Err(e) = Self::flush_buffer(&mut writer, &mut buffer, &config) {
                            log::error!("Failed to flush log buffer on shutdown: {}", e);
                        }
                        return;
                    }
                    Err(_) => {
                        // Channel closed, flush and exit
                        if let Err(e) = Self::flush_buffer(&mut writer, &mut buffer, &config) {
                            log::error!("Failed to flush log buffer on channel close: {}", e);
                        }
                        return;
                    }
                }
            }

            // Flush the batch
            if let Err(e) = Self::flush_buffer(&mut writer, &mut buffer, &config) {
                log::error!("Failed to flush log buffer: {}", e);
            }
        }
    }

    /// Flush a batch of log entries to disk
    fn flush_buffer(
        writer: &mut BufWriter<std::fs::File>,
        buffer: &mut VecDeque<StructuredLogEntry>,
        config: &LogConfig,
    ) -> ZthfsResult<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        // Write all entries in the buffer
        for entry in buffer.drain(..) {
            let json_line = serde_json::to_string(&entry)
                .map_err(|e| ZthfsError::Serialization(e.to_string()))?;
            writeln!(writer, "{}", json_line)?;
        }

        writer.flush()?;

        // Check if log rotation is needed
        if let Err(e) = Self::rotate_if_needed_static(&config) {
            log::error!("Failed to rotate log file: {}", e);
        }

        Ok(())
    }

    /// Static version of rotate_if_needed for use in worker thread
    fn rotate_if_needed_static(config: &LogConfig) -> ZthfsResult<()> {
        let _rotated = Self::rotate_log_file_static(config)?;
        Ok(())
    }

    /// Static version of rotate_log_file for use in worker thread
    /// Returns true if rotation occurred and file needs to be reopened
    fn rotate_log_file_static(config: &LogConfig) -> ZthfsResult<bool> {
        let base_path = Path::new(&config.file_path);
        let extension = base_path.extension().unwrap_or_default();

        // Check if rotation is needed
        let metadata = std::fs::metadata(&config.file_path)?;
        if metadata.len() <= config.max_size {
            return Ok(false);
        }

        // Delete the oldest log file
        for i in (1..=config.rotation_count).rev() {
            let old_file = if i == 1 {
                base_path.with_extension(format!("{}.1", extension.to_string_lossy()))
            } else {
                base_path.with_extension(format!("{}.{}", i, extension.to_string_lossy()))
            };

            if old_file.exists() {
                if i == config.rotation_count {
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
        fs::rename(&config.file_path, &rotated_file)?;

        // Create a new log file
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&config.file_path)?;

        Ok(true)
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
        self.log_structured(LogParams {
            level: LogLevel::Info,
            operation: operation.to_string(),
            path: path.to_string(),
            uid,
            gid,
            result: result.to_string(),
            details,
            duration_ms: None,
            file_size: None,
            checksum: None,
        })
    }

    pub fn log_structured(&self, params: LogParams) -> ZthfsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let entry = StructuredLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: format!("{:?}", params.level).to_lowercase(),
            operation: params.operation,
            path: params.path,
            uid: params.uid,
            gid: params.gid,
            result: params.result,
            details: params.details,
            duration_ms: params.duration_ms,
            file_size: params.file_size,
            checksum: params.checksum,
        };

        // Send log entry to the async worker thread
        self.sender.send(LogMessage::LogEntry(entry)).map_err(|_| {
            ZthfsError::Log("Failed to send log message to worker thread".to_string())
        })?;

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
        self.log_structured(LogParams {
            level: LogLevel::Error,
            operation: operation.to_string(),
            path: path.to_string(),
            uid,
            gid,
            result: error.to_string(),
            details,
            duration_ms: None,
            file_size: None,
            checksum: None,
        })
    }

    pub fn log_performance(&self, params: PerformanceLogParams) -> ZthfsResult<()> {
        self.log_structured(LogParams {
            level: LogLevel::Debug,
            operation: params.operation,
            path: params.path,
            uid: params.uid,
            gid: params.gid,
            result: "success".to_string(),
            details: Some(format!("Operation completed in {}ms", params.duration_ms)),
            duration_ms: Some(params.duration_ms),
            file_size: params.file_size,
            checksum: params.checksum,
        })
    }

    /// Flush all pending log messages to disk (async operation)
    pub fn flush_logs(&self) -> ZthfsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Send flush message to worker thread
        self.sender.send(LogMessage::Flush).map_err(|_| {
            ZthfsError::Log("Failed to send flush message to worker thread".to_string())
        })?;

        Ok(())
    }

    /// Flush all pending log messages and shutdown the worker thread
    pub fn flush_all(&self) -> ZthfsResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Send shutdown message to worker thread
        let _ = self.sender.send(LogMessage::Shutdown);

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
        // Disabling logging should always be valid
        let config = LogConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(LogHandler::validate_config(&config).is_ok());

        // When logging is enabled, the file path cannot be empty
        let config = LogConfig {
            enabled: true,
            file_path: String::new(),
            ..Default::default()
        };
        assert!(LogHandler::validate_config(&config).is_err());

        // Valid configuration
        let config = LogConfig::default();
        assert!(LogHandler::validate_config(&config).is_ok());
    }
}
