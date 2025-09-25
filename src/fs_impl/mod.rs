use crate::config::FilesystemConfig;
use crate::core::encryption::EncryptionHandler;
use crate::core::integrity::IntegrityHandler;
use crate::core::logging::LogHandler;
use crate::errors::ZthfsResult;
use dashmap::DashMap;
use fuser::{
    Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyWrite, Request,
};
use std::ffi::OsStr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub mod operations;
pub mod security;
pub mod utils;

const TTL: Duration = Duration::from_secs(1);

pub struct Zthfs {
    config: FilesystemConfig,
    data_dir: PathBuf,
    encryption: EncryptionHandler,
    logger: Arc<LogHandler>,
    /// inode to actual file path mapping (using DashMap for better concurrency)
    inodes: Arc<DashMap<u64, PathBuf>>,
}

impl Zthfs {
    /// Create new ZTHFS instance
    pub fn new(config: &FilesystemConfig) -> ZthfsResult<Self> {
        // Validate configuration
        config.validate()?;

        // Validate configuration of each component
        EncryptionHandler::validate_config(&config.encryption)?;
        LogHandler::validate_config(&config.logging)?;
        IntegrityHandler::validate_config(&config.integrity)?;

        // Ensure data directory exists
        std::fs::create_dir_all(&config.data_dir)?;

        let encryption = EncryptionHandler::new(&config.encryption);
        let logger = Arc::new(LogHandler::new(&config.logging)?);

        Ok(Self {
            config: config.clone(),
            data_dir: PathBuf::from(config.data_dir.clone()),
            encryption,
            logger,
            inodes: Arc::new(DashMap::new()),
        })
    }

    pub fn config(&self) -> &FilesystemConfig {
        &self.config
    }

    pub fn log_access(
        &self,
        operation: &str,
        path: &str,
        uid: u32,
        gid: u32,
        result: &str,
        details: Option<String>,
    ) {
        if let Err(e) = self
            .logger
            .log_access(operation, path, uid, gid, result, details)
        {
            log::error!("Failed to log access: {e}");
        }
    }

    /// Check if the given user ID (UID) and group ID (GID) have access to the file system.
    /// Check based on the allowed_users and allowed_groups lists in config.security.
    /// TODO: The logic here may be able to be strengthened
    pub fn check_permission(&self, uid: u32, gid: u32) -> bool {
        self.config.security.allowed_users.contains(&uid)
            || self.config.security.allowed_groups.contains(&gid)
    }
}

impl Filesystem for Zthfs {
    /// When the file system client needs to find a file or directory under the parent directory, it is called.
    fn lookup(&mut self, _req: &Request, _parent: u64, name: &OsStr, reply: ReplyEntry) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the parent path from inode
        let parent_path = {
            match self.inodes.get(&_parent) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error(
                            "lookup",
                            "unknown_parent_inode",
                            uid,
                            gid,
                            "Invalid parent inode",
                            None,
                        )
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build the virtual path based on parent and name
        let path = parent_path.join(name);

        // Execute check_permission for permission check. If permission is insufficient, log and return EACCES error.
        if !self.check_permission(uid, gid) {
            self.log_access(
                "lookup",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::get_attr(self, &path) {
            Ok(attr) => {
                self.logger
                    .log_access("lookup", &path.to_string_lossy(), uid, gid, "success", None)
                    .unwrap_or(());

                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "lookup",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());

                reply.error(libc::ENOENT);
            }
        }
    }

    /// Get the attributes of the specified inode (file or directory).
    fn getattr(&mut self, _req: &Request, _ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the actual path from inode
        let path = {
            match self.inodes.get(&_ino) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error("getattr", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        if !self.check_permission(uid, gid) {
            self.log_access(
                "getattr",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::get_attr(self, &path) {
            Ok(attr) => {
                self.logger
                    .log_access(
                        "getattr",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        "success",
                        None,
                    )
                    .unwrap_or(());

                reply.attr(&TTL, &attr);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "getattr",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());

                reply.error(libc::ENOENT);
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the actual path from inode
        let path = {
            match self.inodes.get(&_ino) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error("read", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Execute check_permission for permission check. If permission is insufficient, log and return EACCES error.
        if !self.check_permission(uid, gid) {
            self.log_access(
                "read",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::read_partial_chunked(self, &path, offset, size) {
            Ok(data) => {
                if data.is_empty() {
                    self.logger
                        .log_access("read", &path.to_string_lossy(), uid, gid, "eof", None)
                        .unwrap_or(());
                } else {
                    self.logger
                        .log_access("read", &path.to_string_lossy(), uid, gid, "success", None)
                        .unwrap_or(());
                }

                reply.data(&data);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error("read", &path.to_string_lossy(), uid, gid, &error_msg, None)
                    .unwrap_or(());

                reply.error(libc::EIO);
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the actual path from inode
        let path = {
            match self.inodes.get(&_ino) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error("write", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        if !self.check_permission(uid, gid) {
            self.log_access(
                "write",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        // Use partial write implementation for proper POSIX semantics
        match operations::FileSystemOperations::write_partial(self, &path, _offset, data) {
            Ok(bytes_written) => {
                self.logger
                    .log_access(
                        "write",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        "success",
                        Some(format!("offset={}, bytes={}", _offset, bytes_written)),
                    )
                    .unwrap_or(());

                reply.written(bytes_written);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error("write", &path.to_string_lossy(), uid, gid, &error_msg, None)
                    .unwrap_or(());

                reply.error(libc::EIO);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the actual path from inode
        let path = {
            match self.inodes.get(&_ino) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error("readdir", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        if !self.check_permission(uid, gid) {
            self.log_access(
                "readdir",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::read_dir(self, &path, offset, &mut reply) {
            Ok(()) => {
                self.logger
                    .log_access(
                        "readdir",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        "success",
                        None,
                    )
                    .unwrap_or(());

                reply.ok();
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "readdir",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());

                reply.error(libc::ENOENT);
            }
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        _parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the parent path from inode
        let parent_path = {
            match self.inodes.get(&_parent) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error(
                            "create",
                            "unknown_parent_inode",
                            uid,
                            gid,
                            "Invalid parent inode",
                            None,
                        )
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build the path for the new file
        let path = parent_path.join(name);

        if !self.check_permission(uid, gid) {
            self.log_access(
                "create",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::create_file(self, &path, mode) {
            Ok(attr) => {
                self.logger
                    .log_access("create", &path.to_string_lossy(), uid, gid, "success", None)
                    .unwrap_or(());

                reply.created(&TTL, &attr, 0, 0, 0);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "create",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());

                reply.error(libc::EIO);
            }
        }
    }

    fn unlink(&mut self, _req: &Request, _parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the parent path from inode
        let parent_path = {
            match self.inodes.get(&_parent) {
                Some(path) => path.clone(),
                None => {
                    self.logger
                        .log_error(
                            "unlink",
                            "unknown_parent_inode",
                            uid,
                            gid,
                            "Invalid parent inode",
                            None,
                        )
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Build the path for the file to be removed
        let path = parent_path.join(name);

        // 权限检查
        if !self.check_permission(uid, gid) {
            self.log_access(
                "unlink",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        match operations::FileSystemOperations::remove_file(self, &path) {
            Ok(()) => {
                self.logger
                    .log_access("unlink", &path.to_string_lossy(), uid, gid, "success", None)
                    .unwrap_or(());

                reply.ok();
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "unlink",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());

                reply.error(libc::ENOENT);
            }
        }
    }
}
