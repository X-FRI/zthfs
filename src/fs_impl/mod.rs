use crate::config::FilesystemConfig;
use crate::core::encryption::EncryptionHandler;
use crate::core::integrity::IntegrityHandler;
use crate::core::logging::LogHandler;
use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::security::{FileAccess, SecurityValidator};
use dashmap::DashMap;
use fuser::{
    Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyWrite, Request,
};
use sled::{Db, IVec};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
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
    security_validator: SecurityValidator,
    /// inode to actual file path mapping (using DashMap for fast lookups)
    inodes: Arc<DashMap<u64, PathBuf>>,
    /// Persistent inode database using sled for collision-free inode allocation
    inode_db: Db,
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

        // Initialize sled database for inode management
        let inode_db_path = PathBuf::from(&config.data_dir).join("inode_db");
        let inode_db = sled::open(inode_db_path)?;

        // Pre-allocate inode 1 for root directory (FUSE requirement)
        // This must be done before restoring mappings to ensure root is always inode 1
        Self::ensure_root_inode(&inode_db)?;

        let encryption = EncryptionHandler::new(&config.encryption);
        let logger = Arc::new(LogHandler::new(&config.logging)?);
        let security_validator = SecurityValidator::new(config.security.clone());

        // Restore inode mappings from persistent storage to memory
        let inodes = Arc::new(DashMap::new());
        Self::restore_inode_mappings(&inode_db, &inodes)?;

        Ok(Self {
            config: config.clone(),
            data_dir: PathBuf::from(config.data_dir.clone()),
            encryption,
            logger,
            security_validator,
            inodes,
            inode_db,
        })
    }

    pub fn config(&self) -> &FilesystemConfig {
        &self.config
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Restore inode mappings from persistent sled database to memory DashMap
    /// Uses the reverse mapping (inode -> path) for efficient restoration
    fn restore_inode_mappings(
        inode_db: &Db,
        inodes: &Arc<DashMap<u64, PathBuf>>,
    ) -> ZthfsResult<()> {
        // Use a separate tree/namespace for reverse mappings to avoid key conflicts
        // Inode keys are 8 bytes, path keys are variable length strings
        // We can distinguish them by key length
        let mut restored_count = 0;

        for result in inode_db.iter() {
            let (key, value) = result?;

            // Check if this is an inode -> path mapping (8-byte key = inode)
            if key.len() == 8 {
                // This is an inode -> path reverse mapping
                let inode_bytes: [u8; 8] = key
                    .as_ref()
                    .try_into()
                    .map_err(|_| ZthfsError::Fs("Invalid inode key in database".to_string()))?;
                let inode = u64::from_be_bytes(inode_bytes);

                let path_str = String::from_utf8(value.to_vec())?;
                let path = PathBuf::from(path_str);

                inodes.insert(inode, path);
                restored_count += 1;
            }
            // Skip path -> inode mappings (they have variable length keys)
        }

        log::info!("Restored {restored_count} inode mappings from persistent storage");
        Ok(())
    }

    /// Ensure root directory is always mapped to inode 1 (FUSE requirement)
    /// Inode 0 is invalid/reserved, inode 1 must be root directory
    fn ensure_root_inode(inode_db: &Db) -> ZthfsResult<()> {
        const ROOT_INODE: u64 = 1;
        let root_path = "/";
        let root_path_key = IVec::from(root_path.as_bytes());
        let root_inode_bytes = ROOT_INODE.to_be_bytes();
        let root_inode_key = IVec::from(&root_inode_bytes[..]); // inode as key for reverse mapping

        // Check if root mapping already exists
        if inode_db.get(&root_path_key)?.is_none() {
            // Root mapping doesn't exist, create it atomically
            let mut batch = sled::Batch::default();
            batch.insert(root_path_key, IVec::from(&root_inode_bytes[..])); // path -> inode
            batch.insert(root_inode_key, IVec::from(root_path.as_bytes())); // inode -> path
            inode_db.apply_batch(batch)?;

            log::info!(
                "Initialized root directory inode mapping: {root_path} -> inode {ROOT_INODE}"
            );
        }

        Ok(())
    }

    /// Get inode for a path, creating a new one if it doesn't exist
    /// Uses sled's atomic ID generation to ensure collision-free allocation
    /// Returns inode numbers starting from 1 (FUSE requirement)
    /// Maintains bidirectional mapping: path -> inode and inode -> path
    /// Root directory (/) is always inode 1
    pub fn get_or_create_inode(&self, path: &Path) -> ZthfsResult<u64> {
        // Special case: root directory must always be inode 1
        if path == Path::new("/") {
            return Ok(1);
        }

        let path_str = path.to_string_lossy().to_string();

        // First, check if we already have this path mapped to an inode
        let path_key = IVec::from(path_str.as_bytes());
        if let Some(inode_bytes) = self.inode_db.get(&path_key)? {
            // Path already exists, return its inode
            let inode_bytes: [u8; 8] = inode_bytes
                .as_ref()
                .try_into()
                .map_err(|_| ZthfsError::Fs("Invalid inode data for existing path".to_string()))?;
            let inode = u64::from_be_bytes(inode_bytes);
            Ok(inode)
        } else {
            // Path doesn't exist, generate a new unique inode atomically
            // Add 1 to ensure inode starts from 1 (FUSE requirement)
            let inode = self.inode_db.generate_id()? + 1;
            let inode_bytes = inode.to_be_bytes();
            let inode_key = IVec::from(&inode_bytes[..]); // inode as key for reverse mapping

            // Atomically store both mappings in a sled transaction
            // This ensures path->inode and inode->path mappings are always consistent
            let mut batch = sled::Batch::default();
            batch.insert(path_key, IVec::from(&inode_bytes[..])); // path -> inode
            batch.insert(inode_key, IVec::from(path_str.as_bytes())); // inode -> path
            self.inode_db.apply_batch(batch)?;

            // Also store in memory for fast access
            self.inodes.insert(inode, path.to_path_buf());

            Ok(inode)
        }
    }

    /// Get path for an inode (used by FUSE operations)
    pub fn get_path_for_inode(&self, inode: u64) -> Option<PathBuf> {
        self.inodes.get(&inode).map(|p| p.clone())
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
    pub fn check_permission(&self, uid: u32, gid: u32) -> bool {
        self.config.security.allowed_users.contains(&uid)
            || self.config.security.allowed_groups.contains(&gid)
    }

    /// Check detailed file permissions including POSIX-style access control
    /// This provides more granular permission checking for different operations
    ///
    /// # Arguments
    /// * `uid` - The user ID requesting access
    /// * `gid` - The group ID of the requesting user
    /// * `access` - The type of access being requested
    /// * `file_attr` - Optional file attributes containing ownership and mode information
    pub fn check_file_access(
        &self,
        uid: u32,
        gid: u32,
        access: FileAccess,
        file_attr: Option<&fuser::FileAttr>,
    ) -> bool {
        // Use the security validator for detailed permission checking
        if let Some(attr) = file_attr {
            self.security_validator.check_file_permission(
                uid,
                gid,
                attr.uid,
                attr.gid,
                attr.perm as u32,
                access,
                None, // TODO: pass actual file path for audit logging
            )
        } else {
            // Fall back to basic permission check if no file attributes available
            self.check_permission(uid, gid)
        }
    }
}

impl Filesystem for Zthfs {
    /// When the file system client needs to find a file or directory under the parent directory, it is called.
    fn lookup(&mut self, _req: &Request, _parent: u64, name: &OsStr, reply: ReplyEntry) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the parent path from inode
        let parent_path = {
            match self.get_path_for_inode(_parent) {
                Some(path) => path,
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
            match self.get_path_for_inode(_ino) {
                Some(path) => path,
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
            match self.get_path_for_inode(_ino) {
                Some(path) => path,
                None => {
                    self.logger
                        .log_error("read", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Get file attributes for permission checking
        let file_attr = match operations::FileSystemOperations::get_attr(self, &path) {
            Ok(attr) => attr,
            Err(_) => {
                self.logger
                    .log_error(
                        "read",
                        "get_attr_failed",
                        uid,
                        gid,
                        "Failed to get file attributes",
                        None,
                    )
                    .unwrap_or(());
                reply.error(libc::EIO);
                return;
            }
        };

        // Check read permissions
        if !self.check_file_access(uid, gid, FileAccess::Read, Some(&file_attr)) {
            self.log_access(
                "read",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("Read access denied".to_string()),
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
            match self.get_path_for_inode(_ino) {
                Some(path) => path,
                None => {
                    self.logger
                        .log_error("write", "unknown_inode", uid, gid, "Invalid inode", None)
                        .unwrap_or(());
                    reply.error(libc::ENOENT);
                    return;
                }
            }
        };

        // Get file attributes for permission checking
        let file_attr = match operations::FileSystemOperations::get_attr(self, &path) {
            Ok(attr) => attr,
            Err(_) => {
                self.logger
                    .log_error(
                        "write",
                        "get_attr_failed",
                        uid,
                        gid,
                        "Failed to get file attributes",
                        None,
                    )
                    .unwrap_or(());
                reply.error(libc::EIO);
                return;
            }
        };

        // Check write permissions
        if !self.check_file_access(uid, gid, FileAccess::Write, Some(&file_attr)) {
            self.log_access(
                "write",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("Write access denied".to_string()),
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
                        Some(format!("offset={_offset}, bytes={bytes_written}")),
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
            match self.get_path_for_inode(_ino) {
                Some(path) => path,
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
            match self.get_path_for_inode(_parent) {
                Some(path) => path,
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
            match self.get_path_for_inode(_parent) {
                Some(path) => path,
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

    fn mkdir(&mut self, _req: &Request, _parent: u64, name: &OsStr, mode: u32, _umask: u32, reply: ReplyEntry) {
        let uid = _req.uid();
        let gid = _req.gid();

        // Get the parent path from inode
        let parent_path = {
            match self.get_path_for_inode(_parent) {
                Some(path) => path,
                None => {
                    self.logger
                        .log_error(
                            "mkdir",
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

        // Build the path for the new directory
        let path = parent_path.join(name);

        // Check permission
        if !self.check_permission(uid, gid) {
            self.log_access(
                "mkdir",
                &path.to_string_lossy(),
                uid,
                gid,
                "permission_denied",
                Some("User not authorized".to_string()),
            );
            reply.error(libc::EACCES);
            return;
        }

        // Apply umask to mode
        let effective_mode = mode & !_umask;

        match operations::FileSystemOperations::create_directory(self, &path, effective_mode) {
            Ok(attr) => {
                self.logger
                    .log_access("mkdir", &path.to_string_lossy(), uid, gid, "success", None)
                    .unwrap_or(());
                reply.entry(&TTL, &attr, 0);
            }
            Err(e) => {
                let error_msg = format!("{e}");
                self.logger
                    .log_error(
                        "mkdir",
                        &path.to_string_lossy(),
                        uid,
                        gid,
                        &error_msg,
                        None,
                    )
                    .unwrap_or(());
                // Return appropriate POSIX error code
                let error_code = match &e {
                    ZthfsError::Io(io_err) if io_err.kind() == std::io::ErrorKind::AlreadyExists => libc::EEXIST,
                    _ => libc::EIO,
                };
                reply.error(error_code);
            }
        }
    }
}
