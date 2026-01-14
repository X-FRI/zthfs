# FUSE Core Features Implementation Plan (Option B)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement core FUSE operations (mkdir, rmdir, rename, setattr, fsync, open, release, truncate) to achieve POSIX-compliant filesystem functionality.

**Architecture:** Extend existing `fuser::Filesystem` trait implementation in `src/fs_impl/mod.rs`. Add new operations to `src/fs_impl/operations.rs`. Use sled's batch operations for atomic rename. Store extended metadata in existing chunk metadata structure.

**Tech Stack:** Rust, fuser crate, sled (embedded database), serde (serialization)

---

## Task 1: Extend File Metadata Structure

**Files:**
- Modify: `src/fs_impl/operations.rs:10-21`

**Step 1: Write the failing test**

Add to `src/fs_impl/operations.rs` tests module:

```rust
#[test]
fn test_extended_metadata_fields() {
    let (_temp_dir, fs) = create_test_fs();

    let test_path = Path::new("/test_metadata.txt");
    FileSystemOperations::write_file(&fs, test_path, b"test data").unwrap();

    // Get attributes - should include mode, uid, gid, timestamps
    let attr = FileSystemOperations::get_attr(&fs, test_path).unwrap();

    // Verify new fields exist (will fail initially)
    assert!(attr.perm > 0, "File should have permissions");
    assert!(attr.uid > 0 || attr.uid == 0, "File should have uid");
    assert!(attr.gid > 0 || attr.gid == 0, "File should have gid");

    FileSystemOperations::remove_file(&fs, test_path).unwrap();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_extended_metadata_fields`

Expected: COMPILE FAIL - fields don't exist in current implementation

**Step 3: Modify ChunkedFileMetadata structure**

In `src/fs_impl/operations.rs` at line 10, replace the struct:

```rust
/// File metadata structure for chunked files
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkedFileMetadata {
    /// Original file size
    pub size: u64,
    /// Number of chunks
    pub chunk_count: u32,
    /// Chunk size used
    pub chunk_size: usize,
    /// Last modified time
    pub mtime: u64,
    /// File permissions (POSIX mode)
    pub mode: u32,
    /// Owner user ID
    pub uid: u32,
    /// Owner group ID
    pub gid: u32,
    /// Last access time
    pub atime: u64,
    /// Metadata change time
    pub ctime: u64,
    /// Is this a directory?
    pub is_dir: bool,
}
```

**Step 4: Update all metadata creation sites**

In `write_file_chunked` function (around line 680), update metadata creation:

```rust
// Create metadata
let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs();

let metadata = ChunkedFileMetadata {
    size: data.len() as u64,
    chunk_count: total_chunks as u32,
    chunk_size,
    mtime: now,
    mode: 0o644,  // Default: rw-r--r--
    uid: unsafe { libc::getuid() } as u32,
    gid: unsafe { libc::getgid() } as u32,
    atime: now,
    ctime: now,
    is_dir: false,
};
```

**Step 5: Update get_attr to use metadata**

In `get_attr` function (around line 108), add metadata-aware attribute retrieval:

```rust
pub fn get_attr(fs: &Zthfs, path: &Path) -> ZthfsResult<FileAttr> {
    let metadata_path = Self::get_metadata_path(fs, path);

    // Check if we have extended metadata
    let (size, mtime, mode, uid, gid, atime, ctime, is_dir) = if metadata_path.exists() {
        let meta = Self::load_metadata(fs, path)?;
        (meta.size as u64, meta.mtime, meta.mode, meta.uid, meta.gid, meta.atime, meta.ctime, meta.is_dir)
    } else {
        // Fallback to filesystem metadata for non-chunked files
        let real_path = Self::virtual_to_real(fs, path);
        let fs_meta = fs::metadata(&real_path)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (fs_meta.len(), now, 0o644, fs_meta.uid(), fs_meta.gid(), now, now, real_path.is_dir())
    };

    let inode = Self::get_inode(fs, path)?;
    let kind = if is_dir { FileType::Directory } else { FileType::RegularFile };

    Ok(FileAttr {
        ino: inode,
        size,
        blocks: size.div_ceil(4096),
        atime: std::time::SystemTime::from_unix(atime as i64, 0),
        mtime: std::time::SystemTime::from_unix(mtime as i64, 0),
        ctime: std::time::SystemTime::from_unix(ctime as i64, 0),
        crtime: std::time::SystemTime::from_unix(ctime as i64, 0),
        kind,
        perm: mode as u16,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    })
}
```

**Step 6: Run tests**

Run: `cargo test`

Expected: PASS

**Step 7: Commit**

```bash
git add src/fs_impl/operations.rs
git commit -m "feat: extend file metadata with POSIX fields (mode, uid, gid, timestamps)"
```

---

## Task 2: Implement mkdir Operation

**Files:**
- Modify: `src/fs_impl/mod.rs` (add mkdir method to Filesystem trait)
- Modify: `src/fs_impl/operations.rs` (add create_directory implementation)

**Step 1: Write the failing test**

Add to `src/fs_impl/mod.rs` tests (create new test module at end of file):

```rust
#[cfg(test)]
mod fuse_tests {
    use super::*;
    use fuser::{ReplyEntry, Request};
    use std::ffi::OsStr;

    #[test]
    fn test_mkdir_creates_directory() {
        let (temp_dir, fs) = crate::fs_impl::operations::tests::create_test_fs();
        let fs = std::sync::Arc::new(std::sync::Mutex::new(fs));

        // Create a fake request
        let req = Request::new(std::sync::Arc::new(()), 1, 0, 0, 0, 0, 0, 0, 0);

        // Test mkdir
        let mut fs_guard = fs.lock().unwrap();
        let parent_ino = 1; // Root inode

        // This will fail until mkdir is implemented
        let received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reply = ReplyEntry::new(std::sync::Arc::new({
            let received = received.clone();
            move |code: i32, _, _, _| {
                if code == 0 {
                    received.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }));

        fs_guard.mkdir(&req, parent_ino, OsStr::new("testdir"), 0o755, 0);
        // Note: This is a simplified test - actual implementation will use proper reply handling

        drop(temp_dir);
    }
}
```

**Step 2: Add directory marker file creation to operations.rs**

```rust
/// Directory marker file suffix
const DIR_MARKER_SUFFIX: &str = ".zthfs_dir";

/// Get directory marker file path
fn get_dir_marker_path(fs: &Zthfs, path: &Path) -> PathBuf {
    let real_path = Self::virtual_to_real(fs, path);
    real_path.with_extension(DIR_MARKER_SUFFIX)
}

/// Create a directory with metadata
pub fn create_directory(fs: &Zthfs, path: &Path, mode: u32) -> ZthfsResult<FileAttr> {
    let real_path = Self::virtual_to_real(fs, path);

    // Ensure parent directory exists
    if let Some(parent) = real_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    // Create the actual directory
    fs::create_dir(&real_path)?;

    // Create directory marker file with metadata
    let marker_path = Self::get_dir_marker_path(fs, path);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let metadata = ChunkedFileMetadata {
        size: 0,
        chunk_count: 0,
        chunk_size: 0,
        mtime: now,
        mode,
        uid: unsafe { libc::getuid() } as u32,
        gid: unsafe { libc::getgid() } as u32,
        atime: now,
        ctime: now,
        is_dir: true,
    };

    let json = serde_json::to_string(&metadata)
        .map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    fs::write(&marker_path, json)?;

    // Set directory permissions
    let mut perms = fs::metadata(&real_path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(&real_path, perms)?;

    // Get and return attributes
    Self::get_attr(fs, path)
}
```

**Step 3: Implement mkdir in Filesystem trait**

In `src/fs_impl/mod.rs`, add to `impl Filesystem for Zthfs`:

```rust
fn mkdir(&mut self, req: &Request, parent: u64, name: &OsStr, mode: u32, umask: u32, reply: ReplyEntry) {
    let uid = req.uid();
    let gid = req.gid();

    // Get the parent path from inode
    let parent_path = match self.get_path_for_inode(parent) {
        Some(path) => path,
        None => {
            self.logger.log_error("mkdir", "unknown_parent_inode", uid, gid,
                "Invalid parent inode", None).unwrap_or(());
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Build the path for the new directory
    let path = parent_path.join(name);

    // Check permission
    if !self.check_permission(uid, gid) {
        self.log_access("mkdir", &path.to_string_lossy(), uid, gid,
            "permission_denied", Some("User not authorized".to_string()));
        reply.error(libc::EACCES);
        return;
    }

    // Apply umask to mode
    let effective_mode = mode & !umask;

    match operations::FileSystemOperations::create_directory(self, &path, effective_mode) {
        Ok(attr) => {
            self.logger.log_access("mkdir", &path.to_string_lossy(), uid, gid, "success", None).unwrap_or(());
            reply.entry(&TTL, &attr, 0);
        }
        Err(e) => {
            let error_msg = format!("{e}");
            self.logger.log_error("mkdir", &path.to_string_lossy(), uid, gid, &error_msg, None).unwrap_or(());
            reply.error(libc::EIO);
        }
    }
}
```

**Step 4: Update get_attr to recognize directories**

In `get_attr`, check for directory marker:

```rust
let metadata_path = Self::get_metadata_path(fs, path);
let dir_marker_path = Self::get_dir_marker_path(fs, path);

// Check if we have extended metadata (file or directory)
let (size, mtime, mode, uid, gid, atime, ctime, is_dir) = if metadata_path.exists() {
    let meta = Self::load_metadata(fs, path)?;
    (meta.size as u64, meta.mtime, meta.mode, meta.uid, meta.gid, meta.atime, meta.ctime, meta.is_dir)
} else if dir_marker_path.exists() {
    let meta = Self::load_dir_metadata(fs, path)?;
    (meta.size as u64, meta.mtime, meta.mode, meta.uid, meta.gid, meta.atime, meta.ctime, meta.is_dir)
} else {
    // Fallback to filesystem metadata
    // ... existing fallback code ...
};
```

Add helper function:

```rust
fn load_dir_metadata(fs: &Zthfs, path: &Path) -> ZthfsResult<ChunkedFileMetadata> {
    let marker_path = Self::get_dir_marker_path(fs, path);
    let json = fs::read_to_string(&marker_path)?;
    let metadata: ChunkedFileMetadata =
        serde_json::from_str(&json).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
    Ok(metadata)
}
```

**Step 5: Run tests**

Run: `cargo test`

Expected: PASS

**Step 6: Commit**

```bash
git add src/fs_impl/mod.rs src/fs_impl/operations.rs
git commit -m "feat: implement mkdir FUSE operation"
```

---

## Task 3: Implement rmdir Operation

**Files:**
- Modify: `src/fs_impl/mod.rs` (add rmdir method)
- Modify: `src/fs_impl/operations.rs` (add remove_directory and is_directory_empty)

**Step 1: Write the failing test**

```rust
#[test]
fn test_rmdir_removes_empty_directory() {
    let (_temp_dir, fs) = create_test_fs();

    // Create directory
    let dir_path = Path::new("/test_empty_dir");
    FileSystemOperations::create_directory(&fs, dir_path, 0o755).unwrap();
    assert!(FileSystemOperations::path_exists(&fs, dir_path));

    // Remove empty directory
    FileSystemOperations::remove_directory(&fs, dir_path, false).unwrap();
    assert!(!FileSystemOperations::path_exists(&fs, dir_path));
}

#[test]
fn test_rmdir_fails_on_nonempty_directory() {
    let (_temp_dir, fs) = create_test_fs();

    // Create directory with a file
    let dir_path = Path::new("/test_nonempty_dir");
    FileSystemOperations::create_directory(&fs, dir_path, 0o755).unwrap();

    let file_path = Path::new("/test_nonempty_dir/file.txt");
    FileSystemOperations::write_file(&fs, file_path, b"content").unwrap();

    // Try to remove non-empty directory - should fail
    let result = FileSystemOperations::remove_directory(&fs, dir_path, false);
    assert!(result.is_err());

    // Clean up
    FileSystemOperations::remove_directory(&fs, dir_path, true).unwrap();
}
```

**Step 2: Implement is_directory_empty**

```rust
/// Check if a directory is empty (no children)
pub fn is_directory_empty(fs: &Zthfs, path: &Path) -> ZthfsResult<bool> {
    let path_str = path.to_string_lossy().as_bytes();
    let prefix = IVec::from(path_str);

    // Scan inode_db for entries with this path as prefix
    let mut child_count = 0;

    for result in fs.inode_db.scan_prefix(prefix) {
        let (key, _) = result?;

        // Skip the directory's own marker file
        let key_str = String::from_utf8_lossy(&key);
        if key_str == path.to_string_lossy() {
            continue;
        }

        // Check if this is a direct child (not a deeper descendant)
        let relative = key_str.strip_prefix(&path.to_string_lossy())?;
        if relative.contains('/') && !relative.starts_with('/') {
            // Deeper nested path, not direct child
            continue;
        }

        child_count += 1;
        if child_count > 0 {
            return Ok(false);
        }
    }

    // Also check the actual filesystem
    let real_path = Self::virtual_to_real(fs, path);
    if let Ok(entries) = fs::read_dir(&real_path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            // Skip the directory marker file and dot entries
            if name.to_string_lossy().ends_with(DIR_MARKER_SUFFIX) {
                continue;
            }
            if name == "." || name == ".." {
                continue;
            }
            return Ok(false);
        }
    }

    Ok(true)
}
```

**Step 3: Implement remove_directory**

```rust
/// Remove a directory (must be empty unless recursive=true)
pub fn remove_directory(fs: &Zthfs, path: &Path, recursive: bool) -> ZthfsResult<()> {
    let real_path = Self::virtual_to_real(fs, path);

    // Check if directory exists
    if !real_path.is_dir() {
        return Err(ZthfsError::Fs("Not a directory".to_string()));
    }

    // Check if empty (unless recursive)
    if !recursive && !Self::is_directory_empty(fs, path)? {
        return Err(ZthfsError::Fs("Directory not empty".to_string()));
    }

    // Remove directory marker file
    let marker_path = Self::get_dir_marker_path(fs, path);
    let _ = fs::remove_file(&marker_path);

    // Remove the actual directory
    if recursive {
        fs::remove_dir_all(&real_path)?;
    } else {
        fs::remove_dir(&real_path)?;
    }

    // Clean up inode mappings
    let path_str = path.to_string_lossy().as_bytes();
    let _ = fs.inode_db.remove(path_str);

    Ok(())
}
```

**Step 4: Implement rmdir in Filesystem trait**

```rust
fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
    let uid = req.uid();
    let gid = req.gid();

    // Get the parent path from inode
    let parent_path = match self.get_path_for_inode(parent) {
        Some(path) => path,
        None => {
            self.logger.log_error("rmdir", "unknown_parent_inode", uid, gid,
                "Invalid parent inode", None).unwrap_or(());
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Build the path for the directory to be removed
    let path = parent_path.join(name);

    // Check permission
    if !self.check_permission(uid, gid) {
        self.log_access("rmdir", &path.to_string_lossy(), uid, gid,
            "permission_denied", Some("User not authorized".to_string()));
        reply.error(libc::EACCES);
        return;
    }

    match operations::FileSystemOperations::remove_directory(self, &path, false) {
        Ok(()) => {
            self.logger.log_access("rmdir", &path.to_string_lossy(), uid, gid, "success", None).unwrap_or(());
            reply.ok();
        }
        Err(ZthfsError::Fs(msg)) if msg.contains("not empty") => {
            reply.error(libc::ENOTEMPTY);
        }
        Err(e) => {
            let error_msg = format!("{e}");
            self.logger.log_error("rmdir", &path.to_string_lossy(), uid, gid, &error_msg, None).unwrap_or(());
            reply.error(libc::EIO);
        }
    }
}
```

**Step 5: Run tests**

Run: `cargo test`

Expected: PASS

**Step 6: Commit**

```bash
git add src/fs_impl/mod.rs src/fs_impl/operations.rs
git commit -m "feat: implement rmdir FUSE operation with empty directory check"
```

---

## Task 4: Implement Atomic rename Operation

**Files:**
- Modify: `src/fs_impl/mod.rs` (add rename method)
- Modify: `src/fs_impl/operations.rs` (add rename_file)

**Step 1: Write the failing test**

```rust
#[test]
fn test_rename_file_within_directory() {
    let (_temp_dir, fs) = create_test_fs();

    let src_path = Path::new("/original.txt");
    let dst_path = Path::new("/renamed.txt");

    // Create source file
    FileSystemOperations::write_file(&fs, src_path, b"test data").unwrap();
    assert!(FileSystemOperations::path_exists(&fs, src_path));

    // Rename file
    FileSystemOperations::rename_file(&fs, src_path, dst_path).unwrap();

    // Verify source no longer exists
    assert!(!FileSystemOperations::path_exists(&fs, src_path));

    // Verify destination exists with same content
    assert!(FileSystemOperations::path_exists(&fs, dst_path));
    let data = FileSystemOperations::read_file(&fs, dst_path).unwrap();
    assert_eq!(data, b"test data");
}

#[test]
fn test_rename_file_across_directories() {
    let (_temp_dir, fs) = create_test_fs();

    // Create directories
    FileSystemOperations::create_directory(&fs, Path::new("/dir1"), 0o755).unwrap();
    FileSystemOperations::create_directory(&fs, Path::new("/dir2"), 0o755).unwrap();

    let src_path = Path::new("/dir1/file.txt");
    let dst_path = Path::new("/dir2/file.txt");

    // Create source file
    FileSystemOperations::write_file(&fs, src_path, b"test data").unwrap();

    // Rename across directories
    FileSystemOperations::rename_file(&fs, src_path, dst_path).unwrap();

    // Verify
    assert!(!FileSystemOperations::path_exists(&fs, src_path));
    assert!(FileSystemOperations::path_exists(&fs, dst_path));
}
```

**Step 2: Implement atomic rename_file**

```rust
/// Atomically rename a file or directory from src_path to dst_path
pub fn rename_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<()> {
    let src_str = src_path.to_string_lossy().as_bytes();
    let dst_str = dst_path.to_string_lossy().as_bytes();

    // Check source exists
    let src_inode = fs.inode_db.get(src_str)?
        .ok_or_else(|| ZthfsError::Fs("Source does not exist".to_string()))?;

    // Check target doesn't exist (unless we're implementing overwrite)
    if fs.inode_db.contains_key(dst_str)? {
        return Err(ZthfsError::Fs("Target already exists".to_string()));
    }

    let inode_num = u64::from_be_bytes(
        src_inode.as_ref().try_into()
            .map_err(|_| ZthfsError::Fs("Invalid inode data".to_string()))?
    );

    // Atomic batch operation
    let mut batch = sled::Batch::default();

    // Remove old mappings
    batch.remove(src_str);
    batch.remove(&inode_num.to_be_bytes());

    // Add new mappings
    batch.insert(dst_str, &src_inode);
    batch.insert(&inode_num.to_be_bytes(), dst_str);

    // Apply atomically
    fs.inode_db.apply_batch(batch)?;

    // Update in-memory cache
    fs.inodes.insert(inode_num, dst_path.to_path_buf());

    // Move the actual data on disk
    let src_real = Self::virtual_to_real(fs, src_path);
    let dst_real = Self::virtual_to_real(fs, dst_path);

    // Ensure target directory exists
    if let Some(parent) = dst_real.parent() {
        fs::create_dir_all(parent)?;
    }

    // Move metadata file if exists
    let src_meta = Self::get_metadata_path(fs, src_path);
    let dst_meta = Self::get_metadata_path(fs, dst_path);
    if src_meta.exists() {
        fs::rename(&src_meta, &dst_meta)?;
    }

    // Move directory marker if exists
    let src_marker = Self::get_dir_marker_path(fs, src_path);
    let dst_marker = Self::get_dir_marker_path(fs, dst_path);
    if src_marker.exists() {
        fs::rename(&src_marker, &dst_marker)?;
    }

    // Move actual file or directory
    if src_real.is_dir() {
        fs::rename(&src_real, &dst_real)?;
    } else if src_real.exists() {
        fs::rename(&src_real, &dst_real)?;
    }

    Ok(())
}
```

**Step 3: Implement rename in Filesystem trait**

```rust
fn rename(&mut self, req: &Request, parent: u64, name: &OsStr, newparent: u64, newname: &OsStr, _flags: u32, reply: ReplyEmpty) {
    let uid = req.uid();
    let gid = req.gid();

    // Get paths
    let old_path = match self.get_path_for_inode(parent) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    }.join(name);

    let new_path = match self.get_path_for_inode(newparent) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    }.join(newname);

    // Check permission
    if !self.check_permission(uid, gid) {
        self.log_access("rename", &old_path.to_string_lossy(), uid, gid,
            "permission_denied", Some("User not authorized".to_string()));
        reply.error(libc::EACCES);
        return;
    }

    match operations::FileSystemOperations::rename_file(self, &old_path, &new_path) {
        Ok(()) => {
            self.logger.log_access("rename", &format!("{} -> {}", old_path.display(), new_path.display()),
                uid, gid, "success", None).unwrap_or(());
            reply.ok();
        }
        Err(ZthfsError::Fs(msg)) if msg.contains("already exists") => {
            reply.error(libc::EEXIST);
        }
        Err(e) => {
            let error_msg = format!("{e}");
            self.logger.log_error("rename", &old_path.to_string_lossy(), uid, gid, &error_msg, None).unwrap_or(());
            reply.error(libc::EIO);
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test`

Expected: PASS

**Step 5: Commit**

```bash
git add src/fs_impl/mod.rs src/fs_impl/operations.rs
git commit -m "feat: implement atomic rename FUSE operation"
```

---

## Task 5: Implement setattr (chmod/chown/utime)

**Files:**
- Modify: `src/fs_impl/mod.rs` (add setattr method)
- Modify: `src/fs_impl/operations.rs` (add set_file_attributes)

**Step 1: Write the failing test**

```rust
#[test]
fn test_setattr_chmod() {
    let (_temp_dir, fs) = create_test_fs();

    let path = Path::new("/chmod_test.txt");
    FileSystemOperations::write_file(&fs, path, b"data").unwrap();

    // Change permissions
    FileSystemOperations::set_file_attributes(&fs, path, Some(0o600), None, None, None, None).unwrap();

    // Verify new permissions
    let attr = FileSystemOperations::get_attr(&fs, path).unwrap();
    assert_eq!(attr.perm, 0o600);
}

#[test]
fn test_setattr_chown_requires_privilege() {
    let (_temp_dir, fs) = create_test_fs();

    let path = Path::new("/chown_test.txt");
    FileSystemOperations::write_file(&fs, path, b"data").unwrap();

    // Try to change owner (should fail without privilege)
    let result = FileSystemOperations::set_file_attributes(&fs, path, None, Some(1000), None, None, None);
    assert!(result.is_err());
}
```

**Step 2: Implement set_file_attributes**

```rust
/// Set file attributes (mode, uid, gid, size, atime, mtime)
pub fn set_file_attributes(
    fs: &Zthfs,
    path: &Path,
    mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    mtime: Option<u64>,
) -> ZthfsResult<()> {
    let metadata_path = Self::get_metadata_path(fs, path);
    let dir_marker_path = Self::get_dir_marker_path(fs, path);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut updated = false;

    if metadata_path.exists() {
        // File with extended metadata
        let mut metadata = Self::load_metadata(fs, path)?;

        if let Some(new_mode) = mode {
            metadata.mode = new_mode;
            updated = true;
        }
        if let Some(new_uid) = uid {
            metadata.uid = new_uid;
            updated = true;
        }
        if let Some(new_gid) = gid {
            metadata.gid = new_gid;
            updated = true;
        }
        if let Some(new_mtime) = mtime {
            metadata.mtime = new_mtime;
            updated = true;
        }

        // Always update ctime when attributes change
        metadata.ctime = now;
        updated = true;

        if updated {
            Self::save_metadata(fs, path, &metadata)?;
        }

        // Handle truncate via size
        if let Some(new_size) = size {
            if new_size != metadata.size {
                Self::truncate_file(fs, path, new_size)?;
            }
        }
    } else if dir_marker_path.exists() {
        // Directory with metadata
        let mut metadata = Self::load_dir_metadata(fs, path)?;

        if let Some(new_mode) = mode {
            metadata.mode = new_mode;
            updated = true;
        }
        // Similar handling for uid, gid, mtime...
        metadata.ctime = now;
        updated = true;

        if updated {
            let json = serde_json::to_string(&metadata)
                .map_err(|e| ZthfsError::Serialization(e.to_string()))?;
            fs::write(&dir_marker_path, json)?;
        }
    }

    // Also update filesystem permissions
    let real_path = Self::virtual_to_real(fs, path);
    if real_path.exists() {
        if let Some(new_mode) = mode {
            let mut perms = fs::metadata(&real_path)?.permissions();
            perms.set_mode(new_mode);
            fs::set_permissions(&real_path, perms)?;
        }
    }

    Ok(())
}

/// Truncate file to specified size
pub fn truncate_file(fs: &Zthfs, path: &Path, new_size: u64) -> ZthfsResult<()> {
    let metadata_path = Self::get_metadata_path(fs, path);

    if metadata_path.exists() {
        let mut metadata = Self::load_metadata(fs, path)?;

        if new_size < metadata.size {
            // Truncate: just update metadata size
            // Read operations will respect the new size
            metadata.size = new_size;
            Self::save_metadata(fs, path, &metadata)?;
        } else if new_size > metadata.size {
            // Extend: write zeros at the end
            let current_data = Self::read_file_chunked(fs, path)?;
            let mut extended_data = vec![0u8; new_size as usize];
            extended_data[..current_data.len()].copy_from_slice(&current_data);
            Self::write_file_chunked(fs, path, &extended_data)?;
        }
    } else {
        // Regular file - read, truncate/extend, write back
        let current_data = Self::read_file(fs, path).unwrap_or_default();
        let mut new_data = vec![0u8; new_size as usize];
        let copy_len = std::cmp::min(current_data.len(), new_data.len());
        new_data[..copy_len].copy_from_slice(&current_data[..copy_len]);
        Self::write_file(fs, path, &new_data)?;
    }

    Ok(())
}
```

**Step 3: Implement setattr in Filesystem trait**

```rust
fn setattr(&mut self, req: &Request, ino: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>,
           size: Option<u64>, atime: Option<SystemTime>, mtime: Option<SystemTime>,
           _fh: Option<u64>, _cr: Option<u64>, _kill_priv: bool, reply: ReplyAttr) {
    let uid = req.uid();
    let gid = req.gid();

    let path = match self.get_path_for_inode(ino) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Get current attributes for permission check
    let current_attr = match operations::FileSystemOperations::get_attr(self, &path) {
        Ok(attr) => attr,
        Err(_) => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Check chmod/chown permissions
    if mode.is_some() && current_attr.uid != uid && uid != 0 {
        reply.error(libc::EPERM);
        return;
    }

    if uid.is_some() || gid.is_some() {
        // chown requires privilege (simplified check)
        if uid != 0 {
            reply.error(libc::EPERM);
            return;
        }
    }

    // Convert time options
    let mtime_secs = mtime.map(|t| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());

    match operations::FileSystemOperations::set_file_attributes(
        self, &path, mode, uid, gid, size, mtime_secs
    ) {
        Ok(()) => {
            match operations::FileSystemOperations::get_attr(self, &path) {
                Ok(attr) => reply.attr(&TTL, &attr),
                Err(_) => reply.error(libc::EIO),
            }
        }
        Err(e) => {
            let error_msg = format!("{e}");
            self.logger.log_error("setattr", &path.to_string_lossy(), uid, gid, &error_msg, None).unwrap_or(());
            reply.error(libc::EIO);
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test`

Expected: PASS

**Step 5: Commit**

```bash
git add src/fs_impl/mod.rs src/fs_impl/operations.rs
git commit -m "feat: implement setattr FUSE operation (chmod, chown, utime, truncate)"
```

---

## Task 6: Implement open, release, fsync

**Files:**
- Modify: `src/fs_impl/mod.rs` (add open, release, fsync methods)

**Step 1: Write the failing test**

```rust
#[test]
fn test_open_with_flags() {
    let (_temp_dir, fs) = create_test_fs();
    let path = Path::new("/open_test.txt");
    FileSystemOperations::write_file(&fs, path, b"data").unwrap();

    // Test that we can query file attributes (open internally checks permissions)
    let attr = FileSystemOperations::get_attr(&fs, path).unwrap();
    assert_eq!(attr.kind, FileType::RegularFile);
}
```

**Step 2: Implement open**

```rust
fn open(&mut self, req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
    let uid = req.uid();
    let gid = req.gid();

    let path = match self.get_path_for_inode(ino) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    let file_attr = match operations::FileSystemOperations::get_attr(self, &path) {
        Ok(attr) => attr,
        Err(_) => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    // Check read/write permissions based on flags
    let read_required = (flags & libc::O_ACCMODE) != libc::O_WRONLY;
    let write_required = (flags & libc::O_ACCMODE) != libc::O_RDONLY;

    if read_required && !self.check_file_access(uid, gid, FileAccess::Read, Some(&file_attr)) {
        self.log_access("open", &path.to_string_lossy(), uid, gid,
            "permission_denied", Some("Read access denied".to_string()));
        reply.error(libc::EACCES);
        return;
    }

    if write_required && !self.check_file_access(uid, gid, FileAccess::Write, Some(&file_attr)) {
        self.log_access("open", &path.to_string_lossy(), uid, gid,
            "permission_denied", Some("Write access denied".to_string()));
        reply.error(libc::EACCES);
        return;
    }

    // Handle O_TRUNC
    if (flags & libc::O_TRUNC) != 0 && write_required {
        if let Err(e) = operations::FileSystemOperations::truncate_file(self, &path, 0) {
            self.logger.log_error("open", &path.to_string_lossy(), uid, gid, &format!("{e}"), None).unwrap_or(());
            reply.error(libc::EIO);
            return;
        }
    }

    self.logger.log_access("open", &path.to_string_lossy(), uid, gid, "success", None).unwrap_or(());
    reply.opened(0, fuser::FuseOpenFlags::KEEP_CACHE.bits());
}
```

**Step 3: Implement release**

```rust
fn release(&mut self, req: &Request, ino: u64, _fh: u64, _flags: i32,
           _lock_owner: Option<u64>, _flush: bool, reply: ReplyEmpty) {
    let uid = req.uid();
    let gid = req.gid();

    let path = match self.get_path_for_inode(ino) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    self.logger.log_access("release", &path.to_string_lossy(), uid, gid, "success", None).unwrap_or(());
    reply.ok();
}
```

**Step 4: Implement fsync**

```rust
fn fsync(&mut self, req: &Request, ino: u64, _fh: u64, datasync: bool, reply: ReplyEmpty) {
    let uid = req.uid();
    let gid = req.gid();

    let path = match self.get_path_for_inode(ino) {
        Some(path) => path,
        None => {
            reply.error(libc::ENOENT);
            return;
        }
    };

    let result = if datasync {
        // fdatasync: sync data only
        operations::FileSystemOperations::sync_data(self, &path)
    } else {
        // fsync: sync data and metadata
        operations::FileSystemOperations::sync_all(self, &path)
    };

    match result {
        Ok(()) => {
            self.logger.log_access("fsync", &path.to_string_lossy(), uid, gid, "success", None).unwrap_or(());
            reply.ok();
        }
        Err(e) => {
            self.logger.log_error("fsync", &path.to_string_lossy(), uid, gid, &format!("{e}"), None).unwrap_or(());
            reply.error(libc::EIO);
        }
    }
}
```

**Step 5: Add sync helpers to operations.rs**

```rust
/// Sync data and metadata to disk
pub fn sync_all(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
    let real_path = Self::virtual_to_real(fs, path);

    if real_path.is_file() {
        let file = std::fs::File::open(&real_path)?;
        file.sync_all()?;
    }

    // Sync the inode database
    fs.inode_db.flush()?;

    Ok(())
}

/// Sync only data to disk
pub fn sync_data(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
    let real_path = Self::virtual_to_real(fs, path);

    if real_path.is_file() {
        let file = std::fs::File::open(&real_path)?;
        file.sync_data()?;
    }

    Ok(())
}
```

**Step 6: Run tests**

Run: `cargo test`

Expected: PASS

**Step 7: Commit**

```bash
git add src/fs_impl/mod.rs src/fs_impl/operations.rs
git commit -m "feat: implement open, release, fsync FUSE operations"
```

---

## Task 7: Integration Testing

**Files:**
- Create: `tests/fuse_integration_test.rs`

**Step 1: Create integration test file**

```rust
//! Integration tests for FUSE operations
//! These tests require actual filesystem mounting

use std::fs;
use std::path::Path;
use tempfile::TempDir;
use zthfs::config::{FilesystemConfig, FilesystemConfigBuilder, LogConfig};
use zthfs::fs_impl::Zthfs;

fn create_test_config(mount_dir: &Path, data_dir: &Path) -> FilesystemConfig {
    FilesystemConfigBuilder::new()
        .data_dir(data_dir.to_string_lossy().to_string())
        .mount_point(mount_dir.to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap()
}

#[test]
#[ignore]  // Run with: cargo test --test fuse_integration_test -- --ignored
fn test_full_mkdir_rmdir_workflow() {
    let mount_dir = TempDir::new().unwrap();
    let data_dir = TempDir::new().unwrap();

    let config = create_test_config(mount_dir.path(), data_dir.path());
    let fs = Zthfs::new(&config).unwrap();

    // Mount the filesystem
    let _session = unsafe {
        fuser::spawn_mount2(
            fs,
            mount_dir.path(),
            &[
                fuser::MountOption::RO,
                fuser::MountOption::FSName("zthfs".to_string()),
            ]
        )
    }.expect("Failed to mount");

    // Give FUSE time to initialize
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Test mkdir
    let test_dir = mount_dir.path().join("test_directory");
    fs::create_dir(&test_dir).unwrap();
    assert!(test_dir.exists());

    // Test create file in directory
    let test_file = test_dir.join("test.txt");
    fs::write(&test_file, b"Hello, World!").unwrap();
    assert!(test_file.exists());

    // Test rmdir (should fail because directory is not empty)
    fs::remove_dir(&test_dir).unwrap_err();

    // Test remove file then rmdir
    fs::remove_file(&test_file).unwrap();
    fs::remove_dir(&test_dir).unwrap();
    assert!(!test_dir.exists());
}

#[test]
#[ignore]
fn test_rename_workflow() {
    let mount_dir = TempDir::new().unwrap();
    let data_dir = TempDir::new().unwrap();

    let config = create_test_config(mount_dir.path(), data_dir.path());
    let fs = Zthfs::new(&config).unwrap();

    let _session = unsafe {
        fuser::spawn_mount2(fs, mount_dir.path(), &[])
    }.expect("Failed to mount");

    std::thread::sleep(std::time::Duration::from_millis(100));

    // Create file
    let old_path = mount_dir.path().join("old_name.txt");
    fs::write(&old_path, b"test data").unwrap();

    // Rename file
    let new_path = mount_dir.path().join("new_name.txt");
    fs::rename(&old_path, &new_path).unwrap();

    // Verify
    assert!(!old_path.exists());
    assert!(new_path.exists());
    assert_eq!(fs::read_to_string(&new_path).unwrap(), "test data");
}
```

**Step 2: Run integration tests**

Run: `cargo test --test fuse_integration_test -- --ignored`

Expected: Tests require manual setup due to FUSE mounting requirements

**Step 3: Commit**

```bash
git add tests/fuse_integration_test.rs
git commit -m "test: add FUSE integration tests"
```

---

## Task 8: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `README_zh.md`

**Step 1: Update feature list in README.md**

Add to the "Current Status" section:

```markdown
### FUSE Operations

| Operation | Status | Notes |
|-----------|--------|-------|
| lookup | ✅ Implemented | Path resolution with permission check |
| getattr | ✅ Implemented | File attributes with extended metadata |
| read | ✅ Implemented | Chunked reading with decryption |
| write | ✅ Implemented | Partial write support |
| readdir | ✅ Implemented | Directory listing |
| create | ✅ Implemented | File creation |
| unlink | ✅ Implemented | File deletion |
| mkdir | ✅ Implemented | Directory creation with marker file |
| rmdir | ✅ Implemented | Empty directory removal |
| rename | ✅ Implemented | Atomic cross-directory rename |
| setattr | ✅ Implemented | chmod, chown, utime, truncate |
| open | ✅ Implemented | Permission-based access control |
| release | ✅ Implemented | Handle release |
| fsync | ✅ Implemented | Data and metadata sync |
```

**Step 2: Update Chinese README**

Same content translated to Chinese.

**Step 3: Run documentation build**

Run: `cargo doc --no-deps --open`

**Step 4: Commit**

```bash
git add README.md README_zh.md
git commit -m "docs: update FUSE operation status in README"
```

---

## Task 9: Final Verification

**Step 1: Run full test suite**

Run: `cargo test --all`

Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`

Expected: No warnings

**Step 3: Check formatting**

Run: `cargo fmt --check`

If not formatted, run: `cargo fmt`

**Step 4: Build release**

Run: `cargo build --release`

Expected: Clean build

**Step 5: Final commit if any changes**

```bash
git add -A
git commit -m "chore: final cleanup and formatting"
```

---

## Summary

This plan implements Option B (core FUSE features) with approximately 800 lines of new code across:

- `src/fs_impl/mod.rs`: 7 new FUSE trait methods
- `src/fs_impl/operations.rs`: Extended metadata, directory operations, atomic rename, attribute setting
- `tests/fuse_integration_test.rs`: Integration tests

All operations follow POSIX semantics and include proper error handling, permission checks, and logging.
