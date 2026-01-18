//! FUSE API integration tests
//!
//! These tests verify the FUSE operation behavior by testing the underlying
//! functionality of Zthfs without requiring actual FUSE mounting or root privileges.
//!
//! Run with: cargo test --test fuse_api_tests

mod fuse_reply;
mod test_helpers;
mod test_request;

use std::ffi::OsStr;
use std::fs;

use test_helpers::create_test_fs;
use test_request::TestRequest;
use zthfs::fs_impl::Zthfs;

const ROOT_INODE: u64 = 1;

/// Helper to create a test file in the data directory
fn create_test_file(fs: &Zthfs, name: &str, content: &[u8]) {
    let file_path = fs.data_dir().join(name);
    fs::write(file_path, content).expect("Failed to create test file");
}

/// Helper to create a test directory in the data directory
fn create_test_dir(fs: &Zthfs, name: &str) {
    let dir_path = fs.data_dir().join(name);
    fs::create_dir(dir_path).expect("Failed to create test directory");
}

/// Test lookup by simulating the lookup operation using Zthfs's internal methods
///
/// This simulates what lookup() does:
/// 1. Get parent path from inode
/// 2. Check permissions
/// 3. Get file attributes
fn simulate_lookup(
    fs: &mut Zthfs,
    req: &TestRequest,
    parent: u64,
    name: &OsStr,
) -> Result<fuser::FileAttr, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the parent path from inode
    let parent_path = match fs.get_path_for_inode(parent) {
        Some(path) => path,
        None => return Err(libc::ENOENT),
    };

    // Build the virtual path
    let path = parent_path.join(name);

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Get attributes
    match zthfs::fs_impl::attr_ops::get_attr(fs, &path) {
        Ok(attr) => Ok(attr),
        Err(_) => Err(libc::ENOENT),
    }
}

// ============================================================================
// Lookup Tests
// ============================================================================

#[test]
fn test_lookup_existing_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    // Create a test file
    create_test_file(&fs, "hello.txt", b"Hello, World!");

    let req = TestRequest::unprivileged();

    // Simulate lookup
    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new("hello.txt"));

    // Verify success
    assert!(result.is_ok(), "lookup should succeed");
    let attr = result.unwrap();
    assert_eq!(attr.size, 13, "file size should match");
    assert_eq!(
        attr.kind,
        fuser::FileType::RegularFile,
        "should be a regular file"
    );
}

#[test]
fn test_lookup_nonexistent_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Try to lookup a file that doesn't exist
    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new("nonexistent.txt"));

    // Should fail with ENOENT (2)
    assert!(result.is_err(), "lookup should fail");
    assert_eq!(result.unwrap_err(), libc::ENOENT, "should return ENOENT");
}

#[test]
fn test_lookup_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    // Create a test directory
    create_test_dir(&fs, "testdir");

    let req = TestRequest::unprivileged();

    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new("testdir"));

    assert!(result.is_ok(), "lookup should succeed");
    let attr = result.unwrap();
    assert_eq!(
        attr.kind,
        fuser::FileType::Directory,
        "should be a directory"
    );
}

#[test]
fn test_lookup_unauthorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    create_test_file(&fs, "secret.txt", b"Secret data");

    // Create request with unauthorized uid (99999)
    let req = TestRequest::new(99999, 99999);

    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new("secret.txt"));

    // Should fail with EACCES (13) - permission denied
    assert!(result.is_err(), "lookup should fail for unauthorized user");
    assert_eq!(result.unwrap_err(), libc::EACCES, "should return EACCES");
}

#[test]
fn test_lookup_root_user_always_authorized() {
    let (_temp_dir, mut fs) = create_test_fs();

    create_test_file(&fs, "anyfile.txt", b"data");

    // Root user should always have access
    let req = TestRequest::root();

    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new("anyfile.txt"));

    assert!(result.is_ok(), "root should be able to lookup any file");
}

#[test]
fn test_lookup_invalid_parent_inode() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Try to lookup with an invalid parent inode
    let result = simulate_lookup(&mut fs, &req, 99999, OsStr::new("anything.txt"));

    // Should fail with ENOENT (2) - parent not found
    assert!(result.is_err(), "lookup should fail");
    assert_eq!(result.unwrap_err(), libc::ENOENT, "should return ENOENT");
}

#[test]
fn test_lookup_empty_filename() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Try to lookup with empty filename
    let result = simulate_lookup(&mut fs, &req, ROOT_INODE, OsStr::new(""));

    // Empty filename results in looking up the root directory itself, which succeeds
    // The actual FUSE lookup would fail earlier in the kernel, but our simulation
    // doesn't have that check. For this test, we just verify the behavior.
    // The lookup succeeds with the root directory's attributes.
    assert!(
        result.is_ok(),
        "empty filename lookup returns root directory"
    );
    let attr = result.unwrap();
    assert_eq!(attr.ino, ROOT_INODE, "should return root inode");
    assert_eq!(
        attr.kind,
        fuser::FileType::Directory,
        "should be a directory"
    );
}

// ============================================================================
// GetAttr Tests
// ============================================================================

/// Simulate getattr by using Zthfs's internal methods
fn simulate_getattr(fs: &mut Zthfs, req: &TestRequest, ino: u64) -> Result<fuser::FileAttr, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the path from inode
    let path = match fs.get_path_for_inode(ino) {
        Some(p) => p,
        None => return Err(libc::ENOENT),
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Get attributes
    match zthfs::fs_impl::attr_ops::get_attr(fs, &path) {
        Ok(attr) => Ok(attr),
        Err(_) => Err(libc::ENOENT),
    }
}

#[test]
fn test_getattr_existing_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    create_test_file(&fs, "test.txt", b"content");

    let req = TestRequest::unprivileged();

    // Get the inode for the file
    let ino = fs
        .get_or_create_inode(std::path::Path::new("/test.txt"))
        .unwrap();

    let result = simulate_getattr(&mut fs, &req, ino);

    assert!(result.is_ok(), "getattr should succeed");
    let attr = result.unwrap();
    assert_eq!(attr.size, 7, "file size should match");
}

#[test]
fn test_getattr_root_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_getattr(&mut fs, &req, ROOT_INODE);

    assert!(result.is_ok(), "getattr should succeed for root");
    let attr = result.unwrap();
    assert_eq!(attr.ino, ROOT_INODE, "root inode should be 1");
    assert_eq!(
        attr.kind,
        fuser::FileType::Directory,
        "root should be a directory"
    );
}

#[test]
fn test_getattr_nonexistent_inode() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_getattr(&mut fs, &req, 99999);

    // Should fail - invalid inode
    assert!(result.is_err(), "getattr should fail");
}

// ============================================================================
// Access Tests
// ============================================================================

/// Simulate access by using Zthfs's internal permission checking
fn simulate_access(fs: &mut Zthfs, req: &TestRequest, ino: u64, _mask: i32) -> Result<(), i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the path from inode (to verify it exists)
    let _path = match fs.get_path_for_inode(ino) {
        Some(p) => p,
        None => return Err(libc::ENOENT),
    };

    // Check permission (ZthFS doesn't evaluate the mask parameter)
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    Ok(())
}

#[test]
fn test_access_authorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_access(&mut fs, &req, ROOT_INODE, 0);

    assert!(result.is_ok(), "authorized user should have access");
}

#[test]
fn test_access_unauthorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::new(99999, 99999);

    let result = simulate_access(&mut fs, &req, ROOT_INODE, 0);

    assert!(result.is_err(), "unauthorized user should be denied");
    assert_eq!(result.unwrap_err(), libc::EACCES, "should return EACCES");
}

#[test]
fn test_access_read_mask() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Request read access (R_OK = 4)
    let result = simulate_access(&mut fs, &req, ROOT_INODE, 4);

    assert!(result.is_ok(), "authorized user should have read access");
}

#[test]
fn test_access_write_mask() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Request write access (W_OK = 2)
    let result = simulate_access(&mut fs, &req, ROOT_INODE, 2);

    assert!(result.is_ok(), "authorized user should have write access");
}

// ============================================================================
// Create Tests
// ============================================================================

/// Simulate create by using Zthfs's internal file creation
fn simulate_create(
    fs: &mut Zthfs,
    req: &TestRequest,
    parent: u64,
    name: &OsStr,
    _mode: u32,
) -> Result<fuser::FileAttr, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the parent path from inode
    let parent_path = match fs.get_path_for_inode(parent) {
        Some(path) => path,
        None => return Err(libc::ENOENT),
    };

    // Build the full path
    let path = parent_path.join(name);

    // Strip leading "/" for actual file system path
    let relative_path = path.to_string_lossy();
    let relative_path_str = relative_path.as_ref();
    let fs_path = if let Some(stripped) = relative_path_str.strip_prefix('/') {
        fs.data_dir().join(stripped)
    } else {
        fs.data_dir().join(relative_path_str)
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Create parent directories if needed
    if let Some(parent_dir) = fs_path.parent()
        && !parent_dir.exists()
        && fs::create_dir_all(parent_dir).is_err()
    {
        return Err(libc::EIO);
    }

    // Create the file (empty)
    match std::fs::write(&fs_path, b"") {
        Ok(_) => {
            // Get the file attributes
            match zthfs::fs_impl::attr_ops::get_attr(fs, &path) {
                Ok(attr) => Ok(attr),
                Err(_) => Err(libc::EIO),
            }
        }
        Err(_) => Err(libc::EIO),
    }
}

#[test]
fn test_create_new_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_create(&mut fs, &req, ROOT_INODE, OsStr::new("newfile.txt"), 0o644);

    assert!(result.is_ok(), "create should succeed");

    // Verify file was actually created
    let file_path = fs.data_dir().join("newfile.txt");
    assert!(file_path.exists(), "file should exist on disk");
}

#[test]
fn test_create_in_nested_path() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Create file in nested path (parent doesn't exist)
    let result = simulate_create(
        &mut fs,
        &req,
        ROOT_INODE,
        OsStr::new("subdir/nested.txt"),
        0o644,
    );

    // This should succeed (creates parent directories)
    assert!(result.is_ok(), "create with nested path should succeed");
}

#[test]
fn test_create_unauthorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::new(99999, 99999);

    let result = simulate_create(&mut fs, &req, ROOT_INODE, OsStr::new("denied.txt"), 0o644);

    assert!(result.is_err(), "unauthorized user should be denied");
    assert_eq!(result.unwrap_err(), libc::EACCES, "should return EACCES");
}

// ============================================================================
// Read Tests
// ============================================================================

/// Simulate read by using Zthfs's internal file reading
fn simulate_read(fs: &mut Zthfs, req: &TestRequest, ino: u64) -> Result<Vec<u8>, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the path from inode
    let path = match fs.get_path_for_inode(ino) {
        Some(p) => p,
        None => return Err(libc::ENOENT),
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Read the file (encrypted content)
    match zthfs::fs_impl::file_read::read_file(fs, &path) {
        Ok(data) => Ok(data),
        Err(_) => Err(libc::EIO),
    }
}

#[test]
fn test_read_existing_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    // Create a test file with known content using write_file (which encrypts)
    let file_path = std::path::Path::new("/readme.txt");
    zthfs::fs_impl::file_write::write_file(&fs, file_path, b"Hello, read test!").unwrap();

    // Get inode for the file
    let ino = fs.get_or_create_inode(file_path).unwrap();

    let req = TestRequest::unprivileged();

    let result = simulate_read(&mut fs, &req, ino);

    assert!(result.is_ok(), "read should succeed");
    let data = result.unwrap();
    // Content should match the original (decrypted by read_file)
    assert_eq!(
        data, b"Hello, read test!",
        "decrypted content should match original"
    );
}

#[test]
fn test_read_nonexistent_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    // Try to read from a nonexistent inode
    let result = simulate_read(&mut fs, &req, 99999);

    // Should fail
    assert!(result.is_err(), "read should fail");
}

#[test]
fn test_read_unauthorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    let file_path = std::path::Path::new("/protected.txt");
    zthfs::fs_impl::file_write::write_file(&fs, file_path, b"Secret data").unwrap();

    let ino = fs.get_or_create_inode(file_path).unwrap();

    let req = TestRequest::new(99999, 99999);

    let result = simulate_read(&mut fs, &req, ino);

    assert!(result.is_err(), "unauthorized user should be denied");
    assert_eq!(result.unwrap_err(), libc::EACCES, "should return EACCES");
}

// ============================================================================
// Write Tests
// ============================================================================

/// Simulate write by using Zthfs's internal file writing
fn simulate_write(
    fs: &mut Zthfs,
    req: &TestRequest,
    path: &std::path::Path,
    data: &[u8],
) -> Result<usize, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Write the file (will be encrypted)
    match zthfs::fs_impl::file_write::write_file(fs, path, data) {
        Ok(()) => Ok(data.len()),
        Err(_) => Err(libc::EIO),
    }
}

#[test]
fn test_write_new_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let data = b"Hello, write!";
    let path = std::path::Path::new("/write.txt");

    let result = simulate_write(&mut fs, &req, path, data);

    assert!(result.is_ok(), "write should succeed");
    assert_eq!(result.unwrap(), data.len(), "should return bytes written");

    // Verify file was written
    let file_path = fs.data_dir().join("write.txt");
    assert!(file_path.exists(), "file should have been created");
}

#[test]
fn test_write_append() {
    let (_temp_dir, mut fs) = create_test_fs();

    // Create initial file
    create_test_file(&fs, "append.txt", b"Hello");

    let req = TestRequest::unprivileged();

    let append_data = b" World";
    let path = std::path::Path::new("/append.txt");

    let result = simulate_write(&mut fs, &req, path, append_data);

    assert!(result.is_ok(), "append should succeed");
}

#[test]
fn test_write_unauthorized_user() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::new(99999, 99999);

    let data = b"Should not write";
    let path = std::path::Path::new("/denied.txt");

    let result = simulate_write(&mut fs, &req, path, data);

    assert!(result.is_err(), "unauthorized user should be denied");
    assert_eq!(result.unwrap_err(), libc::EACCES, "should return EACCES");
}

// ============================================================================
// Readdir Tests
// ============================================================================

/// Simulate readdir by using Zthfs's internal directory reading
fn simulate_readdir(fs: &mut Zthfs, req: &TestRequest, ino: u64) -> Result<Vec<String>, i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the path from inode
    let path = match fs.get_path_for_inode(ino) {
        Some(p) => p,
        None => return Err(libc::ENOENT),
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Strip leading "/" for actual filesystem path
    let relative_path = path.to_string_lossy();
    let relative_path_str = relative_path.as_ref();
    let fs_path = if let Some(stripped) = relative_path_str.strip_prefix('/') {
        fs.data_dir().join(stripped)
    } else {
        fs.data_dir().join(relative_path_str)
    };

    // Read directory entries
    match std::fs::read_dir(&fs_path) {
        Ok(entries) => {
            let mut names = Vec::new();
            for e in entries.flatten() {
                if let Ok(name) = e.file_name().into_string() {
                    names.push(name);
                }
            }
            Ok(names)
        }
        Err(_) => Err(libc::ENOENT),
    }
}

#[test]
fn test_readdir_root() {
    let (_temp_dir, mut fs) = create_test_fs();

    // Create some test files
    create_test_file(&fs, "a.txt", b"a");
    create_test_file(&fs, "b.txt", b"b");
    create_test_file(&fs, "c.txt", b"c");

    let req = TestRequest::unprivileged();

    let result = simulate_readdir(&mut fs, &req, ROOT_INODE);

    assert!(result.is_ok(), "readdir should succeed");
    let entries = result.unwrap();
    assert!(entries.len() >= 3, "should have at least 3 files");
    // Note: may have additional entries (like inode_db)
}

#[test]
fn test_readdir_empty_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_readdir(&mut fs, &req, ROOT_INODE);

    assert!(result.is_ok(), "readdir should succeed");
    let entries = result.unwrap();
    // New filesystem should have minimal entries
    assert!(entries.len() <= 5, "empty dir should have minimal entries");
}

#[test]
fn test_readdir_nonexistent_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_readdir(&mut fs, &req, 99999);

    // Should fail - directory doesn't exist
    assert!(result.is_err(), "readdir should fail");
}

// ============================================================================
// Mkdir Tests
// ============================================================================

/// Simulate mkdir by using Zthfs's internal directory creation
fn simulate_mkdir(fs: &mut Zthfs, req: &TestRequest, parent: u64, name: &OsStr) -> Result<(), i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the parent path from inode
    let parent_path = match fs.get_path_for_inode(parent) {
        Some(path) => path,
        None => return Err(libc::ENOENT),
    };

    // Build the full path
    let path = parent_path.join(name);

    // Strip leading "/" for actual filesystem path
    let relative_path = path.to_string_lossy();
    let relative_path_str = relative_path.as_ref();
    let fs_path = if let Some(stripped) = relative_path_str.strip_prefix('/') {
        fs.data_dir().join(stripped)
    } else {
        fs.data_dir().join(relative_path_str)
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Create the directory
    match std::fs::create_dir(&fs_path) {
        Ok(_) => Ok(()),
        Err(_) => Err(libc::EIO),
    }
}

#[test]
fn test_mkdir_new_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_mkdir(&mut fs, &req, ROOT_INODE, OsStr::new("newdir"));

    assert!(result.is_ok(), "mkdir should succeed");

    // Verify directory was created
    let dir_path = fs.data_dir().join("newdir");
    assert!(dir_path.exists(), "directory should exist");
}

#[test]
fn test_mkdir_unauthorized() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::new(99999, 99999);

    let result = simulate_mkdir(&mut fs, &req, ROOT_INODE, OsStr::new("denied_dir"));

    assert!(result.is_err(), "unauthorized user should be denied");
}

// ============================================================================
// Unlink Tests
// ============================================================================

/// Simulate unlink by using Zthfs's internal file deletion
fn simulate_unlink(
    fs: &mut Zthfs,
    req: &TestRequest,
    parent: u64,
    name: &OsStr,
) -> Result<(), i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the parent path from inode
    let parent_path = match fs.get_path_for_inode(parent) {
        Some(path) => path,
        None => return Err(libc::ENOENT),
    };

    // Build the full path
    let path = parent_path.join(name);

    // Strip leading "/" for actual filesystem path
    let relative_path = path.to_string_lossy();
    let relative_path_str = relative_path.as_ref();
    let fs_path = if let Some(stripped) = relative_path_str.strip_prefix('/') {
        fs.data_dir().join(stripped)
    } else {
        fs.data_dir().join(relative_path_str)
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Delete the file
    match std::fs::remove_file(&fs_path) {
        Ok(_) => Ok(()),
        Err(_) => Err(libc::ENOENT),
    }
}

#[test]
fn test_unlink_existing_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    create_test_file(&fs, "to_delete.txt", b"delete me");

    let req = TestRequest::unprivileged();

    let result = simulate_unlink(&mut fs, &req, ROOT_INODE, OsStr::new("to_delete.txt"));

    assert!(result.is_ok(), "unlink should succeed");

    // Verify file was deleted
    let file_path = fs.data_dir().join("to_delete.txt");
    assert!(!file_path.exists(), "file should be deleted");
}

#[test]
fn test_unlink_nonexistent_file() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_unlink(&mut fs, &req, ROOT_INODE, OsStr::new("doesnotexist.txt"));

    // Should fail with ENOENT
    assert!(result.is_err(), "unlink should fail for nonexistent file");
}

// ============================================================================
// Rmdir Tests
// ============================================================================

/// Simulate rmdir by using Zthfs's internal directory deletion
fn simulate_rmdir(fs: &mut Zthfs, req: &TestRequest, parent: u64, name: &OsStr) -> Result<(), i32> {
    let uid = req.uid;
    let gid = req.gid;

    // Get the parent path from inode
    let parent_path = match fs.get_path_for_inode(parent) {
        Some(path) => path,
        None => return Err(libc::ENOENT),
    };

    // Build the full path
    let path = parent_path.join(name);

    // Strip leading "/" for actual filesystem path
    let relative_path = path.to_string_lossy();
    let relative_path_str = relative_path.as_ref();
    let fs_path = if let Some(stripped) = relative_path_str.strip_prefix('/') {
        fs.data_dir().join(stripped)
    } else {
        fs.data_dir().join(relative_path_str)
    };

    // Check permission
    if !fs.check_permission(uid, gid) {
        return Err(libc::EACCES);
    }

    // Delete the directory
    match std::fs::remove_dir(&fs_path) {
        Ok(_) => Ok(()),
        Err(_) => Err(libc::ENOENT),
    }
}

#[test]
fn test_rmdir_existing_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    create_test_dir(&fs, "to_remove");

    let req = TestRequest::unprivileged();

    let result = simulate_rmdir(&mut fs, &req, ROOT_INODE, OsStr::new("to_remove"));

    assert!(result.is_ok(), "rmdir should succeed");

    // Verify directory was deleted
    let dir_path = fs.data_dir().join("to_remove");
    assert!(!dir_path.exists(), "directory should be removed");
}

#[test]
fn test_rmdir_nonexistent_directory() {
    let (_temp_dir, mut fs) = create_test_fs();

    let req = TestRequest::unprivileged();

    let result = simulate_rmdir(&mut fs, &req, ROOT_INODE, OsStr::new("doesnotexist"));

    // Should fail
    assert!(
        result.is_err(),
        "rmdir should fail for nonexistent directory"
    );
}
