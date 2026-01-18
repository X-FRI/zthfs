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
fn simulate_lookup(fs: &mut Zthfs, req: &TestRequest, parent: u64, name: &OsStr) -> Result<fuser::FileAttr, i32> {
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
    assert_eq!(attr.kind, fuser::FileType::RegularFile, "should be a regular file");
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
    assert_eq!(attr.kind, fuser::FileType::Directory, "should be a directory");
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
    assert!(result.is_ok(), "empty filename lookup returns root directory");
    let attr = result.unwrap();
    assert_eq!(attr.ino, ROOT_INODE, "should return root inode");
    assert_eq!(attr.kind, fuser::FileType::Directory, "should be a directory");
}
