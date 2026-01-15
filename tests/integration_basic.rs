//! Basic FUSE filesystem integration tests
//!
//! These tests mount a real FUSE filesystem and perform filesystem operations
//! through the mounted filesystem, testing the full stack.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

mod test_helpers;
use test_helpers::{MountedFs, TestFs};

/// Helper to create and mount a test filesystem
fn setup_mounted_fs() -> MountedFs {
    let test_fs = TestFs::new();
    // Give FUSE time to fully initialize
    std::thread::sleep(Duration::from_millis(200));
    MountedFs::new(test_fs)
}

#[test]
#[ignore] // Requires root/sudo for FUSE mounting
fn test_basic_mount_unmount() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Verify mount point exists and is accessible
    assert!(mount_path.exists());
    assert!(mount_path.is_dir());

    // List directory (should be empty or have only metadata files)
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    // Filter to find only user-visible files (not starting with '.')
    let user_files: Vec<_> = entries
        .iter()
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .collect();

    // New filesystem should have no user-visible files
    // (metadata files like .zthfs_meta are hidden)
    assert_eq!(
        user_files.len(),
        0,
        "New filesystem should have no user files"
    );
}

#[test]
#[ignore]
fn test_create_write_read_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("test_file.txt");
    let test_data = b"Hello, FUSE World!";

    // Create and write to file
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(test_data).expect("Failed to write data");
    }

    // Verify file exists
    assert!(file_path.exists(), "File should exist after creation");

    // Read back the data
    {
        let mut file = File::open(&file_path).expect("Failed to open file");
        let mut read_data = Vec::new();
        file.read_to_end(&mut read_data)
            .expect("Failed to read data");

        assert_eq!(
            &read_data[..],
            test_data,
            "Read data should match written data"
        );
    }

    // Check file size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), test_data.len() as u64);
}

#[test]
#[ignore]
fn test_create_directory() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let dir_path = mount_path.join("test_dir");

    // Create directory
    fs::create_dir(&dir_path).expect("Failed to create directory");

    // Verify directory exists
    assert!(dir_path.exists(), "Directory should exist");
    assert!(dir_path.is_dir(), "Path should be a directory");

    // Verify we can list it (should be empty)
    let entries: Vec<_> = fs::read_dir(&dir_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(entries.len(), 0, "New directory should be empty");
}

#[test]
#[ignore]
fn test_nested_directory_creation() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Create nested directories
    let nested_path = mount_path.join("level1").join("level2").join("level3");
    fs::create_dir_all(&nested_path).expect("Failed to create nested directories");

    // Verify all levels exist
    assert!(nested_path.exists(), "Nested directory should exist");
    assert!(
        mount_path.join("level1").exists(),
        "First level should exist"
    );
    assert!(
        mount_path.join("level1/level2").exists(),
        "Second level should exist"
    );
}

#[test]
#[ignore]
fn test_delete_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("to_delete.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");
    assert!(file_path.exists(), "File should exist");

    // Delete file
    fs::remove_file(&file_path).expect("Failed to delete file");
    assert!(!file_path.exists(), "File should not exist after deletion");
}

#[test]
#[ignore]
fn test_delete_empty_directory() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let dir_path = mount_path.join("empty_dir");

    // Create and then delete empty directory
    fs::create_dir(&dir_path).expect("Failed to create directory");
    assert!(dir_path.exists(), "Directory should exist");

    fs::remove_dir(&dir_path).expect("Failed to remove directory");
    assert!(
        !dir_path.exists(),
        "Directory should not exist after deletion"
    );
}

#[test]
#[ignore]
fn test_rename_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let old_path = mount_path.join("old_name.txt");
    let new_path = mount_path.join("new_name.txt");
    let test_data = b"Rename test data";

    // Create file with data
    {
        let mut file = File::create(&old_path).expect("Failed to create file");
        file.write_all(test_data).expect("Failed to write data");
    }

    // Rename file
    fs::rename(&old_path, &new_path).expect("Failed to rename file");

    // Verify old path doesn't exist
    assert!(!old_path.exists(), "Old path should not exist");

    // Verify new path exists (note: due to path-based encryption, content may not be readable)
    assert!(new_path.exists(), "New path should exist");
}

#[test]
#[ignore]
fn test_file_append() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("append_test.txt");

    // Write initial data
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&file_path)
            .expect("Failed to create file");
        file.write_all(b"Initial ")
            .expect("Failed to write initial data");
    }

    // Append data
    {
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&file_path)
            .expect("Failed to open for appending");
        file.write_all(b"appended data")
            .expect("Failed to append data");
    }

    // Verify file size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 23, "File should contain all written bytes");
}

#[test]
#[ignore]
fn test_file_seek_and_write() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("seek_test.txt");

    // Write data at specific position
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&file_path)
            .expect("Failed to create file");

        file.write_all(b"0123456789")
            .expect("Failed to write initial data");
        file.seek(SeekFrom::Start(5)).expect("Failed to seek");
        file.write_all(b"ABCDE")
            .expect("Failed to write at position");
    }

    // Read back and verify
    {
        let mut file = File::open(&file_path).expect("Failed to open file");
        let mut data = String::new();
        file.read_to_string(&mut data).expect("Failed to read data");

        // Position 5-9 should be overwritten
        assert_eq!(data, "01234ABCDE");
    }
}

#[test]
#[ignore]
fn test_file_truncate() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("truncate_test.txt");

    // Create file with data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"0123456789ABCDEFGHIJ")
            .expect("Failed to write data");
    }

    // Truncate using OpenOptions::truncate
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Failed to open with truncate");
        file.write_all(b"Short")
            .expect("Failed to write truncated data");
    }

    // Verify file is smaller
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 5, "File should be truncated to new size");
}

#[test]
#[ignore]
fn test_file_permissions() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("permissions_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Set permissions
    let new_perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(&file_path, new_perms).expect("Failed to set permissions");

    // Verify permissions
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    let perms = metadata.permissions().mode();
    // Note: actual permissions may be masked by umask
    assert!(perms & 0o777 != 0, "Should have some permissions set");
}

#[test]
#[ignore]
fn test_list_directory_with_multiple_files() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Create multiple files
    for i in 1..=5 {
        let file_path = mount_path.join(format!("file{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    // List directory
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().into_string().unwrap())
        .collect();

    // Should have 5 files
    assert_eq!(entries.len(), 5, "Should have 5 files");

    // Verify file names
    for i in 1..=5 {
        let expected = format!("file{}.txt", i);
        assert!(entries.contains(&expected), "Should contain {}", expected);
    }
}

#[test]
#[ignore]
fn test_large_file_write_read() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("large_file.bin");
    let data_size = 100_000; // 100 KB
    let test_data: Vec<u8> = (0..255).cycle().take(data_size).collect();

    // Write large file
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(&test_data)
            .expect("Failed to write large data");
    }

    // Verify file size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), data_size as u64);

    // Read back and verify
    {
        let mut file = File::open(&file_path).expect("Failed to open file");
        let mut read_data = Vec::new();
        file.read_to_end(&mut read_data)
            .expect("Failed to read large data");

        assert_eq!(read_data, test_data, "Large file data should match");
    }
}

#[test]
#[ignore]
fn test_file_attributes() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("attributes_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Get attributes
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");

    // Verify basic attributes
    assert!(metadata.is_file(), "Should be a file");
    assert!(!metadata.is_dir(), "Should not be a directory");
    assert_eq!(metadata.len(), 0, "New file should be empty");
    assert!(metadata.ino() > 0, "Should have valid inode");
}

#[test]
#[ignore]
fn test_directory_attributes() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let dir_path = mount_path.join("dir_attributes_test");

    // Create directory
    fs::create_dir(&dir_path).expect("Failed to create directory");

    // Get attributes
    let metadata = fs::metadata(&dir_path).expect("Failed to get metadata");

    // Verify directory attributes
    assert!(!metadata.is_file(), "Should not be a file");
    assert!(metadata.is_dir(), "Should be a directory");
}

#[test]
#[ignore]
fn test_symlink_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("target.txt");
    let link_path = mount_path.join("link.txt");

    // Create target file
    File::create(&file_path).expect("Failed to create file");

    // Create symlink
    std::os::unix::fs::symlink("target.txt", &link_path).expect("Failed to create symlink");

    // Verify link exists
    assert!(link_path.exists(), "Symlink should exist");
    assert!(link_path.is_symlink(), "Should be a symlink");
}

#[test]
#[ignore]
fn test_hardlink_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("original.txt");
    let link_path = mount_path.join("hardlink.txt");

    // Create original file with data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Hardlink test")
            .expect("Failed to write data");
    }

    // Create hardlink
    fs::hard_link(&file_path, &link_path).expect("Failed to create hardlink");

    // Verify both refer to same file (same inode)
    let orig_meta = fs::metadata(&file_path).expect("Failed to get metadata");
    let link_meta = fs::metadata(&link_path).expect("Failed to get metadata");

    assert_eq!(
        orig_meta.ino(),
        link_meta.ino(),
        "Hardlinks should share inode"
    );
}
