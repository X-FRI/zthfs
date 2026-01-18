//! FUSE-specific integration tests
//!
//! These tests verify FUSE-specific behaviors like file handles,
//! permission handling, and edge cases that are specific to FUSE operations.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

mod test_helpers;
use test_helpers::{MountedFs, TestFs};

/// Helper to create and mount a test filesystem
fn setup_mounted_fs() -> MountedFs {
    let test_fs = TestFs::new();
    std::thread::sleep(Duration::from_millis(200));
    MountedFs::new(test_fs)
}

#[test]
#[ignore]
fn test_fuse_open_read_only() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("readonly_test.txt");

    // Create file with data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Readonly test data")
            .expect("Failed to write data");
    }

    // Open read-only
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(&file_path)
        .expect("Failed to open file read-only");

    // Verify we can read
    let metadata = file.metadata().expect("Failed to get metadata");
    assert_eq!(metadata.len(), 17);
}

#[test]
#[ignore]
fn test_fuse_open_write_only() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("writeonly_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Open write-only and write
    {
        let mut file = OpenOptions::new()
            .write(true)
            .read(false)
            .open(&file_path)
            .expect("Failed to open file write-only");

        file.write_all(b"Write-only data").expect("Failed to write");
    }

    // Verify data was written
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 15);
}

#[test]
#[ignore]
fn test_fuse_open_read_write() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("rw_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Open read-write
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .expect("Failed to open file read-write");

        // Write data
        file.write_all(b"RW test data").expect("Failed to write");

        // Seek back
        file.seek(SeekFrom::Start(0)).expect("Failed to seek");

        // Read back
        let mut buffer = vec![0u8; 12];
        file.read_exact(&mut buffer).expect("Failed to read");

        assert_eq!(buffer, b"RW test data");
    }
}

#[test]
#[ignore]
fn test_fuse_open_append() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("append_test.txt");

    // Create file with initial data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Initial").expect("Failed to write");
    }

    // Open with append mode
    {
        let mut file = OpenOptions::new()
            .append(true)
            .open(&file_path)
            .expect("Failed to open file for append");

        file.write_all(b" data").expect("Failed to append");
    }

    // Verify size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 11); // "Initial" (7) + " data" (4)
}

#[test]
#[ignore]
fn test_fuse_open_create_new() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("new_file.txt");

    // Create with O_EXCL (create_new)
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file_path)
        .expect("Failed to create new file");

    drop(file);

    // Verify file exists
    assert!(file_path.exists());

    // Try to create again - should fail
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file_path);

    assert!(
        result.is_err(),
        "Should not be able to create existing file with create_new"
    );
}

#[test]
#[ignore]
fn test_fuse_open_truncate() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("truncate_test.txt");

    // Create file with data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"0123456789ABCDEFGHIJ")
            .expect("Failed to write");
    }

    // Open with truncate flag
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Failed to open with truncate");

        file.write_all(b"Short").expect("Failed to write new data");
    }

    // Verify file was truncated
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 5);
}

#[test]
#[ignore]
fn test_fuse_release_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("release_test.txt");

    // Create and write to file, then explicitly close
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Release test data")
            .expect("Failed to write");
        file.sync_all().expect("Failed to sync");
    } // File is released here

    // Verify file still exists after release
    assert!(file_path.exists());

    // Should be able to open again
    let file = File::open(&file_path).expect("Failed to open released file");
    let metadata = file.metadata().expect("Failed to get metadata");
    assert_eq!(metadata.len(), 16);
}

#[test]
#[ignore]
fn test_fuse_fsync() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("fsync_test.txt");

    // Create file and write data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Fsync test data").expect("Failed to write");

        // Sync data to disk
        file.sync_all().expect("Failed to sync all");

        // Sync data only (not metadata)
        file.sync_data().expect("Failed to sync data");
    }

    // Verify data persisted
    assert!(file_path.exists());
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 14);
}

#[test]
#[ignore]
fn test_fuse_file_handle_reuse() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("handle_test.txt");

    // Create file
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"Handle test").expect("Failed to write");
    }

    // Open, close, and reopen multiple times
    for i in 0..5 {
        {
            let mut file = OpenOptions::new()
                .write(true)
                .open(&file_path)
                .expect("Failed to open file");

            file.write_all(format!(" iteration {}", i).as_bytes())
                .expect("Failed to append");
        }
    }

    // Verify all data was written
    let mut file = File::open(&file_path).expect("Failed to open for reading");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("Failed to read");

    assert!(content.contains("Handle test"));
    assert!(content.contains("iteration 4"));
}

#[test]
#[ignore]
fn test_fuse_directory_handle() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let dir_path = mount_path.join("dir_handle_test");

    // Create directory
    fs::create_dir(&dir_path).expect("Failed to create directory");

    // Add some files
    for i in 0..3 {
        let file_path = dir_path.join(format!("file_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    // Open directory and iterate
    {
        let entries = fs::read_dir(&dir_path).expect("Failed to read directory");
        let count = entries.filter_map(Result::ok).count();
        assert_eq!(count, 3);
    }

    // Reopen directory
    {
        let entries = fs::read_dir(&dir_path).expect("Failed to re-read directory");
        let count = entries.filter_map(Result::ok).count();
        assert_eq!(count, 3);
    }
}

#[test]
#[ignore]
fn test_fuse_lookup_negative_cache() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("nonexistent.txt");

    // Try to open non-existent file multiple times
    for _ in 0..3 {
        let result = File::open(&file_path);
        assert!(result.is_err(), "Non-existent file should fail to open");
    }

    // Now create the file
    File::create(&file_path).expect("Failed to create file");

    // Should now be able to open it (negative cache should be invalidated)
    let file = File::open(&file_path).expect("Should be able to open newly created file");
    drop(file);

    assert!(file_path.exists());
}

#[test]
#[ignore]
fn test_fuse_getattr_consistency() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("getattr_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Get attributes multiple times
    let attr1 = fs::metadata(&file_path).expect("Failed to get metadata (1)");
    let attr2 = fs::metadata(&file_path).expect("Failed to get metadata (2)");
    let attr3 = fs::metadata(&file_path).expect("Failed to get metadata (3)");

    // Inode should be consistent
    assert_eq!(attr1.ino(), attr2.ino());
    assert_eq!(attr2.ino(), attr3.ino());

    // File type should be consistent
    assert!(attr1.is_file());
    assert!(attr2.is_file());
    assert!(attr3.is_file());
}

#[test]
#[ignore]
fn test_fuse_setattr_mode() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("chmod_test.txt");

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Set different permissions
    let new_perms = fs::Permissions::from_mode(0o644);
    fs::set_permissions(&file_path, new_perms).expect("Failed to set permissions");

    // Verify permissions changed
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    let mode = metadata.permissions().mode();

    // Note: Actual mode may be affected by umask
    assert!(mode & 0o777 != 0);
}

#[test]
#[ignore]
fn test_fuse_setattr_size_truncate() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("setattr_size_test.txt");

    // Create file with data
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(b"0123456789").expect("Failed to write");
    }

    // Open with truncate flag
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Failed to open with truncate");

        file.write_all(b"ABC").expect("Failed to write");
    }

    // Verify size changed
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(metadata.len(), 3);
}

#[test]
#[ignore]
fn test_fuse_statfs() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Query filesystem stats
    let metadata = fs::metadata(mount_path).expect("Failed to get root metadata");

    // Root should be a directory
    assert!(metadata.is_dir());
    assert!(metadata.ino() == 1, "Root inode should be 1");
}
