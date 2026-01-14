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
            &[]
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
