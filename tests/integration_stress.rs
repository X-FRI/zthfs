//! Stress tests for the FUSE filesystem
//!
//! These tests push the filesystem to its limits with large files,
//! deep directory structures, and many operations.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
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
fn test_many_small_files() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 1000;
    let test_data = b"Small file content";

    // Create many small files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("file_{:04}.txt", i));
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(test_data).expect("Failed to write data");
    }

    // Verify all files exist
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_files, "Should have all files");

    // Verify a sample of files
    for i in &[0, 100, 500, 999] {
        let file_path = mount_path.join(format!("file_{:04}.txt", i));
        assert!(file_path.exists(), "File {} should exist", i);
    }
}

#[test]
#[ignore]
fn test_deep_directory_nesting() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let depth = 50; // Deep nesting
    let mut current_path = mount_path.to_path_buf();

    // Create deeply nested directory structure
    for i in 0..depth {
        current_path = current_path.join(format!("level_{}", i));
        fs::create_dir(&current_path).expect("Failed to create directory");
    }

    // Verify deepest level exists
    assert!(current_path.exists(), "Deepest directory should exist");
    assert!(current_path.is_dir(), "Should be a directory");

    // Create a file at the deepest level
    let file_path = current_path.join("deep_file.txt");
    File::create(&file_path).expect("Failed to create file at deep level");
    assert!(file_path.exists(), "Deep file should exist");
}

#[test]
#[ignore]
fn test_wide_directory_tree() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let branching_factor = 20; // 20 subdirectories per level
    let levels = 3; // 3 levels deep

    fn create_tree(base: &Path, level: usize, max_level: usize, branching: usize) {
        if level > max_level {
            return;
        }

        for i in 0..branching {
            let dir_path = base.join(format!("L{}_D{}", level, i));
            fs::create_dir(&dir_path).expect("Failed to create directory");

            // Create a file in each directory
            let file_path = dir_path.join("file.txt");
            File::create(&file_path).expect("Failed to create file");

            create_tree(&dir_path, level + 1, max_level, branching);
        }
    }

    create_tree(mount_path, 0, levels, branching_factor);

    // Count total directories (should be 1 + 20 + 400 + 8000 = 8421)
    fn count_dirs(path: &Path) -> usize {
        let mut count = 1; // Count this directory
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.filter_map(Result::ok) {
                if entry.path().is_dir() {
                    count += count_dirs(&entry.path());
                }
            }
        }
        count
    }

    let dir_count = count_dirs(mount_path);
    assert!(dir_count > 1000, "Should have many directories");
}

#[test]
#[ignore]
fn test_large_file_write() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("large_file.bin");
    let file_size = 5 * 1024 * 1024; // 5 MB
    let buffer_size = 64 * 1024; // 64 KB chunks
    let write_buffer = vec![0x42u8; buffer_size];

    // Write large file in chunks
    let mut file = File::create(&file_path).expect("Failed to create file");
    let mut written = 0;

    while written < file_size {
        let to_write = buffer_size.min(file_size - written);
        file.write_all(&write_buffer[..to_write])
            .expect("Failed to write chunk");
        written += to_write;
    }

    file.sync_all().expect("Failed to sync file");

    // Verify file size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    assert_eq!(
        metadata.len(),
        file_size as u64,
        "File should have correct size"
    );
}

#[test]
#[ignore]
fn test_large_file_random_access() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("random_access.bin");
    let file_size = 1024 * 1024; // 1 MB

    // Create file with known pattern
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        let data: Vec<u8> = (0..255).cycle().take(file_size).collect();
        file.write_all(&data).expect("Failed to write data");
    }

    // Test random access reads
    {
        let mut file = File::open(&file_path).expect("Failed to open file");

        let test_positions = vec![
            0,
            100,
            10_000,
            100_000,
            500_000,
            file_size - 100,
            file_size - 1,
        ];

        for pos in test_positions {
            file.seek(SeekFrom::Start(pos as u64))
                .expect("Failed to seek");
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte).expect("Failed to read");

            let expected = (pos % 256) as u8;
            assert_eq!(byte[0], expected, "Data mismatch at position {}", pos);
        }
    }
}

#[test]
#[ignore]
fn test_rapid_file_create_delete_cycle() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let cycles = 100;

    // Rapidly create and delete the same file
    for i in 0..cycles {
        let file_path = mount_path.join("cycle_file.txt");

        // Create
        {
            let mut file = File::create(&file_path).expect("Failed to create file");
            file.write_all(b"Cycle test").expect("Failed to write");
        }

        assert!(file_path.exists(), "File should exist in cycle {}", i);

        // Delete
        fs::remove_file(&file_path).expect("Failed to delete file");
        assert!(
            !file_path.exists(),
            "File should not exist after deletion in cycle {}",
            i
        );
    }
}

#[test]
#[ignore]
fn test_many_file_renames() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 50;
    let rename_rounds = 5;

    // Create initial files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("file_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    // Perform multiple rounds of renames
    for round in 0..rename_rounds {
        for i in 0..num_files {
            let old_path = mount_path.join(format!("file_{}.txt", i));
            let new_path = mount_path.join(format!("file_r{}_{}.txt", round, i));

            fs::rename(&old_path, &new_path).expect("Failed to rename");
        }
    }

    // Verify final count
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_files);
}

#[test]
#[ignore]
fn test_file_descriptor_limit() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 200; // Try to open many files at once

    // Create many files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("fd_test_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    // Try to open many files simultaneously
    let mut files = Vec::new();
    for i in 0..num_files {
        let file_path = mount_path.join(format!("fd_test_{}.txt", i));
        match File::open(&file_path) {
            Ok(file) => files.push(file),
            Err(_) => break, // Hit FD limit
        }
    }

    // Should be able to open a reasonable number of files
    assert!(
        files.len() > 50,
        "Should be able to open at least 50 files simultaneously"
    );

    // All opened files should be valid
    for (i, file) in files.iter().enumerate() {
        let metadata = file.metadata().expect("Failed to get metadata");
        assert!(metadata.is_file(), "File {} should be valid", i);
    }
}

#[test]
#[ignore]
fn test_long_file_names() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Test various long filename scenarios
    let long_name = "a".repeat(200); // 200 character name
    let file_path = mount_path.join(&long_name);

    File::create(&file_path).expect("Failed to create file with long name");
    assert!(file_path.exists(), "File with long name should exist");

    // Test with special characters (valid ones)
    let special_name = "file-with_special.chars_123.txt";
    let special_path = mount_path.join(special_name);
    File::create(&special_path).expect("Failed to create file with special chars");
    assert!(
        special_path.exists(),
        "File with special chars should exist"
    );
}

#[test]
#[ignore]
fn test_many_directory_operations() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_dirs = 100;

    // Create many directories
    for i in 0..num_dirs {
        let dir_path = mount_path.join(format!("stress_dir_{}", i));
        fs::create_dir(&dir_path).expect("Failed to create directory");

        // Add a file to each
        let file_path = dir_path.join("file.txt");
        File::create(&file_path).expect("Failed to create file");
    }

    // List all directories
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_dirs);

    // Delete all directories
    for i in 0..num_dirs {
        let dir_path = mount_path.join(format!("stress_dir_{}", i));

        // Remove file first
        let file_path = dir_path.join("file.txt");
        fs::remove_file(&file_path).expect("Failed to remove file");

        // Remove directory
        fs::remove_dir(&dir_path).expect("Failed to remove directory");
    }

    // Verify all deleted
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), 0);
}

#[test]
#[ignore]
fn test_append_stress() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("append_stress.txt");
    let num_appends = 1000;
    let append_data = b"Append";

    // Create file
    File::create(&file_path).expect("Failed to create file");

    // Perform many append operations
    for _ in 0..num_appends {
        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&file_path)
            .expect("Failed to open for append");

        file.write_all(append_data).expect("Failed to append");
    }

    // Verify file size
    let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
    let expected_size = (num_appends * append_data.len()) as u64;
    assert_eq!(metadata.len(), expected_size);
}

#[test]
#[ignore]
fn test_truncate_stress() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("truncate_stress.txt");
    let initial_size = 100_000;

    // Create large file
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        let data = vec![0x42u8; initial_size];
        file.write_all(&data).expect("Failed to write");
    }

    // Perform multiple truncations
    let sizes = vec![50000, 10000, 5000, 1000, 500, 100, 50, 10, 1];

    for size in sizes {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file_path)
            .expect("Failed to open with truncate");

        let data = vec![0x43u8; size];
        file.write_all(&data)
            .expect("Failed to write after truncate");

        let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
        assert_eq!(metadata.len(), size as u64, "Size mismatch for {}", size);
    }
}

#[test]
#[ignore]
fn test_mixed_operations_stress() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    // Perform a mix of different operations
    let operations = 200;

    for i in 0..operations {
        match i % 5 {
            0 => {
                // Create file
                let file_path = mount_path.join(format!("mix_{}.txt", i));
                File::create(&file_path).ok();
            }
            1 => {
                // Create directory
                let dir_path = mount_path.join(format!("mix_dir_{}", i));
                fs::create_dir(&dir_path).ok();
            }
            2 => {
                // List directory
                let _ = fs::read_dir(mount_path);
            }
            3 => {
                // Get metadata
                if i > 0 {
                    let file_path = mount_path.join(format!("mix_{}.txt", i - 1));
                    let _ = fs::metadata(&file_path);
                }
            }
            4 => {
                // Try to delete (may fail if doesn't exist)
                let file_path =
                    mount_path.join(format!("mix_{}.txt", (i as i32).saturating_sub(10)));
                let _ = fs::remove_file(&file_path);
            }
            _ => unreachable!(),
        }
    }

    // Verify filesystem is still functional
    let test_path = mount_path.join("final_test.txt");
    File::create(&test_path).expect("Filesystem should still be functional");
    assert!(test_path.exists());
}
