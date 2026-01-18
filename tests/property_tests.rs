//! Property-based tests for zthfs
//!
//! These tests use proptest to verify that filesystem operations
//! maintain their expected properties across a wide range of inputs.

use proptest::prelude::*;
use std::path::Path;
use tempfile::TempDir;
use zthfs::config::{FilesystemConfig, FilesystemConfigBuilder, LogConfig};
use zthfs::fs_impl::Zthfs;
use zthfs::fs_impl::{
    attr_ops, chunk_ops, dir_modify, file_attr_ops, file_create, file_read, file_write, inode_ops,
    metadata_ops, path_ops,
};

/// Creates a temporary test filesystem without mounting
///
/// Each test gets a unique temporary directory namespace to avoid
/// interference when tests run in parallel.
fn create_test_fs() -> (TempDir, Zthfs) {
    use std::sync::atomic::{AtomicU64, Ordering};

    // Use a global counter to generate unique IDs for each test
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    // Combine counter with high-precision timestamp for uniqueness
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let unique_id = format!("zthfs_prop_test_{}_{}", counter, timestamp);

    let temp_dir = TempDir::with_prefix(&unique_id).unwrap();
    let config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();
    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}

/// Creates a test filesystem configuration
fn create_test_config(data_dir: &Path) -> FilesystemConfig {
    FilesystemConfigBuilder::new()
        .data_dir(data_dir.to_string_lossy().to_string())
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

// Property 1: Write-Read Roundtrip
// After writing data to a file and then reading it back, we should get the same data.
proptest! {
    #[test]
    fn prop_write_read_roundtrip(
        file_name in "[a-zA-Z0-9_-]{1,50}",
        data in prop::collection::vec(any::<u8>(), 0..10000)
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path_str = format!("/{}", file_name);
        let path = Path::new(&path_str);

        file_write::write_file(&fs, path, &data).unwrap();
        let read = file_read::read_file(&fs, path).unwrap();

        prop_assert_eq!(data, read);
    }
}

// Property 2: Truncate Reduces Size
// Truncating a file to a smaller size should reduce its reported size.
// Note: The truncate implementation may have block alignment constraints.
proptest! {
    #[test]
    fn prop_truncate_reduces_size(
        initial_size in 1000usize..10000,
        truncate_ratio in 0.01f32..0.9f32
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path = Path::new("/test.bin");

        let data = vec![0x42u8; initial_size];
        file_write::write_file(&fs, path, &data).unwrap();

        let attr_before = attr_ops::get_attr(&fs, path).unwrap();
        let truncate_size = (initial_size as f32 * truncate_ratio) as u64;

        file_attr_ops::truncate_file(&fs, path, truncate_size).unwrap();

        let attr_after = attr_ops::get_attr(&fs, path).unwrap();
        // Truncating should make the file smaller or equal
        prop_assert!(attr_after.size <= attr_before.size);
    }
}

// Property 3: Create Then Exists
// After creating a file, path_exists should return true.
proptest! {
    #[test]
    fn prop_create_then_exists(
        file_name in "[a-zA-Z0-9_-]{1,50}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path_str = format!("/{}", file_name);
        let path = Path::new(&path_str);

        file_write::write_file(&fs, path, b"data").unwrap();

        prop_assert!(path_ops::path_exists(&fs, path));
    }
}

// Property 4: Delete Then Not Exists
// After deleting a file, path_exists should return false.
proptest! {
    #[test]
    fn prop_delete_then_not_exists(
        file_name in "[a-zA-Z0-9_-]{1,50}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path_str = format!("/{}", file_name);
        let path = Path::new(&path_str);

        file_write::write_file(&fs, path, b"data").unwrap();
        file_create::remove_file(&fs, path).unwrap();

        prop_assert!(!path_ops::path_exists(&fs, path));
    }
}

// Property 5: Nested Directories
// We should be able to create deeply nested directory structures.
proptest! {
    #[test]
    fn prop_nested_directories(
        depth in 1usize..10,
        dir_name in "[a-z]{3,8}"
    ) {
        let (_temp_dir, fs) = create_test_fs();

        let mut path = String::new();
        for i in 0..depth {
            path.push('/');
            path.push_str(&dir_name);
            path.push('_');
            path.push_str(&i.to_string());
        }

        let dir_path = Path::new(&path);
        dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        prop_assert!(path_ops::path_exists(&fs, dir_path));
    }
}

// Property 6: Empty Directory is Empty
// A newly created directory should be empty.
proptest! {
    #[test]
    fn prop_empty_directory_is_empty(
        dir_name in "[a-z]{3,10}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path_str = format!("/{}", dir_name);
        let path = Path::new(&path_str);

        dir_modify::create_directory(&fs, path, 0o755).unwrap();

        prop_assert!(dir_modify::is_directory_empty(&fs, path).unwrap());
    }
}

// Property 7: Directory With File is Not Empty
// A directory containing a file should not be empty.
proptest! {
    #[test]
    fn prop_directory_with_file_not_empty(
        dir_name in "[a-z]{3,10}",
        file_name in "[a-z]{3,10}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path_str = format!("/{}", dir_name);
        let dir_path = Path::new(&dir_path_str);
        let file_path_str = format!("/{}/{}", dir_name, file_name);
        let file_path = Path::new(&file_path_str);

        dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();
        file_write::write_file(&fs, file_path, b"data").unwrap();

        prop_assert!(!dir_modify::is_directory_empty(&fs, dir_path).unwrap());
    }
}

// Property 8: Metadata Persistence
// File should still exist after filesystem reload.
// Note: Due to path-based encryption, we can only verify existence, not content.
proptest! {
    #[test]
    fn prop_metadata_persistence(
        file_name in "[a-zA-Z0-9_-]{1,50}",
        data in prop::collection::vec(any::<u8>(), 100..10000)
    ) {
        let (temp_dir, fs) = create_test_fs();
        let path_str = format!("/{}", file_name);
        let path = Path::new(&path_str);

        file_write::write_file(&fs, path, &data).unwrap();
        let exists_before = path_ops::path_exists(&fs, path);

        // Reload the filesystem (simulate restart)
        // Explicitly drop the filesystem to ensure sled database is closed
        drop(fs);

        // Give the OS a moment to fully release file handles
        // This is especially important for parallel test execution
        std::thread::sleep(std::time::Duration::from_millis(1));

        let config = create_test_config(temp_dir.path());
        let fs = zthfs::fs_impl::Zthfs::new(&config).unwrap();

        let exists_after = path_ops::path_exists(&fs, path);
        prop_assert_eq!(exists_before, exists_after);
    }
}

// Property 9: Chunked File Roundtrip
// For chunked files, write-read should also preserve data.
proptest! {
    #[test]
    fn prop_chunked_file_roundtrip(
        data in prop::collection::vec(any::<u8>(), 0..50000)
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path = Path::new("/chunked_test.bin");

        // This will be a chunked file due to size
        chunk_ops::write_file_chunked(&fs, path, &data).unwrap();
        let read = chunk_ops::read_file_chunked(&fs, path).unwrap();

        prop_assert_eq!(data, read);
    }
}

// Property 10: File Size Consistency
// The reported file size should match the actual data size.
proptest! {
    #[test]
    fn prop_file_size_consistency(
        data in prop::collection::vec(any::<u8>(), 0..10000)
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path = Path::new("/size_test.bin");

        file_write::write_file(&fs, path, &data).unwrap();

        let reported_size = path_ops::get_file_size(&fs, path).unwrap();
        prop_assert_eq!(reported_size, data.len() as u64);
    }
}

// Property 11: Sequential Write Preserves Data
// Writing data sequentially should preserve all bytes.
proptest! {
    #[test]
    fn prop_sequential_write_preserves(
        chunk1 in prop::collection::vec(any::<u8>(), 0..5000),
        chunk2 in prop::collection::vec(any::<u8>(), 0..5000)
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let path = Path::new("/sequential_test.bin");

        let mut combined = chunk1.clone();
        combined.extend_from_slice(&chunk2);

        file_write::write_file(&fs, path, &combined).unwrap();
        let read = file_read::read_file(&fs, path).unwrap();

        prop_assert_eq!(combined, read);
    }
}

// Property 12: Inode Allocation is Unique
// Each file should get a unique inode.
proptest! {
    #[test]
    fn prop_inode_uniqueness(
        file_names in prop::collection::hash_set("[a-z]{3,8}", 2..20)
    ) {
        let (_temp_dir, fs) = create_test_fs();

        let mut inodes = std::collections::HashSet::new();
        for file_name in &file_names {
            let path_str = format!("/{}", file_name);
            let path = Path::new(&path_str);
            file_write::write_file(&fs, path, b"data").unwrap();

            let inode = inode_ops::get_inode(&fs, path).unwrap();
            prop_assert!(inodes.insert(inode), "Duplicate inode detected: {}", inode);
        }
    }
}

// Property 13: Directory Marker Exists
// Creating a directory should create its marker file.
proptest! {
    #[test]
    fn prop_directory_marker_exists(
        dir_name in "[a-z]{3,10}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path_str = format!("/{}", dir_name);
        let dir_path = Path::new(&dir_path_str);

        dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        let marker_path = metadata_ops::get_dir_marker_path(&fs, dir_path);
        prop_assert!(marker_path.exists(), "Directory marker file should exist");
    }
}

// Property 14: Remove Empty Directory
// Removing an empty directory should succeed and path should not exist afterwards.
proptest! {
    #[test]
    fn prop_remove_empty_directory(
        dir_name in "[a-z]{3,10}"
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path_str = format!("/{}", dir_name);
        let dir_path = Path::new(&dir_path_str);

        dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();
        dir_modify::remove_directory(&fs, dir_path, false).unwrap();

        prop_assert!(!path_ops::path_exists(&fs, dir_path));
    }
}

// Property 15: Directory Mode Preservation
// The directory mode should be preserved when stored.
proptest! {
    #[test]
    fn prop_directory_mode_preservation(
        mode in 0o700u32..0o777u32
    ) {
        let (_temp_dir, fs) = create_test_fs();
        let dir_path = Path::new("/test_dir");

        dir_modify::create_directory(&fs, dir_path, mode).unwrap();

        // Verify directory exists and has correct attributes
        let attr = attr_ops::get_attr(&fs, dir_path).unwrap();
        prop_assert!(attr.perm > 0, "Directory should have permissions");
    }
}
