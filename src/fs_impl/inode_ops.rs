//! Inode operations for ZTHFS.
//!
//! This module provides functions for managing inode numbers,
//! which are used to uniquely identify files and directories.

use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::Zthfs;
use std::path::Path;

/// Get or assign an inode number for the given path.
/// Uses sled's atomic ID generation to ensure collision-free inode allocation.
/// This ensures that the same path always gets the same inode and different paths never conflict.
///
/// # Errors
/// Returns `ZthfsError::Fs` if inode allocation fails after retry attempts.
pub fn get_inode(fs: &Zthfs, path: &Path) -> ZthfsResult<u64> {
    // Use the new sled-based inode allocation system with retry logic
    get_inode_with_retry(fs, path, 3)
}

/// Get inode with retry logic for transient failures
fn get_inode_with_retry(fs: &Zthfs, path: &Path, max_retries: u32) -> ZthfsResult<u64> {
    let mut last_error = None;

    for attempt in 0..max_retries {
        match fs.get_or_create_inode(path) {
            Ok(inode) => return Ok(inode),
            Err(e) => {
                last_error = Some(e);

                // Check if this is a transient error worth retrying
                let is_transient = matches!(
                    last_error.as_ref().unwrap(),
                    ZthfsError::Fs(_) | ZthfsError::Io(_)
                );

                if is_transient && attempt < max_retries - 1 {
                    // Exponential backoff: 10ms, 20ms, 40ms...
                    let delay_ms = 10 * (1 << attempt);
                    log::warn!(
                        "Transient inode allocation failure for {path:?} (attempt {}), retrying in {}ms",
                        attempt + 1,
                        delay_ms
                    );
                    std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                }
            }
        }
    }

    // All retries exhausted - return the error instead of falling back to root inode
    let error = last_error.unwrap();
    log::error!("Failed to allocate inode for path {path:?} after {max_retries} attempts: {error}");

    // Return the actual error rather than falling back to inode 1 (root)
    // This prevents the dangerous behavior where multiple files share the same inode
    Err(ZthfsError::Fs(format!(
        "Failed to allocate inode for {path:?} after {max_retries} attempts: {error}"
    )))
}

/// Get inode with a safe fallback that doesn't use root (inode 1).
/// This is a legacy compatibility method that should be avoided in new code.
/// Returns None if inode allocation fails, allowing callers to handle the error.
pub fn get_inode_safe(fs: &Zthfs, path: &Path) -> Option<u64> {
    get_inode(fs, path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionConfig, FilesystemConfigBuilder, LogConfig};

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, Zthfs) {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().join("data").to_string_lossy().to_string())
            .encryption(EncryptionConfig::with_random_keys())
            .logging(LogConfig {
                enabled: true,
                file_path: log_dir.join("test.log").to_string_lossy().to_string(),
                level: "info".to_string(),
                max_size: 1024 * 1024,
                rotation_count: 3,
            })
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();
        (temp_dir, fs)
    }

    #[test]
    fn test_inode_generation_consistency() {
        let (_temp_dir, fs) = create_test_fs();

        let path = Path::new("/test/file.txt");
        let inode1 = get_inode(&fs, path).unwrap();
        let inode2 = get_inode(&fs, path).unwrap();

        // Same path should generate the same inode
        assert_eq!(inode1, inode2);
        assert!(inode1 > 0);
    }

    #[test]
    fn test_inode_collision_resistance() {
        let (_temp_dir, fs) = create_test_fs();

        // Test different paths that might have collided with hash-based approach
        let paths = vec![
            "/test/file1.txt",
            "/test/file2.txt",
            "/different/path/file.txt",
            "/very/deep/nested/directory/structure/file.txt",
            "/file/with/similar/name.txt",
            "/file/with/similar/name2.txt",
        ];

        let mut inodes = std::collections::HashSet::new();

        for path in paths {
            let inode = get_inode(&fs, Path::new(path)).unwrap();
            // Each inode should be unique and > 0
            assert!(inode > 0, "Inode should be greater than 0 for path: {path}");
            assert!(
                inodes.insert(inode),
                "Inode collision detected: {inode} appears multiple times"
            );
        }

        // Verify that the same path always gives the same inode
        let test_path = Path::new("/consistency/test.txt");
        let inode_first = get_inode(&fs, test_path).unwrap();
        let inode_second = get_inode(&fs, test_path).unwrap();
        assert_eq!(inode_first, inode_second);
    }

    #[test]
    fn test_root_inode_fixed() {
        let (_temp_dir, fs) = create_test_fs();

        // Root directory must always be inode 1 (FUSE requirement)
        let root_inode = get_inode(&fs, Path::new("/")).unwrap();
        assert_eq!(root_inode, 1, "Root directory must always be inode 1");

        // Multiple calls should always return the same inode
        let root_inode2 = get_inode(&fs, Path::new("/")).unwrap();
        assert_eq!(root_inode, root_inode2);
    }

    #[test]
    fn test_inode_allocation_range() {
        let (_temp_dir, fs) = create_test_fs();

        // Test that inode allocation produces reasonable values
        let paths = vec![
            "/range_test_1.txt",
            "/range_test_2.txt",
            "/range_test_3.txt",
            "/range_test_4.txt",
            "/range_test_5.txt",
        ];

        let mut allocated_inodes = Vec::new();

        for path in paths {
            let inode = get_inode(&fs, Path::new(path)).unwrap();
            allocated_inodes.push(inode);

            // Inode should be positive and within reasonable range
            assert!(inode >= 1, "Inode {inode} should be >= 1");
            assert!(inode < 10000, "Inode {inode} seems unreasonably large");
        }

        // All inodes should be unique
        let unique_inodes: std::collections::HashSet<_> = allocated_inodes.iter().collect();
        assert_eq!(
            unique_inodes.len(),
            allocated_inodes.len(),
            "All allocated inodes should be unique: {allocated_inodes:?}"
        );

        // Root inode should be 1
        let root_inode = get_inode(&fs, Path::new("/")).unwrap();
        assert_eq!(root_inode, 1);
    }

    #[test]
    fn test_inode_persistence_across_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/persistence_test.txt");

        // Get inode multiple times in different contexts
        let inode1 = get_inode(&fs, test_path).unwrap();

        // Create the file (this shouldn't change the inode)
        crate::fs_impl::file_write::write_file(&fs, test_path, b"test data").unwrap();
        let inode2 = get_inode(&fs, test_path).unwrap();

        // Read the file (this shouldn't change the inode)
        let _data = crate::fs_impl::file_read::read_file(&fs, test_path).unwrap();
        let inode3 = get_inode(&fs, test_path).unwrap();

        // All inodes should be the same
        assert_eq!(inode1, inode2, "Inode should persist after file creation");
        assert_eq!(inode2, inode3, "Inode should persist after file read");
        assert!(inode1 >= 1, "Inode should be valid (>= 1)");

        // Clean up
        crate::fs_impl::file_create::remove_file(&fs, test_path).unwrap();

        // After deletion, getting inode again should give the same value
        // (since it's stored persistently in sled)
        let inode4 = get_inode(&fs, test_path).unwrap();
        assert_eq!(
            inode1, inode4,
            "Inode should persist even after file deletion"
        );
    }

    #[test]
    fn test_bidirectional_mapping_consistency() {
        let (_temp_dir, fs) = create_test_fs();

        // Create some test paths
        let test_paths = vec![
            "/bidirectional/test1.txt",
            "/bidirectional/test2.txt",
            "/bidirectional/nested/deep/file.txt",
        ];

        let mut path_to_inode = std::collections::HashMap::new();

        // Store path -> inode mappings
        for path_str in &test_paths {
            let path = Path::new(path_str);
            let inode = get_inode(&fs, path).unwrap();
            path_to_inode.insert(path_str.to_string(), inode);

            // Verify we can get path from inode using the memory cache
            let retrieved_path = fs.get_path_for_inode(inode);
            assert_eq!(
                retrieved_path,
                Some(path.to_path_buf()),
                "Failed to retrieve path for inode {inode}"
            );
        }

        // Verify all inodes are unique
        let inodes: std::collections::HashSet<_> = path_to_inode.values().collect();
        assert_eq!(
            inodes.len(),
            test_paths.len(),
            "All inodes should be unique"
        );

        // Verify the same path always returns the same inode
        for (path_str, expected_inode) in &path_to_inode {
            let inode = get_inode(&fs, Path::new(path_str)).unwrap();
            assert_eq!(
                inode, *expected_inode,
                "Path {path_str} should always map to inode {expected_inode}"
            );
        }
    }
}
