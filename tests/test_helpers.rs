//! Test helpers for zthfs testing
//!
//! Provides utilities for creating test filesystems and mounting FUSE filesystems
//! for integration testing.

use std::path::Path;
use tempfile::TempDir;
use zthfs::config::{FilesystemConfig, FilesystemConfigBuilder, LogConfig};
use zthfs::fs_impl::Zthfs;

/// Creates a test filesystem configuration with disabled logging and permissive security
pub fn create_test_config(data_dir: &Path) -> FilesystemConfig {
    // Get current user's uid/gid for test configuration
    let current_uid = unsafe { libc::getuid() };
    let current_gid = unsafe { libc::getgid() };

    // Build base config
    let mut config = FilesystemConfigBuilder::new()
        .data_dir(data_dir.to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false,
            file_path: String::new(),
            level: "warn".to_string(),
            max_size: 0,
            rotation_count: 0,
        })
        .build()
        .unwrap();

    // For tests, allow the current user and root to access the filesystem
    // This allows tests to run without root privileges
    config.security.allowed_users = vec![current_uid, 0];
    config.security.allowed_groups = vec![current_gid, 0];

    config
}

/// Creates a temporary test filesystem without mounting
///
/// Returns a tuple of (temp_dir, filesystem) where the temp_dir
/// will be automatically cleaned up when dropped.
pub fn create_test_fs() -> (TempDir, Zthfs) {
    let temp_dir = TempDir::new().unwrap();
    let config = create_test_config(temp_dir.path());
    let fs = Zthfs::new(&config).unwrap();
    (temp_dir, fs)
}

/// A test filesystem wrapper with automatic cleanup
///
/// This struct manages both the temporary directories and the filesystem instance.
pub struct TestFs {
    pub mount_dir: TempDir,
    pub data_dir: TempDir,
    pub fs: Zthfs,
}

impl TestFs {
    /// Creates a new test filesystem with temporary directories
    pub fn new() -> Self {
        let data_dir = TempDir::new().unwrap();
        let mount_dir = TempDir::new().unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(data_dir.path().to_string_lossy().to_string())
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

        Self {
            mount_dir,
            data_dir,
            fs,
        }
    }

    /// Returns the mount directory path
    pub fn mount_path(&self) -> &Path {
        self.mount_dir.path()
    }

    /// Returns the data directory path
    pub fn data_path(&self) -> &Path {
        self.data_dir.path()
    }
}

/// A mounted FUSE filesystem with automatic unmounting on drop
///
/// This is a RAII guard that will unmount the filesystem when dropped.
pub struct MountedFs {
    #[allow(dead_code)]
    session: fuser::BackgroundSession,
    /// Keep the mount_dir alive so the mount point exists
    _mount_dir: TempDir,
    /// Keep the data_dir alive so the backing storage exists
    _data_dir: TempDir,
}

impl MountedFs {
    /// Mounts the test filesystem and returns a guard that auto-unmounts
    pub fn new(test_fs: TestFs) -> Self {
        // Extract the parts we need
        let TestFs {
            mount_dir,
            data_dir,
            fs,
        } = test_fs;

        let session = fuser::spawn_mount2(fs, mount_dir.path(), &[]).expect("Failed to mount");

        // Give FUSE time to initialize
        std::thread::sleep(std::time::Duration::from_millis(100));

        Self {
            session,
            _mount_dir: mount_dir,
            _data_dir: data_dir,
        }
    }

    /// Returns the mount path
    pub fn path(&self) -> &Path {
        self._mount_dir.path()
    }
}

impl Drop for MountedFs {
    fn drop(&mut self) {
        // The BackgroundSession will automatically unmount when dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_test_fs() {
        let (_temp_dir, fs) = create_test_fs();
        assert!(fs.data_dir().exists());
    }

    #[test]
    fn test_test_fs_creation() {
        let test_fs = TestFs::new();
        assert!(test_fs.data_path().exists());
        assert!(test_fs.mount_path().exists());
    }
}
