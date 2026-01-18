//! Directory read operations for ZTHFS.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, inode_ops, metadata_ops, path_ops};
use fuser::{FileType, ReplyDirectory};
use std::fs;
use std::path::Path;

/// Read the content of a directory.
/// Returns entries filtered to exclude ZTHFS internal metadata files.
pub fn read_dir(
    fs: &Zthfs,
    path: &Path,
    offset: i64,
    reply: &mut ReplyDirectory,
) -> ZthfsResult<()> {
    let real_path = path_ops::virtual_to_real(fs, path);
    let entries = fs::read_dir(&real_path)?;

    let mut entries_vec: Vec<_> = entries.collect();
    entries_vec.sort_by_key(|e| e.as_ref().unwrap().file_name());

    for (i, entry) in entries_vec.into_iter().enumerate().skip(offset as usize) {
        if let Ok(entry) = entry {
            let file_name = entry.file_name();

            // Filter out ZTHFS internal metadata files and directory markers
            let file_name_str = file_name.to_string_lossy();
            if file_name_str.ends_with(metadata_ops::METADATA_SUFFIX)
                || file_name_str.ends_with(metadata_ops::DIR_MARKER_SUFFIX)
                // Filter out internal database directories
                || file_name_str == "inode_db"
                || file_name_str == ".zthfs_internal"
            {
                continue;
            }

            let file_type = if entry.file_type().unwrap().is_dir() {
                FileType::Directory
            } else {
                FileType::RegularFile
            };

            // Get inode, skip entry if allocation fails rather than using root inode
            let entry_path = Path::new("/").join(&file_name);
            match inode_ops::get_inode(fs, &entry_path) {
                Ok(inode) => {
                    if reply.add(inode, (i + 1) as i64, file_type, &file_name) {
                        break;
                    }
                }
                Err(e) => {
                    // Log error but continue with other entries
                    log::error!("Failed to get inode for {entry_path:?} in readdir: {e}");
                    // Skip this entry instead of using inode 1 (root)
                    continue;
                }
            }
        }
    }

    Ok(())
}

/// Get the number of entries in a directory.
pub fn get_dir_entry_count(fs: &Zthfs, path: &Path) -> ZthfsResult<usize> {
    let real_path = path_ops::virtual_to_real(fs, path);
    let entries = fs::read_dir(&real_path)?;
    Ok(entries.count())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfigBuilder, LogConfig};

    /// Helper function to create a test filesystem instance
    fn create_test_fs() -> (tempfile::TempDir, Zthfs) {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().join("data").to_string_lossy().to_string())
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
    fn test_get_dir_entry_count() {
        let (_temp_dir, fs) = create_test_fs();

        let dir_path = Path::new("/test_dir_count");
        crate::fs_impl::dir_modify::create_directory(&fs, dir_path, 0o755).unwrap();

        // Empty directory should have 0 entries
        let count = get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 0);

        // Add files to directory
        let file1_path = Path::new("/test_dir_count/file1.txt");
        let file2_path = Path::new("/test_dir_count/file2.txt");
        crate::fs_impl::file_write::write_file(&fs, file1_path, b"data1").unwrap();
        crate::fs_impl::file_write::write_file(&fs, file2_path, b"data2").unwrap();

        let count = get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 2);

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dir_path, true).unwrap();
    }
}
