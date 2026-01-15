//! File copy, move, and rename operations for ZTHFS.

use crate::errors::ZthfsResult;
use crate::fs_impl::{Zthfs, file_create, file_read, file_write, metadata_ops, path_ops};
use std::fs;
use std::path::Path;

/// Copy a file from source to destination.
/// Returns the number of bytes copied.
pub fn copy_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<u64> {
    let dst_real_path = path_ops::virtual_to_real(fs, dst_path);

    // Ensure the target directory exists
    if let Some(parent) = dst_real_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Read source file (this will handle chunked files automatically)
    let data = file_read::read_file(fs, src_path)?;
    let bytes_copied = data.len() as u64;

    // Write to target file (this will create chunked files for large files)
    file_write::write_file(fs, dst_path, &data)?;

    Ok(bytes_copied)
}

/// Move a file from source to destination.
/// For ZTHFS, this requires re-encryption with the new path's nonce.
pub fn move_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<()> {
    // For ZTHFS, moving a file requires re-encryption with the new path's nonce
    // Read the source file
    let data = file_read::read_file(fs, src_path)?;

    // Write to destination (this will encrypt with the new path)
    file_write::write_file(fs, dst_path, &data)?;

    // Remove the source file
    file_create::remove_file(fs, src_path)?;

    Ok(())
}

/// Atomically rename a file or directory from src_path to dst_path.
pub fn rename_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<()> {
    let src_str_owned = src_path.to_string_lossy();
    let dst_str_owned = dst_path.to_string_lossy();
    let src_str = src_str_owned.as_bytes();
    let dst_str = dst_str_owned.as_bytes();

    // Check source exists
    let src_inode = fs
        .inode_db
        .get(src_str)?
        .ok_or_else(|| crate::errors::ZthfsError::Fs("Source does not exist".to_string()))?;

    // Check target doesn't exist (unless we're implementing overwrite)
    if fs.inode_db.contains_key(dst_str)? {
        return Err(crate::errors::ZthfsError::Fs(
            "Target already exists".to_string(),
        ));
    }

    let inode_num = u64::from_be_bytes(
        src_inode
            .as_ref()
            .try_into()
            .map_err(|_| crate::errors::ZthfsError::Fs("Invalid inode data".to_string()))?,
    );

    // Move the actual data on disk FIRST (before database update)
    // This ensures that if file operations fail, database stays consistent
    let src_real = path_ops::virtual_to_real(fs, src_path);
    let dst_real = path_ops::virtual_to_real(fs, dst_path);

    // Ensure target directory exists
    if let Some(parent) = dst_real.parent() {
        fs::create_dir_all(parent)?;
    }

    // Move metadata file if exists
    let src_meta = metadata_ops::get_metadata_path(fs, src_path);
    let dst_meta = metadata_ops::get_metadata_path(fs, dst_path);
    if src_meta.exists() {
        fs::rename(&src_meta, &dst_meta)?;
    }

    // Move directory marker if exists
    let src_marker = metadata_ops::get_dir_marker_path(fs, src_path);
    let dst_marker = metadata_ops::get_dir_marker_path(fs, dst_path);
    if src_marker.exists() {
        fs::rename(&src_marker, &dst_marker)?;
    }

    // Move actual file or directory
    if src_real.is_dir() || src_real.exists() {
        fs::rename(&src_real, &dst_real)?;
    }

    // Move chunk files if this is a chunked file
    let dst_meta_for_chunks = metadata_ops::get_metadata_path(fs, dst_path);
    if dst_meta_for_chunks.exists() {
        // Load metadata to get chunk count
        if let Ok(metadata) = metadata_ops::load_metadata(fs, dst_path) {
            for chunk_index in 0..metadata.chunk_count {
                let src_chunk = metadata_ops::get_chunk_path(fs, src_path, chunk_index);
                let dst_chunk = metadata_ops::get_chunk_path(fs, dst_path, chunk_index);
                if src_chunk.exists() {
                    fs::rename(&src_chunk, &dst_chunk)?;
                }
            }
        }
    }

    // Now that all file operations succeeded, update database atomically
    let mut batch = sled::Batch::default();

    // Remove old mappings
    batch.remove(src_str);
    batch.remove(&inode_num.to_be_bytes());

    // Add new mappings
    batch.insert(dst_str, &src_inode);
    batch.insert(&inode_num.to_be_bytes(), dst_str);

    // Apply atomically
    fs.inode_db.apply_batch(batch)?;

    // Update in-memory cache
    fs.inodes.insert(inode_num, dst_path.to_path_buf());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfigBuilder, LogConfig};
    use crate::fs_impl::inode_ops;

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
    fn test_file_copy_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let src_path = Path::new("/source.txt");
        let dst_path = Path::new("/destination.txt");
        let test_data = b"Medical record data for copying";

        // Create source file
        file_write::write_file(&fs, src_path, test_data).unwrap();

        // Copy file
        let bytes_copied = copy_file(&fs, src_path, dst_path).unwrap();
        assert_eq!(bytes_copied, test_data.len() as u64);

        // Verify destination file
        assert!(path_ops::path_exists(&fs, dst_path));
        let copied_data = file_read::read_file(&fs, dst_path).unwrap();
        assert_eq!(copied_data, test_data);

        // Source file should still exist
        assert!(path_ops::path_exists(&fs, src_path));

        // Clean up
        file_create::remove_file(&fs, src_path).unwrap();
        file_create::remove_file(&fs, dst_path).unwrap();
    }

    #[test]
    fn test_file_move_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let src_path = Path::new("/source.txt");
        let dst_path = Path::new("/destination.txt");
        let test_data = b"Medical record data for moving";

        // Create source file
        file_write::write_file(&fs, src_path, test_data).unwrap();

        // Move file
        move_file(&fs, src_path, dst_path).unwrap();

        // Verify destination file exists and has correct data
        assert!(path_ops::path_exists(&fs, dst_path));
        let moved_data = file_read::read_file(&fs, dst_path).unwrap();
        assert_eq!(moved_data, test_data);

        // Source file should no longer exist
        assert!(!path_ops::path_exists(&fs, src_path));

        // Clean up
        file_create::remove_file(&fs, dst_path).unwrap();
    }

    #[test]
    fn test_rename_basic() {
        let (_temp_dir, fs) = create_test_fs();
        let src = Path::new("/source.txt");
        let dst = Path::new("/dest.txt");
        file_write::write_file(&fs, src, b"data").unwrap();

        // Ensure inode is allocated for source
        let _ = inode_ops::get_inode(&fs, src).unwrap();

        // Perform rename
        rename_file(&fs, src, dst).unwrap();

        // Source path should no longer be accessible
        assert!(!path_ops::path_exists(&fs, src));
    }

    #[test]
    fn test_rename_target_exists_returns_error() {
        let (_temp_dir, fs) = create_test_fs();
        let src = Path::new("/source.txt");
        let dst = Path::new("/dest.txt");

        file_write::write_file(&fs, src, b"source_data").unwrap();
        file_write::write_file(&fs, dst, b"dest_data").unwrap();

        // Ensure inodes are allocated
        let _ = inode_ops::get_inode(&fs, src).unwrap();
        let _ = inode_ops::get_inode(&fs, dst).unwrap();

        let result = rename_file(&fs, src, dst);
        assert!(result.is_err());

        // Clean up
        file_create::remove_file(&fs, src).unwrap();
        file_create::remove_file(&fs, dst).unwrap();
    }

    #[test]
    fn test_rename_directory_with_marker() {
        let (_temp_dir, fs) = create_test_fs();
        let src = Path::new("/source_dir");
        let dst = Path::new("/dest_dir");

        crate::fs_impl::dir_modify::create_directory(&fs, src, 0o755).unwrap();

        // Add a file in the directory
        let file_path = Path::new("/source_dir/file.txt");
        file_write::write_file(&fs, file_path, b"data").unwrap();

        rename_file(&fs, src, dst).unwrap();

        assert!(!path_ops::path_exists(&fs, src));
        assert!(path_ops::path_exists(&fs, dst));

        // Verify directory marker was moved
        let src_marker = metadata_ops::get_dir_marker_path(&fs, src);
        let dst_marker = metadata_ops::get_dir_marker_path(&fs, dst);
        assert!(!src_marker.exists());
        assert!(dst_marker.exists());

        // Verify file is accessible at new location
        let new_file_path = Path::new("/dest_dir/file.txt");
        assert!(path_ops::path_exists(&fs, new_file_path));

        // Clean up
        crate::fs_impl::dir_modify::remove_directory(&fs, dst, true).unwrap();
    }

    #[test]
    fn test_rename_updates_inode_mappings() {
        let (_temp_dir, fs) = create_test_fs();
        let src = Path::new("/source.txt");
        let dst = Path::new("/dest.txt");

        file_write::write_file(&fs, src, b"data").unwrap();
        let inode = inode_ops::get_inode(&fs, src).unwrap();

        rename_file(&fs, src, dst).unwrap();

        // Verify inode now points to new path
        let retrieved_path = fs.get_path_for_inode(inode);
        assert_eq!(retrieved_path, Some(dst.to_path_buf()));

        // Verify new path gets same inode
        let new_inode = inode_ops::get_inode(&fs, dst).unwrap();
        assert_eq!(inode, new_inode);

        // Clean up
        file_create::remove_file(&fs, dst).unwrap();
    }
}
