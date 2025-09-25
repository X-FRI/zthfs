use crate::core::integrity::IntegrityHandler;
use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::Zthfs;
use fuser::{FileAttr, FileType, ReplyDirectory};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// File metadata structure for chunked files
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkedFileMetadata {
    /// Original file size
    size: u64,
    /// Number of chunks
    chunk_count: u32,
    /// Chunk size used
    chunk_size: usize,
    /// Last modified time
    mtime: u64,
}

pub struct FileSystemOperations;

impl FileSystemOperations {
    /// Get chunk size from filesystem configuration
    fn get_chunk_size(fs: &Zthfs) -> usize {
        fs.config.performance.chunk_size
    }

    /// Check if chunking is enabled
    fn is_chunking_enabled(fs: &Zthfs) -> bool {
        fs.config.performance.chunk_size > 0
    }

    /// Metadata file suffix for storing file metadata
    const METADATA_SUFFIX: &str = ".zthfs_meta";

    /// Convert the virtual path in ZTHFS to the real physical path in the underlying file system.
    /// Use fs.data_dir as the root directory, and concatenate the virtual path (remove the leading /) to form the real path under data_dir.
    /// For example, the virtual path /test/file.txt when data_dir is /var/lib/zthfs/data will be mapped to /var/lib/zthfs/data/test/file.txt.
    pub fn virtual_to_real(fs: &Zthfs, path: &Path) -> PathBuf {
        fs.data_dir.join(path.strip_prefix("/").unwrap_or(path))
    }

    /// Get or assign an inode number for the given path.
    /// Uses a simple strategy: hash value of the file real path as the inode.
    /// This ensures that the same path always gets the same inode.
    /// Stores the mapping of inode and real path in fs.inodes.
    pub fn get_inode(fs: &Zthfs, path: &Path) -> u64 {
        let real_path = Self::virtual_to_real(fs, path);

        // Simple inode allocation strategy: use the hash value of the path
        let mut hasher = DefaultHasher::new();
        real_path.hash(&mut hasher);
        let inode = hasher.finish();

        // Use DashMap's entry API for atomic insert
        fs.inodes.insert(inode, real_path);
        inode
    }

    /// Get the attributes of the specified inode (file or directory). (size, permissions, timestamps, etc.)
    pub fn get_attr(fs: &Zthfs, path: &Path) -> ZthfsResult<FileAttr> {
        let real_path = Self::virtual_to_real(fs, path);
        let metadata = fs::metadata(&real_path)?;

        let kind = if metadata.is_dir() {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        let inode = Self::get_inode(fs, path);

        Ok(FileAttr {
            ino: inode,
            size: metadata.len(),
            blocks: metadata.len().div_ceil(4096),
            atime: metadata.accessed()?,
            mtime: metadata.modified()?,
            ctime: metadata.created()?,
            crtime: metadata.created()?,
            kind,
            perm: metadata.permissions().mode() as u16,
            nlink: 1,
            uid: metadata.uid(),
            gid: metadata.gid(),
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    /// Read the content of the file (with decryption and integrity verification).
    /// This function now uses chunked reading for better performance with large files.
    pub fn read_file(fs: &Zthfs, path: &Path) -> ZthfsResult<Vec<u8>> {
        let real_path = Self::virtual_to_real(fs, path);

        // Check if it's a chunked file
        let metadata_path = Self::get_metadata_path(fs, path);
        if metadata_path.exists() {
            // Use chunked reading for better performance
            return Self::read_file_chunked(fs, path);
        }

        // Fall back to old method for non-chunked files
        let encrypted_data = fs::read(&real_path)?;

        // Verify integrity
        if let Some(expected_checksum) =
            IntegrityHandler::get_checksum_from_xattr(&real_path, &fs.config.integrity)?
            && !IntegrityHandler::verify_integrity(&encrypted_data, expected_checksum)
        {
            log::warn!("Data integrity check failed for {path:?}");
            return Err(ZthfsError::Integrity(
                "Data integrity verification failed".to_string(),
            ));
        }

        // Decrypt data
        let path_str = path.to_string_lossy();
        let decrypted_data = fs.encryption.decrypt(&encrypted_data, &path_str)?;
        Ok(decrypted_data)
    }

    /// Write partial content to a file at the specified offset (with encryption and integrity verification).
    /// This enables proper POSIX write semantics with offset support.
    pub fn write_partial(fs: &Zthfs, path: &Path, offset: i64, data: &[u8]) -> ZthfsResult<u32> {
        // Read the current file content
        let current_data = match Self::read_file(fs, path) {
            Ok(data) => data,
            Err(_) => {
                // File doesn't exist or other error, treat as empty file
                Vec::new()
            }
        };

        let offset = offset as usize;
        let new_size = std::cmp::max(current_data.len(), offset + data.len());

        // Create new data buffer
        let mut new_data = vec![0u8; new_size];

        // Copy existing data
        if !current_data.is_empty() {
            let copy_len = std::cmp::min(current_data.len(), new_data.len());
            new_data[..copy_len].copy_from_slice(&current_data[..copy_len]);
        }

        // Write new data at offset
        let write_start = offset;
        let write_end = std::cmp::min(write_start + data.len(), new_data.len());
        let data_end = write_end - write_start;
        new_data[write_start..write_end].copy_from_slice(&data[..data_end]);

        // Write the modified data back
        Self::write_file(fs, path, &new_data)?;

        Ok(data_end as u32)
    }

    /// Write the content of the file (with encryption and integrity verification).
    /// This function now uses chunked writing for better performance with large files.
    pub fn write_file(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);

        // Check file size to decide whether to use chunking
        if Self::is_chunking_enabled(fs) && data.len() > Self::get_chunk_size(fs) {
            // Use chunked writing for large files
            return Self::write_file_chunked(fs, path, data);
        }

        // For small files, use the old method for simplicity and backward compatibility
        // Ensure the directory exists
        if let Some(parent) = real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Encrypt data
        let path_str = path.to_string_lossy();
        let encrypted_data = fs.encryption.encrypt(data, &path_str)?;

        // Compute checksum
        let checksum = IntegrityHandler::compute_checksum(&encrypted_data);

        // Write encrypted data
        fs::write(&real_path, &encrypted_data)?;

        // Set checksum extended attribute
        IntegrityHandler::set_checksum_xattr(&real_path, checksum, &fs.config.integrity)?;

        Ok(())
    }

    /// Read the content of the directory.
    pub fn read_dir(
        fs: &Zthfs,
        path: &Path,
        offset: i64,
        reply: &mut ReplyDirectory,
    ) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);
        let entries = fs::read_dir(&real_path)?;

        let mut entries_vec: Vec<_> = entries.collect();
        entries_vec.sort_by_key(|e| e.as_ref().unwrap().file_name());

        for (i, entry) in entries_vec.into_iter().enumerate().skip(offset as usize) {
            if let Ok(entry) = entry {
                let file_name = entry.file_name();
                let file_type = if entry.file_type().unwrap().is_dir() {
                    FileType::Directory
                } else {
                    FileType::RegularFile
                };

                let inode = Self::get_inode(fs, &Path::new("/").join(&file_name));

                if reply.add(inode, (i + 1) as i64, file_type, &file_name) {
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn create_file(fs: &Zthfs, path: &Path, mode: u32) -> ZthfsResult<FileAttr> {
        let real_path = Self::virtual_to_real(fs, path);

        // Ensure the directory exists
        if let Some(parent) = real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create file
        let _file = fs::File::create(&real_path)?;

        // Set file permissions
        let mut perms = fs::metadata(&real_path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&real_path, perms)?;

        // Get file attributes
        let attr = Self::get_attr(fs, path)?;
        Ok(attr)
    }

    pub fn remove_file(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
        let metadata_path = Self::get_metadata_path(fs, path);

        if metadata_path.exists() {
            // Remove chunked file
            // Load metadata before removing it
            if let Ok(metadata) = Self::load_metadata(fs, path) {
                // Remove all chunks
                for chunk_index in 0..metadata.chunk_count {
                    let chunk_path = Self::get_chunk_path(fs, path, chunk_index);
                    let _ = fs::remove_file(&chunk_path); // Ignore errors
                }
            }

            // Remove metadata file
            let _ = fs::remove_file(&metadata_path); // Ignore errors if file doesn't exist
        } else {
            // Remove regular file
            let real_path = Self::virtual_to_real(fs, path);
            let _ = fs::remove_file(&real_path); // Ignore errors if file doesn't exist
        }

        Ok(())
    }

    pub fn path_exists(fs: &Zthfs, path: &Path) -> bool {
        let real_path = Self::virtual_to_real(fs, path);
        let metadata_path = Self::get_metadata_path(fs, path);

        // Check if it's a chunked file or regular file
        metadata_path.exists() || real_path.exists()
    }

    pub fn get_file_size(fs: &Zthfs, path: &Path) -> ZthfsResult<u64> {
        let metadata_path = Self::get_metadata_path(fs, path);
        if metadata_path.exists() {
            // For chunked files, get size from metadata
            let metadata = Self::load_metadata(fs, path)?;
            Ok(metadata.size)
        } else {
            // For regular files, read and decrypt to get original size
            let data = Self::read_file(fs, path)?;
            Ok(data.len() as u64)
        }
    }

    pub fn get_dir_entry_count(fs: &Zthfs, path: &Path) -> ZthfsResult<usize> {
        let real_path = Self::virtual_to_real(fs, path);
        let entries = fs::read_dir(&real_path)?;
        Ok(entries.count())
    }

    pub fn copy_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<u64> {
        let dst_real_path = Self::virtual_to_real(fs, dst_path);

        // Ensure the target directory exists
        if let Some(parent) = dst_real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Read source file (this will handle chunked files automatically)
        let data = Self::read_file(fs, src_path)?;
        let bytes_copied = data.len() as u64;

        // Write to target file (this will create chunked files for large files)
        Self::write_file(fs, dst_path, &data)?;

        Ok(bytes_copied)
    }

    pub fn move_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<()> {
        // For ZTHFS, moving a file requires re-encryption with the new path's nonce
        // Read the source file
        let data = Self::read_file(fs, src_path)?;

        // Write to destination (this will encrypt with the new path)
        Self::write_file(fs, dst_path, &data)?;

        // Remove the source file
        Self::remove_file(fs, src_path)?;

        Ok(())
    }

    pub fn create_directory(fs: &Zthfs, path: &Path, mode: u32) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);
        fs::create_dir_all(&real_path)?;

        let mut perms = fs::metadata(&real_path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&real_path, perms)?;

        Ok(())
    }

    pub fn remove_directory(fs: &Zthfs, path: &Path, recursive: bool) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);

        if recursive {
            fs::remove_dir_all(&real_path)?;
        } else {
            fs::remove_dir(&real_path)?;
        }

        Ok(())
    }

    /// Get available space.
    pub fn get_available_space(fs: &Zthfs) -> ZthfsResult<u64> {
        // Simplified to check the available space of the data directory.
        let _metadata = fs::metadata(&fs.data_dir)?;
        // TODO: Use a more accurate method to get the available space.
        // TODO: Return an estimated value for now.
        Ok(1024 * 1024 * 1024) // 1GB as fallback
    }

    /// Get metadata file path for a chunked file
    fn get_metadata_path(fs: &Zthfs, path: &Path) -> PathBuf {
        let real_path = Self::virtual_to_real(fs, path);
        real_path.with_extension(Self::METADATA_SUFFIX)
    }

    /// Save file metadata
    fn save_metadata(fs: &Zthfs, path: &Path, metadata: &ChunkedFileMetadata) -> ZthfsResult<()> {
        let metadata_path = Self::get_metadata_path(fs, path);
        let json = serde_json::to_string(metadata)
            .map_err(|e| ZthfsError::Serialization(e.to_string()))?;
        fs::write(&metadata_path, json)?;
        Ok(())
    }

    /// Load file metadata
    fn load_metadata(fs: &Zthfs, path: &Path) -> ZthfsResult<ChunkedFileMetadata> {
        let metadata_path = Self::get_metadata_path(fs, path);
        let json = fs::read_to_string(&metadata_path)?;
        let metadata: ChunkedFileMetadata =
            serde_json::from_str(&json).map_err(|e| ZthfsError::Serialization(e.to_string()))?;
        Ok(metadata)
    }

    /// Get chunk path for a specific chunk
    fn get_chunk_path(fs: &Zthfs, path: &Path, chunk_index: u32) -> PathBuf {
        let real_path = Self::virtual_to_real(fs, path);
        real_path.with_extension(format!("{chunk_index}.chunk"))
    }

    /// Calculate which chunks are needed for a read operation
    fn get_chunks_for_read(offset: i64, size: u32, chunk_size: usize) -> Vec<u32> {
        let start_chunk = (offset as usize) / chunk_size;
        let end_chunk = ((offset as usize) + size as usize).div_ceil(chunk_size);
        (start_chunk..end_chunk).map(|i| i as u32).collect()
    }

    /// Read a specific chunk
    fn read_chunk(fs: &Zthfs, path: &Path, chunk_index: u32) -> ZthfsResult<Vec<u8>> {
        let chunk_path = Self::get_chunk_path(fs, path, chunk_index);
        let encrypted_data = fs::read(&chunk_path)?;

        // Verify integrity
        if let Some(expected_checksum) =
            IntegrityHandler::get_checksum_from_xattr(&chunk_path, &fs.config.integrity)?
            && !IntegrityHandler::verify_integrity(&encrypted_data, expected_checksum)
        {
            log::warn!("Data integrity check failed for chunk {chunk_index} of {path:?}");
            return Err(ZthfsError::Integrity(format!(
                "Data integrity verification failed for chunk {chunk_index}"
            )));
        }

        // Decrypt data
        let path_str = format!("{}:chunk{}", path.to_string_lossy(), chunk_index);
        let decrypted_data = fs.encryption.decrypt(&encrypted_data, &path_str)?;
        Ok(decrypted_data)
    }

    /// Write a specific chunk
    fn write_chunk(fs: &Zthfs, path: &Path, chunk_index: u32, data: &[u8]) -> ZthfsResult<()> {
        let chunk_path = Self::get_chunk_path(fs, path, chunk_index);

        // Ensure the directory exists
        if let Some(parent) = chunk_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Encrypt data
        let path_str = format!("{}:chunk{}", path.to_string_lossy(), chunk_index);
        let encrypted_data = fs.encryption.encrypt(data, &path_str)?;

        // Compute checksum
        let checksum = IntegrityHandler::compute_checksum(&encrypted_data);

        // Write encrypted data
        fs::write(&chunk_path, &encrypted_data)?;

        // Set checksum extended attribute
        IntegrityHandler::set_checksum_xattr(&chunk_path, checksum, &fs.config.integrity)?;

        Ok(())
    }

    /// Read file with chunked support
    pub fn read_file_chunked(fs: &Zthfs, path: &Path) -> ZthfsResult<Vec<u8>> {
        // Check if it's a chunked file
        let metadata_path = Self::get_metadata_path(fs, path);
        if !metadata_path.exists() {
            // Fall back to old method for non-chunked files
            return Self::read_file(fs, path);
        }

        let metadata = Self::load_metadata(fs, path)?;
        let mut result = Vec::with_capacity(metadata.size as usize);

        for chunk_index in 0..metadata.chunk_count {
            let chunk_data = Self::read_chunk(fs, path, chunk_index)?;
            result.extend_from_slice(&chunk_data);
        }

        Ok(result)
    }

    /// Write file with chunked support
    pub fn write_file_chunked(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);

        // Ensure the directory exists
        if let Some(parent) = real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let chunk_size = Self::get_chunk_size(fs);
        let total_chunks = data.len().div_ceil(chunk_size);

        // Create metadata
        let metadata = ChunkedFileMetadata {
            size: data.len() as u64,
            chunk_count: total_chunks as u32,
            chunk_size,
            mtime: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Write chunks
        for (i, chunk_data) in data.chunks(chunk_size).enumerate() {
            Self::write_chunk(fs, path, i as u32, chunk_data)?;
        }

        // Save metadata
        Self::save_metadata(fs, path, &metadata)?;

        Ok(())
    }

    /// Read partial file with chunked support (for FUSE read operations)
    pub fn read_partial_chunked(
        fs: &Zthfs,
        path: &Path,
        offset: i64,
        size: u32,
    ) -> ZthfsResult<Vec<u8>> {
        let metadata_path = Self::get_metadata_path(fs, path);
        if !metadata_path.exists() {
            // Fall back to old method for non-chunked files
            let full_data = Self::read_file(fs, path)?;
            let start = offset as usize;
            let end = std::cmp::min(start + size as usize, full_data.len());
            return Ok(full_data[start..end].to_vec());
        }

        let metadata = Self::load_metadata(fs, path)?;
        let chunk_size = metadata.chunk_size;

        // Get required chunks
        let needed_chunks = Self::get_chunks_for_read(offset, size, chunk_size);

        let mut result = Vec::new();
        let mut current_offset = offset as usize;

        for chunk_index in needed_chunks {
            let chunk_data = Self::read_chunk(fs, path, chunk_index)?;

            let chunk_start = (chunk_index as usize) * chunk_size;
            let chunk_end = chunk_start + chunk_data.len();

            if current_offset < chunk_end {
                let data_start = std::cmp::max(current_offset, chunk_start);
                let data_end = std::cmp::min(current_offset + size as usize, chunk_end);

                if data_start < data_end {
                    let slice_start = data_start - chunk_start;
                    let slice_end = data_end - chunk_start;
                    result.extend_from_slice(&chunk_data[slice_start..slice_end]);
                }
            }

            current_offset += chunk_data.len();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FilesystemConfigBuilder, LogConfig};
    use std::sync::Arc;
    use std::thread;

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
    fn test_virtual_to_real_path_conversion() {
        let (temp_dir, fs) = create_test_fs();

        let virtual_path = Path::new("/test/file.txt");
        let real_path = FileSystemOperations::virtual_to_real(&fs, virtual_path);

        assert!(real_path.starts_with(temp_dir.path().join("data")));
        assert!(real_path.ends_with("test/file.txt"));
    }

    #[test]
    fn test_inode_generation_consistency() {
        let (_temp_dir, fs) = create_test_fs();

        let path = Path::new("/test/file.txt");
        let inode1 = FileSystemOperations::get_inode(&fs, path);
        let inode2 = FileSystemOperations::get_inode(&fs, path);

        // Same path should generate the same inode
        assert_eq!(inode1, inode2);
        assert!(inode1 > 0);
    }

    #[test]
    fn test_basic_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/test.txt");

        // Test path existence check
        assert!(!FileSystemOperations::path_exists(&fs, test_path));

        // Create test file
        let test_data = b"Hello, world!";
        FileSystemOperations::write_file(&fs, test_path, test_data).unwrap();

        // Verify file existence
        assert!(FileSystemOperations::path_exists(&fs, test_path));

        // Verify file size (should be the original data size)
        let size = FileSystemOperations::get_file_size(&fs, test_path).unwrap();
        assert_eq!(size, test_data.len() as u64);

        // Read file to verify content
        let read_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data, test_data);

        // Delete file
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
        assert!(!FileSystemOperations::path_exists(&fs, test_path));
    }

    #[test]
    fn test_partial_write_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/partial_write_test.txt");

        // Create initial file content
        let initial_data = b"Hello, World!";
        FileSystemOperations::write_file(&fs, test_path, initial_data).unwrap();

        // Test partial write at offset 7 (overwrite "World" with "Universe")
        let write_data = b"Universe";
        let bytes_written =
            FileSystemOperations::write_partial(&fs, test_path, 7, write_data).unwrap();
        assert_eq!(bytes_written, write_data.len() as u32);

        // Read entire file to verify content
        let read_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        let expected = b"Hello, Universe"; // "World!" (6 chars) -> "Universe" (7 chars)
        assert_eq!(read_data, expected);

        // Test partial write beyond current file size (append-like behavior)
        let append_data = b" How are you?";
        let bytes_written = FileSystemOperations::write_partial(
            &fs,
            test_path,
            read_data.len() as i64,
            append_data,
        )
        .unwrap();
        assert_eq!(bytes_written, append_data.len() as u32);

        // Verify final content
        let final_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        let expected_final = b"Hello, Universe How are you?";
        assert_eq!(final_data, expected_final);

        // Clean up
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_partial_write_edge_cases() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/edge_case_test.txt");

        // Test writing to empty/non-existent file
        let write_data = b"Start";
        let bytes_written =
            FileSystemOperations::write_partial(&fs, test_path, 0, write_data).unwrap();
        assert_eq!(bytes_written, write_data.len() as u32);

        let read_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data, write_data);

        // Test partial write with offset larger than file size (creates sparse file)
        let sparse_data = b"Sparse";
        let large_offset = 1000i64;
        let bytes_written =
            FileSystemOperations::write_partial(&fs, test_path, large_offset, sparse_data).unwrap();
        assert_eq!(bytes_written, sparse_data.len() as u32);

        let read_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data.len(), (large_offset as usize) + sparse_data.len());
        assert_eq!(&read_data[(large_offset as usize)..], sparse_data);

        // Verify original data is preserved at beginning
        assert_eq!(&read_data[..write_data.len()], write_data);

        // Clean up
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_chunked_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        // Create large file that will be chunked (> 4MB)
        let chunk_size = FileSystemOperations::get_chunk_size(&fs);
        let large_data = vec![0x42u8; chunk_size * 2 + 1024]; // > 8MB

        let test_path = Path::new("/large_file.dat");

        // Write large file using chunked method
        FileSystemOperations::write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Verify file exists
        assert!(FileSystemOperations::path_exists(&fs, test_path));

        // Verify file size
        let size = FileSystemOperations::get_file_size(&fs, test_path).unwrap();
        assert_eq!(size, large_data.len() as u64);

        // Read file using chunked reading
        let read_data = FileSystemOperations::read_file_chunked(&fs, test_path).unwrap();
        assert_eq!(read_data, large_data);

        // Test partial chunked reading
        let partial_data =
            FileSystemOperations::read_partial_chunked(&fs, test_path, 0, 1024).unwrap();
        assert_eq!(partial_data.len(), 1024);
        assert_eq!(&partial_data[..], &large_data[..1024]);

        // Test offset reading
        let offset_data =
            FileSystemOperations::read_partial_chunked(&fs, test_path, chunk_size as i64, 1024)
                .unwrap();
        assert_eq!(offset_data.len(), 1024);
        assert_eq!(&offset_data[..], &large_data[chunk_size..chunk_size + 1024]);

        // Clean up
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
        assert!(!FileSystemOperations::path_exists(&fs, test_path));
    }

    #[test]
    fn test_chunked_vs_regular_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        // Test regular file (< 4MB)
        let small_data = vec![0x41u8; 1024];
        let small_path = Path::new("/small_file.txt");

        FileSystemOperations::write_file(&fs, small_path, &small_data).unwrap();
        let small_read = FileSystemOperations::read_file(&fs, small_path).unwrap();
        assert_eq!(small_read, small_data);

        // Test chunked file (> 4MB)
        let large_data = vec![0x42u8; FileSystemOperations::get_chunk_size(&fs) + 1024];
        let large_path = Path::new("/large_file.dat");

        FileSystemOperations::write_file(&fs, large_path, &large_data).unwrap();
        let large_read = FileSystemOperations::read_file(&fs, large_path).unwrap();
        assert_eq!(large_read, large_data);

        // Both should exist
        assert!(FileSystemOperations::path_exists(&fs, small_path));
        assert!(FileSystemOperations::path_exists(&fs, large_path));

        // Clean up
        FileSystemOperations::remove_file(&fs, small_path).unwrap();
        FileSystemOperations::remove_file(&fs, large_path).unwrap();
    }

    #[test]
    fn test_file_copy_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let src_path = Path::new("/source.txt");
        let dst_path = Path::new("/destination.txt");
        let test_data = b"Medical record data for copying";

        // Create source file
        FileSystemOperations::write_file(&fs, src_path, test_data).unwrap();

        // Copy file
        let bytes_copied = FileSystemOperations::copy_file(&fs, src_path, dst_path).unwrap();
        assert_eq!(bytes_copied, test_data.len() as u64);

        // Verify destination file
        assert!(FileSystemOperations::path_exists(&fs, dst_path));
        let copied_data = FileSystemOperations::read_file(&fs, dst_path).unwrap();
        assert_eq!(copied_data, test_data);

        // Source file should still exist
        assert!(FileSystemOperations::path_exists(&fs, src_path));

        // Clean up
        FileSystemOperations::remove_file(&fs, src_path).unwrap();
        FileSystemOperations::remove_file(&fs, dst_path).unwrap();
    }

    #[test]
    fn test_file_move_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let src_path = Path::new("/source.txt");
        let dst_path = Path::new("/destination.txt");
        let test_data = b"Medical record data for moving";

        // Create source file
        FileSystemOperations::write_file(&fs, src_path, test_data).unwrap();

        // Move file
        FileSystemOperations::move_file(&fs, src_path, dst_path).unwrap();

        // Verify destination file exists and has correct data
        assert!(FileSystemOperations::path_exists(&fs, dst_path));
        let moved_data = FileSystemOperations::read_file(&fs, dst_path).unwrap();
        assert_eq!(moved_data, test_data);

        // Source file should no longer exist
        assert!(!FileSystemOperations::path_exists(&fs, src_path));

        // Clean up
        FileSystemOperations::remove_file(&fs, dst_path).unwrap();
    }

    #[test]
    fn test_directory_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let dir_path = Path::new("/test_directory");

        // Create directory
        FileSystemOperations::create_directory(&fs, dir_path, 0o755).unwrap();

        // Verify directory exists
        assert!(FileSystemOperations::path_exists(&fs, dir_path));

        // Get directory entry count (should be 0 for empty directory)
        let count = FileSystemOperations::get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 0);

        // Create files in directory
        let file1_path = Path::new("/test_directory/file1.txt");
        let file2_path = Path::new("/test_directory/file2.txt");

        FileSystemOperations::write_file(&fs, file1_path, b"File 1 content").unwrap();
        FileSystemOperations::write_file(&fs, file2_path, b"File 2 content").unwrap();

        // Check directory entry count again
        let count = FileSystemOperations::get_dir_entry_count(&fs, dir_path).unwrap();
        assert_eq!(count, 2);

        // Remove directory recursively
        FileSystemOperations::remove_directory(&fs, dir_path, true).unwrap();
        assert!(!FileSystemOperations::path_exists(&fs, dir_path));
    }

    #[test]
    fn test_nested_directory_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let nested_path = Path::new("/level1/level2/level3");

        // Create nested directory structure
        FileSystemOperations::create_directory(&fs, nested_path, 0o755).unwrap();

        // Verify all levels exist
        assert!(FileSystemOperations::path_exists(&fs, Path::new("/level1")));
        assert!(FileSystemOperations::path_exists(
            &fs,
            Path::new("/level1/level2")
        ));
        assert!(FileSystemOperations::path_exists(&fs, nested_path));

        // Create file in nested directory
        let file_path = Path::new("/level1/level2/level3/test.txt");
        let test_data = b"Nested file content";
        FileSystemOperations::write_file(&fs, file_path, test_data).unwrap();

        // Verify file exists and has correct content
        assert!(FileSystemOperations::path_exists(&fs, file_path));
        let read_data = FileSystemOperations::read_file(&fs, file_path).unwrap();
        assert_eq!(read_data, test_data);

        // Clean up (recursive removal)
        FileSystemOperations::remove_directory(&fs, Path::new("/level1"), true).unwrap();
        assert!(!FileSystemOperations::path_exists(
            &fs,
            Path::new("/level1")
        ));
    }

    #[test]
    fn test_data_integrity_verification() {
        let (_temp_dir, fs) = create_test_fs();

        let test_path = Path::new("/integrity_test.txt");
        let test_data = b"Critical medical data that must remain intact";

        // Write file
        FileSystemOperations::write_file(&fs, test_path, test_data).unwrap();

        // Manually corrupt the encrypted data to test integrity verification
        let real_path = FileSystemOperations::virtual_to_real(&fs, test_path);
        let mut encrypted_data = std::fs::read(&real_path).unwrap();
        if !encrypted_data.is_empty() {
            // Flip a bit in the encrypted data
            encrypted_data[0] ^= 0xFF;
            std::fs::write(&real_path, encrypted_data).unwrap();
        }

        // Attempt to read should fail due to integrity check
        let result = FileSystemOperations::read_file(&fs, test_path);
        assert!(result.is_err());

        // Clean up
        let _ = FileSystemOperations::remove_file(&fs, test_path);
    }

    #[test]
    fn test_chunked_file_integrity() {
        let (_temp_dir, fs) = create_test_fs();

        // Create large file for chunked storage
        let large_data = vec![0x55u8; FileSystemOperations::get_chunk_size(&fs) + 1000];
        let test_path = Path::new("/chunked_integrity.dat");

        FileSystemOperations::write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Manually corrupt one chunk
        let chunk_path = FileSystemOperations::get_chunk_path(&fs, test_path, 0);
        let mut chunk_data = std::fs::read(&chunk_path).unwrap();
        if !chunk_data.is_empty() {
            chunk_data[0] ^= 0xFF;
            std::fs::write(&chunk_path, chunk_data).unwrap();
        }

        // Reading should fail due to integrity check
        let result = FileSystemOperations::read_file_chunked(&fs, test_path);
        assert!(result.is_err());

        // Clean up
        let _ = FileSystemOperations::remove_file(&fs, test_path);
    }

    #[test]
    fn test_empty_file_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let empty_path = Path::new("/empty.txt");

        // Write empty file
        FileSystemOperations::write_file(&fs, empty_path, &[]).unwrap();

        // Verify empty file exists
        assert!(FileSystemOperations::path_exists(&fs, empty_path));

        // Verify size is 0 (empty file)
        let size = FileSystemOperations::get_file_size(&fs, empty_path).unwrap();
        assert_eq!(size, 0);

        // Read empty file
        let data = FileSystemOperations::read_file(&fs, empty_path).unwrap();
        assert!(data.is_empty());

        // Clean up
        FileSystemOperations::remove_file(&fs, empty_path).unwrap();
    }

    #[test]
    fn test_large_file_partial_reads() {
        let (_temp_dir, fs) = create_test_fs();

        // Create a file larger than chunk size
        let chunk_size = fs.config.performance.chunk_size;
        let file_size = chunk_size * 3 + 500;
        let large_data: Vec<u8> = (0..file_size).map(|i| (i % 256) as u8).collect();

        let test_path = Path::new("/large_partial.dat");
        FileSystemOperations::write_file_chunked(&fs, test_path, &large_data).unwrap();

        // Test reading from different offsets
        let test_cases = vec![
            (0, 100),                             // Beginning
            (1000, 2000),                         // Middle of first chunk
            (chunk_size as i64, 100),             // Start of second chunk
            ((chunk_size * 2 + 100) as i64, 300), // Middle of third chunk
            ((file_size - 50) as i64, 50),        // End of file
        ];

        for (offset, size) in test_cases {
            let partial_data =
                FileSystemOperations::read_partial_chunked(&fs, test_path, offset, size as u32)
                    .unwrap();
            let expected_size = std::cmp::min(size, (file_size as i64 - offset) as usize);
            assert_eq!(partial_data.len(), expected_size);

            // Verify content matches
            let start = offset as usize;
            let end = start + partial_data.len();
            assert_eq!(&partial_data[..], &large_data[start..end]);
        }

        // Clean up
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
    }

    #[test]
    fn test_concurrent_file_operations() {
        let (_temp_dir, fs) = create_test_fs();
        let fs = Arc::new(fs);

        let mut handles = vec![];

        // Spawn multiple threads to perform concurrent operations
        // Reduce thread count to avoid resource conflicts
        for i in 0..3 {
            let fs_clone = Arc::clone(&fs);
            let handle = thread::spawn(move || {
                let file_path_str = format!("/concurrent_file_{i}.txt");
                let file_path = Path::new(&file_path_str);
                let data = format!("Concurrent data from thread {i}").into_bytes();

                // Write file
                FileSystemOperations::write_file(&fs_clone, file_path, &data)
                    .expect("Write should succeed");

                // Read and verify
                let read_data = FileSystemOperations::read_file(&fs_clone, file_path)
                    .expect("Read should succeed");
                assert_eq!(read_data, data);

                // Get file size (encrypted size will be larger)
                let size = FileSystemOperations::get_file_size(&fs_clone, file_path)
                    .expect("Get size should succeed");
                assert!(size >= data.len() as u64);

                // Clean up
                FileSystemOperations::remove_file(&fs_clone, file_path)
                    .expect("Remove should succeed");
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }
    }

    #[test]
    fn test_file_size_edge_cases() {
        let (_temp_dir, fs) = create_test_fs();

        // Test various file sizes
        let chunk_size = fs.config.performance.chunk_size;
        let test_cases = vec![
            (0, "empty"),
            (1, "single_byte"),
            (1023, "small"),
            (1024, "one_kilobyte"),
            (chunk_size - 1, "just_under_chunk"),
            (chunk_size, "exactly_chunk"),
            (chunk_size + 1, "just_over_chunk"),
            (chunk_size * 2, "two_chunks"),
        ];

        for (size, description) in test_cases {
            let file_path_str = format!("/size_test_{description}.dat");
            let file_path = Path::new(&file_path_str);
            let data = vec![0xAAu8; size];

            FileSystemOperations::write_file(&fs, file_path, &data).unwrap();

            // Verify size - should always be the original data size
            let reported_size = FileSystemOperations::get_file_size(&fs, file_path).unwrap();
            assert_eq!(
                reported_size, size as u64,
                "Failed for {size} bytes ({description})"
            );

            // Verify content
            let read_data = FileSystemOperations::read_file(&fs, file_path).unwrap();
            assert_eq!(
                read_data.len(),
                size,
                "Failed for {} bytes ({}) - got {} bytes",
                size,
                read_data.len(),
                description
            );
            assert_eq!(read_data, data, "Failed for {size} bytes ({description})");

            FileSystemOperations::remove_file(&fs, file_path).unwrap();
        }
    }

    #[test]
    fn test_single_byte_file() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/single_byte.dat");
        let data = vec![0xBBu8; 1]; // 1 byte

        FileSystemOperations::write_file(&fs, file_path, &data).unwrap();

        // Verify size
        let reported_size = FileSystemOperations::get_file_size(&fs, file_path).unwrap();
        assert_eq!(reported_size, 1u64);

        // Verify content
        let read_data = FileSystemOperations::read_file(&fs, file_path).unwrap();
        println!(
            "DEBUG: Wrote 1 byte, read {} bytes: {:?}",
            read_data.len(),
            &read_data
        );
        assert_eq!(read_data.len(), 1);
        assert_eq!(read_data, data);

        FileSystemOperations::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_metadata_operations() {
        let (_temp_dir, fs) = create_test_fs();

        let file_path = Path::new("/metadata_test.txt");
        let data = b"Test data for metadata operations";

        // Write file
        FileSystemOperations::write_file(&fs, file_path, data).unwrap();

        // Get attributes
        let attr = FileSystemOperations::get_attr(&fs, file_path).unwrap();

        // Verify basic attributes
        // Note: attr.size returns the encrypted file size, not the original data size
        assert!(attr.size > data.len() as u64); // Encrypted size > original size
        assert_eq!(attr.kind, fuser::FileType::RegularFile);
        assert_eq!(attr.nlink, 1);

        // Inode should be consistent
        let inode = FileSystemOperations::get_inode(&fs, file_path);
        assert_eq!(attr.ino, inode);

        // Clean up
        FileSystemOperations::remove_file(&fs, file_path).unwrap();
    }

    #[test]
    fn test_error_handling() {
        let (_temp_dir, fs) = create_test_fs();

        // Test reading non-existent file
        let nonexistent_path = Path::new("/does_not_exist.txt");
        let result = FileSystemOperations::read_file(&fs, nonexistent_path);
        assert!(result.is_err());

        // Test getting size of non-existent file
        let result = FileSystemOperations::get_file_size(&fs, nonexistent_path);
        assert!(result.is_err());

        // Test removing non-existent file (should not error for regular files)
        let result = FileSystemOperations::remove_file(&fs, nonexistent_path);
        assert!(result.is_ok()); // This might succeed if it's not a chunked file

        // Test path existence for non-existent file
        assert!(!FileSystemOperations::path_exists(&fs, nonexistent_path));
    }

    #[test]
    fn test_unicode_filename_support() {
        let (_temp_dir, fs) = create_test_fs();

        // Test various Unicode filenames
        let test_cases = vec![
            "文件.txt",
            "médical_data.dat",
            "тестовый_файл.txt",
            "📁📄.txt",
            "café_résumé.pdf",
        ];

        for filename in test_cases {
            let file_path_str = format!("/{filename}");
            let file_path = Path::new(&file_path_str);
            let data = format!("Content for {filename}").into_bytes();

            FileSystemOperations::write_file(&fs, file_path, &data).unwrap();

            // Verify file exists
            assert!(FileSystemOperations::path_exists(&fs, file_path));

            // Verify content
            let read_data = FileSystemOperations::read_file(&fs, file_path).unwrap();
            assert_eq!(read_data, data);

            FileSystemOperations::remove_file(&fs, file_path).unwrap();
        }
    }

    #[test]
    fn test_chunk_metadata_persistence() {
        let (_temp_dir, fs) = create_test_fs();

        // Create chunked file
        let large_data = vec![0x77u8; FileSystemOperations::get_chunk_size(&fs) * 2 + 500];
        let file_path = Path::new("/chunked_metadata.dat");

        FileSystemOperations::write_file_chunked(&fs, file_path, &large_data).unwrap();

        // Verify metadata file exists
        let metadata_path = FileSystemOperations::get_metadata_path(&fs, file_path);
        assert!(metadata_path.exists());

        // Load and verify metadata
        let metadata = FileSystemOperations::load_metadata(&fs, file_path).unwrap();
        assert_eq!(metadata.size, large_data.len() as u64);
        assert_eq!(metadata.chunk_count, 3); // 2 full chunks + 1 partial
        assert_eq!(
            metadata.chunk_size,
            FileSystemOperations::get_chunk_size(&fs)
        );
        assert!(metadata.mtime > 0);

        // Verify chunk files exist
        for i in 0..metadata.chunk_count {
            let chunk_path = FileSystemOperations::get_chunk_path(&fs, file_path, i);
            assert!(chunk_path.exists());
        }

        // Clean up
        FileSystemOperations::remove_file(&fs, file_path).unwrap();

        // Verify all files are removed
        assert!(!metadata_path.exists());
        for i in 0..metadata.chunk_count {
            let chunk_path = FileSystemOperations::get_chunk_path(&fs, file_path, i);
            assert!(!chunk_path.exists());
        }
    }
}
