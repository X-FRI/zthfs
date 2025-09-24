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
    /// Chunk size for file chunking (4MB)
    const CHUNK_SIZE: usize = 4 * 1024 * 1024;

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

    /// Write the content of the file (with encryption and integrity verification).
    /// This function now uses chunked writing for better performance with large files.
    pub fn write_file(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);

        // Check file size to decide whether to use chunking
        if data.len() > Self::CHUNK_SIZE {
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
            // Remove metadata file
            fs::remove_file(&metadata_path)?;

            // Remove all chunks
            let metadata = Self::load_metadata(fs, path)?;
            for chunk_index in 0..metadata.chunk_count {
                let chunk_path = Self::get_chunk_path(fs, path, chunk_index);
                if chunk_path.exists() {
                    fs::remove_file(&chunk_path)?;
                }
            }
        } else {
            // Remove regular file
            let real_path = Self::virtual_to_real(fs, path);
            fs::remove_file(&real_path)?;
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
            // For regular files, get size from file system
            let real_path = Self::virtual_to_real(fs, path);
            let metadata = fs::metadata(&real_path)?;
            Ok(metadata.len())
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
        let src_real_path = Self::virtual_to_real(fs, src_path);
        let dst_real_path = Self::virtual_to_real(fs, dst_path);

        // Ensure the target directory exists
        if let Some(parent) = dst_real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Check if source is a chunked file
        let src_metadata_path = Self::get_metadata_path(fs, src_path);
        let dst_metadata_path = Self::get_metadata_path(fs, dst_path);

        if src_metadata_path.exists() {
            // Move chunked file
            // Move metadata file
            fs::rename(&src_metadata_path, &dst_metadata_path)?;

            // Move all chunks
            let metadata = Self::load_metadata(fs, src_path)?;
            for chunk_index in 0..metadata.chunk_count {
                let src_chunk_path = Self::get_chunk_path(fs, src_path, chunk_index);
                let dst_chunk_path = Self::get_chunk_path(fs, dst_path, chunk_index);
                if src_chunk_path.exists() {
                    fs::rename(&src_chunk_path, &dst_chunk_path)?;
                }
            }
        } else {
            // Move regular file
            fs::rename(&src_real_path, &dst_real_path)?;
        }

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

        let chunk_size = Self::CHUNK_SIZE;
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

    #[test]
    fn test_virtual_to_real_path_conversion() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().to_string_lossy().to_string())
            .logging(LogConfig {
                enabled: true, // Enable logging for this test
                file_path: log_dir
                    .path()
                    .join("test.log")
                    .to_string_lossy()
                    .to_string(),
                level: "info".to_string(),
                max_size: 1024 * 1024,
                rotation_count: 3,
            })
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();

        let virtual_path = Path::new("/test/file.txt");
        let real_path = FileSystemOperations::virtual_to_real(&fs, virtual_path);

        assert!(real_path.starts_with(temp_dir.path()));
        assert!(real_path.ends_with("test/file.txt"));
    }

    #[test]
    fn test_path_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = tempfile::tempdir().unwrap();
        let config = FilesystemConfigBuilder::new()
            .data_dir(temp_dir.path().to_string_lossy().to_string())
            .logging(LogConfig {
                enabled: true, // Enable logging for this test
                file_path: log_dir
                    .path()
                    .join("test.log")
                    .to_string_lossy()
                    .to_string(),
                level: "info".to_string(),
                max_size: 1024 * 1024,
                rotation_count: 3,
            })
            .build()
            .unwrap();

        let fs = Zthfs::new(&config).unwrap();

        let test_path = Path::new("/test.txt");

        // Test path existence check
        assert!(!FileSystemOperations::path_exists(&fs, test_path));

        // Create test file
        let test_data = b"Hello, world!";
        FileSystemOperations::write_file(&fs, test_path, test_data).unwrap();

        // Verify file existence
        assert!(FileSystemOperations::path_exists(&fs, test_path));

        // Verify file size (should be the size of the encrypted data, not the original data size)
        let size = FileSystemOperations::get_file_size(&fs, test_path).unwrap();
        assert!(size > test_data.len() as u64); // 加密后的大小应该大于原始数据大小

        // Read file to verify content
        let read_data = FileSystemOperations::read_file(&fs, test_path).unwrap();
        assert_eq!(read_data, test_data);

        // Delete file
        FileSystemOperations::remove_file(&fs, test_path).unwrap();
        assert!(!FileSystemOperations::path_exists(&fs, test_path));
    }
}
