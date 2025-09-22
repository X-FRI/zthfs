use crate::config::FilesystemConfig;
use crate::core::encryption::EncryptionHandler;
use crate::core::integrity::IntegrityHandler;
use crate::errors::{ZthfsError, ZthfsResult};
use crate::fs_impl::Zthfs;
use fuser::{FileAttr, FileType, ReplyDirectory};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct FileSystemOperations;

impl FileSystemOperations {
    /// Convert the virtual path in ZTHFS to the real physical path in the underlying file system.
    /// Use fs.data_dir as the root directory, and concatenate the virtual path (remove the leading /) to form the real path under data_dir.
    /// For example, the virtual path /test/file.txt when data_dir is /var/lib/zthfs/data will be mapped to /var/lib/zthfs/data/test/file.txt.
    pub fn virtual_to_real(fs: &Zthfs, path: &Path) -> PathBuf {
        fs.data_dir.join(path.strip_prefix("/").unwrap_or(path))
    }

    /// Get or assign an inode number for the given path.
    /// TODO: Currently a simple strategy is used, that is, use the hash value of the file real path as the inode.
    /// This ensures that the same path always gets the same inode.
    /// At the same time, it will store the mapping of inode and real path in fs.inodes.
    pub fn get_inode(fs: &Zthfs, path: &Path) -> u64 {
        let real_path = Self::virtual_to_real(fs, path);
        let mut inodes = fs.inodes.lock().unwrap();

        // Simple inode allocation strategy: use the hash value of the path
        let mut hasher = DefaultHasher::new();
        real_path.hash(&mut hasher);
        let inode = hasher.finish();

        inodes.insert(inode, real_path);
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
            blocks: (metadata.len() + 4096 - 1) / 4096,
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
    pub fn read_file(fs: &Zthfs, path: &Path) -> ZthfsResult<Vec<u8>> {
        let real_path = Self::virtual_to_real(fs, path);
        let encrypted_data = fs::read(&real_path)?;

        // Verify integrity
        if let Some(expected_checksum) =
            IntegrityHandler::get_checksum_from_xattr(&real_path, &fs.config.integrity)?
        {
            if !IntegrityHandler::verify_integrity(&encrypted_data, expected_checksum) {
                log::warn!("Data integrity check failed for {:?}", path);
                return Err(ZthfsError::Integrity(
                    "Data integrity verification failed".to_string(),
                ));
            }
        }

        // Decrypt data
        let path_str = path.to_string_lossy();
        let decrypted_data = fs.encryption.decrypt(&encrypted_data, &path_str)?;
        Ok(decrypted_data)
    }

    /// Write the content of the file (with encryption and integrity verification).
    pub fn write_file(fs: &Zthfs, path: &Path, data: &[u8]) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);

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
        let file = fs::File::create(&real_path)?;

        // Set file permissions
        let mut perms = fs::metadata(&real_path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&real_path, perms)?;

        // Get file attributes
        let attr = Self::get_attr(fs, path)?;
        Ok(attr)
    }

    pub fn remove_file(fs: &Zthfs, path: &Path) -> ZthfsResult<()> {
        let real_path = Self::virtual_to_real(fs, path);
        fs::remove_file(&real_path)?;
        Ok(())
    }

    pub fn path_exists(fs: &Zthfs, path: &Path) -> bool {
        let real_path = Self::virtual_to_real(fs, path);
        real_path.exists()
    }

    pub fn get_file_size(fs: &Zthfs, path: &Path) -> ZthfsResult<u64> {
        let real_path = Self::virtual_to_real(fs, path);
        let metadata = fs::metadata(&real_path)?;
        Ok(metadata.len())
    }

    pub fn get_dir_entry_count(fs: &Zthfs, path: &Path) -> ZthfsResult<usize> {
        let real_path = Self::virtual_to_real(fs, path);
        let entries = fs::read_dir(&real_path)?;
        Ok(entries.count())
    }

    pub fn copy_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<u64> {
        let src_real_path = Self::virtual_to_real(fs, src_path);
        let dst_real_path = Self::virtual_to_real(fs, dst_path);

        // Ensure the target directory exists
        if let Some(parent) = dst_real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Read source file
        let data = fs::read(&src_real_path)?;
        let bytes_copied = data.len() as u64;

        // Write to target file
        fs::write(&dst_real_path, &data)?;

        Ok(bytes_copied)
    }

    pub fn move_file(fs: &Zthfs, src_path: &Path, dst_path: &Path) -> ZthfsResult<()> {
        let src_real_path = Self::virtual_to_real(fs, src_path);
        let dst_real_path = Self::virtual_to_real(fs, dst_path);

        // Ensure the target directory exists
        if let Some(parent) = dst_real_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&src_real_path, &dst_real_path)?;
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
        let metadata = fs::metadata(&fs.data_dir)?;
        // TODO: Use a more accurate method to get the available space.
        // TODO: Return an estimated value for now.
        Ok(1024 * 1024 * 1024) // 1GB as fallback
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
