use crate::errors::ZthfsResult;

pub struct FilesystemUtils;

impl FilesystemUtils {
    /// Convert file mode to string representation
    pub fn mode_to_string(mode: u32) -> String {
        format!("{mode:o}")
    }

    /// Check if a file mode indicates a directory
    pub fn is_directory_mode(mode: u32) -> bool {
        (mode & 0o170000) == 0o040000 // S_IFDIR
    }

    /// Check if a file mode indicates a regular file
    pub fn is_regular_file_mode(mode: u32) -> bool {
        (mode & 0o170000) == 0o100000 // S_IFREG
    }

    /// Get file type from mode
    pub fn get_file_type_from_mode(mode: u32) -> &'static str {
        match mode & 0o170000 {
            0o040000 => "directory",
            0o100000 => "regular file",
            0o120000 => "symbolic link",
            0o140000 => "socket",
            0o020000 => "character device",
            0o060000 => "block device",
            0o010000 => "fifo",
            _ => "unknown",
        }
    }

    /// Validate filesystem path
    pub fn validate_path(path: &str) -> ZthfsResult<()> {
        if path.is_empty() {
            return Err(crate::errors::ZthfsError::Path(
                "Path cannot be empty".to_string(),
            ));
        }

        if path.len() > 4096 {
            return Err(crate::errors::ZthfsError::Path("Path too long".to_string()));
        }

        Ok(())
    }
}
