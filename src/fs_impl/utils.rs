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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ZthfsError;

    // ========== mode_to_string tests ==========
    #[test]
    fn test_mode_to_string_basic() {
        assert_eq!(FilesystemUtils::mode_to_string(0o644), "644");
    }

    #[test]
    fn test_mode_to_string_755() {
        assert_eq!(FilesystemUtils::mode_to_string(0o755), "755");
    }

    #[test]
    fn test_mode_to_string_with_file_type() {
        assert_eq!(FilesystemUtils::mode_to_string(0o100644), "100644");
    }

    #[test]
    fn test_mode_to_string_directory() {
        assert_eq!(FilesystemUtils::mode_to_string(0o040755), "40755");
    }

    #[test]
    fn test_mode_to_string_zero() {
        assert_eq!(FilesystemUtils::mode_to_string(0), "0");
    }

    #[test]
    fn test_mode_to_string_full_permissions() {
        assert_eq!(FilesystemUtils::mode_to_string(0o777), "777");
    }

    // ========== is_directory_mode tests ==========
    #[test]
    fn test_is_directory_mode_true() {
        // S_IFDIR = 0o040000
        assert!(FilesystemUtils::is_directory_mode(0o040000));
        assert!(FilesystemUtils::is_directory_mode(0o040755));
    }

    #[test]
    fn test_is_directory_mode_false_regular_file() {
        // S_IFREG = 0o100000
        assert!(!FilesystemUtils::is_directory_mode(0o100000));
        assert!(!FilesystemUtils::is_directory_mode(0o100644));
    }

    #[test]
    fn test_is_directory_mode_false_symlink() {
        // S_IFLNK = 0o120000
        assert!(!FilesystemUtils::is_directory_mode(0o120000));
    }

    #[test]
    fn test_is_directory_mode_false_zero() {
        assert!(!FilesystemUtils::is_directory_mode(0));
    }

    // ========== is_regular_file_mode tests ==========
    #[test]
    fn test_is_regular_file_mode_true() {
        // S_IFREG = 0o100000
        assert!(FilesystemUtils::is_regular_file_mode(0o100000));
        assert!(FilesystemUtils::is_regular_file_mode(0o100644));
    }

    #[test]
    fn test_is_regular_file_mode_false_directory() {
        // S_IFDIR = 0o040000
        assert!(!FilesystemUtils::is_regular_file_mode(0o040000));
        assert!(!FilesystemUtils::is_regular_file_mode(0o040755));
    }

    #[test]
    fn test_is_regular_file_mode_false_symlink() {
        // S_IFLNK = 0o120000
        assert!(!FilesystemUtils::is_regular_file_mode(0o120000));
    }

    #[test]
    fn test_is_regular_file_mode_false_zero() {
        assert!(!FilesystemUtils::is_regular_file_mode(0));
    }

    // ========== get_file_type_from_mode tests ==========
    #[test]
    fn test_get_file_type_directory() {
        // S_IFDIR = 0o040000
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o040000),
            "directory"
        );
    }

    #[test]
    fn test_get_file_type_regular_file() {
        // S_IFREG = 0o100000
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o100000),
            "regular file"
        );
    }

    #[test]
    fn test_get_file_type_symbolic_link() {
        // S_IFLNK = 0o120000
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o120000),
            "symbolic link"
        );
    }

    #[test]
    fn test_get_file_type_socket() {
        // S_IFSOCK = 0o140000
        assert_eq!(FilesystemUtils::get_file_type_from_mode(0o140000), "socket");
    }

    #[test]
    fn test_get_file_type_character_device() {
        // S_IFCHR = 0o020000
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o020000),
            "character device"
        );
    }

    #[test]
    fn test_get_file_type_block_device() {
        // S_IFBLK = 0o060000
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o060000),
            "block device"
        );
    }

    #[test]
    fn test_get_file_type_fifo() {
        // S_IFIFO = 0o010000
        assert_eq!(FilesystemUtils::get_file_type_from_mode(0o010000), "fifo");
    }

    #[test]
    fn test_get_file_type_unknown() {
        // Unknown type
        assert_eq!(
            FilesystemUtils::get_file_type_from_mode(0o030000),
            "unknown"
        );
        assert_eq!(FilesystemUtils::get_file_type_from_mode(0), "unknown");
    }

    // ========== validate_path tests ==========
    #[test]
    fn test_validate_path_empty() {
        let result = FilesystemUtils::validate_path("");
        assert!(result.is_err());
        if let Err(ZthfsError::Path(msg)) = result {
            assert!(msg.contains("empty"));
        } else {
            panic!("Expected Path error");
        }
    }

    #[test]
    fn test_validate_path_too_long() {
        let long_path = "a".repeat(4097);
        let result = FilesystemUtils::validate_path(&long_path);
        assert!(result.is_err());
        if let Err(ZthfsError::Path(msg)) = result {
            assert!(msg.contains("long"));
        } else {
            panic!("Expected Path error");
        }
    }

    #[test]
    fn test_validate_path_valid() {
        assert!(FilesystemUtils::validate_path("/valid/path").is_ok());
        assert!(FilesystemUtils::validate_path("relative/path").is_ok());
        assert!(FilesystemUtils::validate_path("a").is_ok());
    }

    #[test]
    fn test_validate_path_exactly_max_length() {
        let path = "a".repeat(4096);
        assert!(FilesystemUtils::validate_path(&path).is_ok());
    }

    #[test]
    fn test_validate_path_with_null() {
        // Path with null character should be handled by empty check or pass
        // The current implementation doesn't explicitly check for null
        assert!(FilesystemUtils::validate_path("path\x00").is_ok());
    }

    #[test]
    fn test_validate_path_single_char() {
        assert!(FilesystemUtils::validate_path("a").is_ok());
    }

    #[test]
    fn test_validate_path_root() {
        assert!(FilesystemUtils::validate_path("/").is_ok());
    }
}
