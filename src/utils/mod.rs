use crate::errors::{ZthfsError, ZthfsResult};
use std::path::Path;

pub struct Utils;

impl Utils {
    pub fn is_safe_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Prevent path traversal attacks
        if path_str.contains("..") {
            return false;
        }

        // Prevent absolute paths (except the root directory)
        if path_str.starts_with('/') && path_str.len() > 1 {
            return false;
        }

        // Prevent hidden files (except the current directory and parent directory)
        if let Some(filename) = path.file_name() {
            let filename_str = filename.to_string_lossy();
            if filename_str.starts_with('.') && filename_str != "." && filename_str != ".." {
                return false;
            }
        }

        true
    }

    /// Clean and validate path. If the path is unsafe, return ZthfsError::Path.
    pub fn sanitize_path(path: &Path) -> ZthfsResult<String> {
        if !Self::is_safe_path(path) {
            return Err(ZthfsError::Path("Unsafe path detected".to_string()));
        }

        Ok(path.to_string_lossy().to_string())
    }

    pub fn format_file_size(size: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

        if size == 0 {
            return "0 B".to_string();
        }

        let base = 1024_f64;
        let log = (size as f64).log(base).floor() as usize;
        let unit_index = std::cmp::min(log, UNITS.len() - 1);
        let size_in_unit = size as f64 / base.powi(unit_index as i32);

        if size_in_unit >= 100.0 {
            format!("{:.0} {}", size_in_unit, UNITS[unit_index])
        } else if size_in_unit >= 10.0 {
            format!("{:.1} {}", size_in_unit, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size_in_unit, UNITS[unit_index])
        }
    }

    pub fn format_timestamp(timestamp: u64) -> String {
        use chrono::{DateTime, Utc};
        let datetime = DateTime::<Utc>::from_timestamp(timestamp as i64, 0)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
        datetime.format("%Y-%m-%d %H:%M:%S UTC").to_string()
    }

    pub fn generate_random_string(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::rng();

        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    pub fn calculate_hash(data: &[u8]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn is_valid_email(email: &str) -> bool {
        let email_regex = regex::Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap();
        email_regex.is_match(email)
    }

    pub fn truncate_string(s: &str, max_length: usize) -> String {
        if s.len() <= max_length {
            s.to_string()
        } else {
            format!("{}...", &s[..max_length.saturating_sub(3)])
        }
    }

    pub fn encode_base64(data: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(data)
    }

    pub fn decode_base64(data: &str) -> ZthfsResult<Vec<u8>> {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD
            .decode(data)
            .map_err(|e| ZthfsError::Config(format!("Base64 decode error: {e}")))
    }

    pub fn is_debug_mode() -> bool {
        std::env::var("DEBUG").unwrap_or_else(|_| "false".to_string()) == "true"
    }

    pub fn get_env_var(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    }

    pub fn set_env_var(key: &str, value: &str) -> ZthfsResult<()> {
        unsafe { std::env::set_var(key, value) };
        Ok(())
    }

    pub fn current_dir() -> ZthfsResult<String> {
        std::env::current_dir()
            .map_err(|e| ZthfsError::Path(format!("Failed to get current directory: {e}")))
            .map(|p| p.to_string_lossy().to_string())
    }

    pub fn ensure_dir_exists(path: &Path) -> ZthfsResult<()> {
        if !path.exists() {
            std::fs::create_dir_all(path)?;
        }
        Ok(())
    }

    pub fn copy_directory(src: &Path, dst: &Path) -> ZthfsResult<()> {
        if !src.exists() || !src.is_dir() {
            return Err(ZthfsError::Path(format!(
                "Source directory does not exist: {src:?}"
            )));
        }

        Self::ensure_dir_exists(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let entry_path = entry.path();
            let file_name = entry.file_name();
            let target_path = dst.join(file_name);

            if entry_path.is_dir() {
                Self::copy_directory(&entry_path, &target_path)?;
            } else {
                std::fs::copy(&entry_path, &target_path)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_path_safety() {
        assert!(Utils::is_safe_path(Path::new("safe/path")));
        assert!(Utils::is_safe_path(Path::new("file.txt")));
        assert!(!Utils::is_safe_path(Path::new("../unsafe")));
        assert!(!Utils::is_safe_path(Path::new("/absolute/path")));
        assert!(!Utils::is_safe_path(Path::new(".hidden")));
    }

    #[test]
    fn test_file_size_formatting() {
        assert_eq!(Utils::format_file_size(0), "0 B");
        assert_eq!(Utils::format_file_size(512), "512 B");
        assert_eq!(Utils::format_file_size(1024), "1.00 KB");
        assert_eq!(Utils::format_file_size(1536), "1.50 KB");
        assert_eq!(Utils::format_file_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_random_string_generation() {
        let s1 = Utils::generate_random_string(10);
        let s2 = Utils::generate_random_string(10);

        assert_eq!(s1.len(), 10);
        assert_eq!(s2.len(), 10);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"Hello, World!";
        let encoded = Utils::encode_base64(data);
        let decoded = Utils::decode_base64(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_email_validation() {
        assert!(Utils::is_valid_email("test@example.com"));
        assert!(Utils::is_valid_email("user.name@domain.co.uk"));
        assert!(!Utils::is_valid_email("invalid-email"));
        assert!(!Utils::is_valid_email("@domain.com"));
        assert!(!Utils::is_valid_email("test@"));
    }

    #[test]
    fn test_string_truncation() {
        let long_string = "This is a very long string that should be truncated";
        let truncated = Utils::truncate_string(long_string, 20);

        assert_eq!(truncated.len(), 20);
        assert!(truncated.ends_with("..."));
        assert_eq!(&truncated[..17], &long_string[..17]);
    }

    #[test]
    fn test_ensure_dir_exists() {
        let temp_dir = tempdir().unwrap();
        let test_path = temp_dir.path().join("nested/deep/directories");

        assert!(!test_path.exists());
        Utils::ensure_dir_exists(&test_path).unwrap();
        assert!(test_path.exists());
        assert!(test_path.is_dir());
    }
}
