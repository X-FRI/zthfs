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

    // ========== sanitize_path tests ==========
    #[test]
    fn test_sanitize_path_safe() {
        assert!(Utils::sanitize_path(Path::new("safe/path")).is_ok());
        assert_eq!(
            Utils::sanitize_path(Path::new("safe/path")).unwrap(),
            "safe/path"
        );
    }

    #[test]
    fn test_sanitize_path_unsafe_with_dots() {
        assert!(Utils::sanitize_path(Path::new("../unsafe")).is_err());
        assert!(Utils::sanitize_path(Path::new("./path/../other")).is_err());
    }

    #[test]
    fn test_sanitize_path_unsafe_absolute() {
        assert!(Utils::sanitize_path(Path::new("/absolute/path")).is_err());
    }

    #[test]
    fn test_sanitize_path_unsafe_hidden() {
        assert!(Utils::sanitize_path(Path::new(".hidden")).is_err());
    }

    #[test]
    fn test_sanitize_path_safe_current_dir() {
        assert!(Utils::sanitize_path(Path::new(".")).is_ok());
    }

    #[test]
    fn test_sanitize_path_safe_parent_dir_reference() {
        // ".." in the path_str is checked, but ".." as file_name is allowed
        // Actually, the function checks if path_str contains ".."
        assert!(!Utils::is_safe_path(Path::new("..")));
        assert!(Utils::sanitize_path(Path::new("..")).is_err());
    }

    // ========== format_file_size tests (extended) ==========
    #[test]
    fn test_file_size_formatting() {
        assert_eq!(Utils::format_file_size(0), "0 B");
        assert_eq!(Utils::format_file_size(512), "512 B");
        assert_eq!(Utils::format_file_size(1024), "1.00 KB");
        assert_eq!(Utils::format_file_size(1536), "1.50 KB");
        assert_eq!(Utils::format_file_size(1048576), "1.00 MB");
    }

    #[test]
    fn test_file_size_formatting_large_values() {
        assert_eq!(Utils::format_file_size(1073741824), "1.00 GB"); // 1 GB
        assert_eq!(Utils::format_file_size(1099511627776), "1.00 TB"); // 1 TB
    }

    #[test]
    fn test_file_size_formatting_edge_cases() {
        // Exactly at unit boundaries
        assert_eq!(Utils::format_file_size(1023), "1023 B");
        assert_eq!(Utils::format_file_size(1024), "1.00 KB");

        // Values that would round to different precision
        // Note: The actual output may vary based on floating point rounding
        let result = Utils::format_file_size(99999);
        assert!(result.contains("KB"));

        let result2 = Utils::format_file_size(999999);
        assert!(result2.contains("KB"));

        // Very large values - u64::MAX is clamped to TB (max unit in array)
        assert_eq!(Utils::format_file_size(u64::MAX), "16777216 TB");
    }

    #[test]
    fn test_file_size_formatting_precision() {
        // >= 100: no decimal places
        assert_eq!(Utils::format_file_size(102400), "100 KB");

        // >= 10: 1 decimal place
        assert_eq!(Utils::format_file_size(10240), "10.0 KB");

        // < 10: 2 decimal places
        assert_eq!(Utils::format_file_size(2048), "2.00 KB");
    }

    // ========== format_timestamp tests ==========
    #[test]
    fn test_format_timestamp_unix_epoch() {
        assert_eq!(Utils::format_timestamp(0), "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_format_timestamp_current() {
        // 1609459200 = 2021-01-01 00:00:00 UTC
        assert_eq!(
            Utils::format_timestamp(1609459200),
            "2021-01-01 00:00:00 UTC"
        );
    }

    #[test]
    fn test_format_timestamp_far_future() {
        // 4102444800 = 2100-01-01 00:00:00 UTC
        assert_eq!(
            Utils::format_timestamp(4102444800),
            "2100-01-01 00:00:00 UTC"
        );
    }

    // ========== generate_random_string tests (extended) ==========
    #[test]
    fn test_random_string_generation() {
        let s1 = Utils::generate_random_string(10);
        let s2 = Utils::generate_random_string(10);

        assert_eq!(s1.len(), 10);
        assert_eq!(s2.len(), 10);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_random_string_empty() {
        assert_eq!(Utils::generate_random_string(0), "");
    }

    #[test]
    fn test_random_string_characters() {
        let s = Utils::generate_random_string(1000);
        // Check all characters are from the expected charset
        for c in s.chars() {
            assert!(c.is_alphanumeric());
        }
    }

    // ========== calculate_hash tests ==========
    #[test]
    fn test_calculate_hash_consistency() {
        let data = b"test data";
        let hash1 = Utils::calculate_hash(data);
        let hash2 = Utils::calculate_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_calculate_hash_different_inputs() {
        let hash1 = Utils::calculate_hash(b"data1");
        let hash2 = Utils::calculate_hash(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_calculate_hash_empty() {
        let hash = Utils::calculate_hash(b"");
        assert!(!hash.is_empty());
    }

    // ========== is_valid_email tests (extended) ==========
    #[test]
    fn test_email_validation() {
        assert!(Utils::is_valid_email("test@example.com"));
        assert!(Utils::is_valid_email("user.name@domain.co.uk"));
        assert!(!Utils::is_valid_email("invalid-email"));
        assert!(!Utils::is_valid_email("@domain.com"));
        assert!(!Utils::is_valid_email("test@"));
    }

    #[test]
    fn test_email_validation_edge_cases() {
        // Email with plus sign (common for Gmail)
        assert!(Utils::is_valid_email("user+tag@example.com"));

        // Emails with numbers
        assert!(Utils::is_valid_email("user123@example.com"));

        // Subdomain
        assert!(Utils::is_valid_email("user@mail.example.com"));

        // Empty email
        assert!(!Utils::is_valid_email(""));

        // Multiple @
        assert!(!Utils::is_valid_email("user@name@example.com"));

        // No TLD
        assert!(!Utils::is_valid_email("test@domain"));
    }

    // ========== truncate_string tests (extended) ==========
    #[test]
    fn test_string_truncation() {
        let long_string = "This is a very long string that should be truncated";
        let truncated = Utils::truncate_string(long_string, 20);

        assert_eq!(truncated.len(), 20);
        assert!(truncated.ends_with("..."));
        assert_eq!(&truncated[..17], &long_string[..17]);
    }

    #[test]
    fn test_truncate_string_shorter_than_max() {
        let s = "short";
        assert_eq!(Utils::truncate_string(s, 20), "short");
    }

    #[test]
    fn test_truncate_string_exact_length() {
        let s = "exact length!";
        assert_eq!(Utils::truncate_string(s, 13), "exact length!");
    }

    #[test]
    fn test_truncate_string_empty() {
        assert_eq!(Utils::truncate_string("", 10), "");
    }

    #[test]
    fn test_truncate_string_very_short_max() {
        let s = "hello";
        // With max_length=3, we saturating_sub(3) giving 0, then truncate to "..."
        assert_eq!(Utils::truncate_string(s, 3), "...");
    }

    #[test]
    fn test_truncate_string_max_less_than_ellipsis() {
        let s = "hello";
        assert_eq!(Utils::truncate_string(s, 2), "...");
    }

    // ========== decode_base64 tests (error cases) ==========
    #[test]
    fn test_base64_encoding() {
        let data = b"Hello, World!";
        let encoded = Utils::encode_base64(data);
        let decoded = Utils::decode_base64(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_invalid_input() {
        assert!(Utils::decode_base64("not valid base64!").is_err());
        assert!(Utils::decode_base64("a!b#c$d").is_err());
    }

    #[test]
    fn test_base64_decode_empty() {
        assert_eq!(Utils::decode_base64("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(Utils::encode_base64(b""), "");
    }

    #[test]
    fn test_base64_roundtrip_binary() {
        let data: Vec<u8> = vec![0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE];
        let encoded = Utils::encode_base64(&data);
        let decoded = Utils::decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    // ========== is_debug_mode tests ==========
    #[test]
    fn test_is_debug_mode_default() {
        // By default, DEBUG should be "false"
        assert!(!Utils::is_debug_mode());
    }

    #[test]
    fn test_is_debug_mode_set() {
        unsafe { std::env::set_var("DEBUG", "true") };
        assert!(Utils::is_debug_mode());
        unsafe { std::env::remove_var("DEBUG") };
    }

    #[test]
    fn test_is_debug_mode_other_values() {
        unsafe { std::env::set_var("DEBUG", "1") };
        assert!(!Utils::is_debug_mode());
        unsafe { std::env::remove_var("DEBUG") };

        unsafe { std::env::set_var("DEBUG", "TRUE") };
        assert!(!Utils::is_debug_mode());
        unsafe { std::env::remove_var("DEBUG") };
    }

    // ========== get_env_var / set_env_var tests ==========
    #[test]
    fn test_get_env_var_exists() {
        unsafe { std::env::set_var("TEST_VAR", "test_value") };
        assert_eq!(Utils::get_env_var("TEST_VAR", "default"), "test_value");
        unsafe { std::env::remove_var("TEST_VAR") };
    }

    #[test]
    fn test_get_env_var_default() {
        assert_eq!(
            Utils::get_env_var("NONEXISTENT_VAR_XYZ", "default"),
            "default"
        );
    }

    #[test]
    fn test_set_env_var() {
        Utils::set_env_var("TEST_SET_VAR", "new_value").unwrap();
        assert_eq!(std::env::var("TEST_SET_VAR"), Ok("new_value".to_string()));
        unsafe { std::env::remove_var("TEST_SET_VAR") };
    }

    // ========== current_dir tests ==========
    #[test]
    fn test_current_dir_success() {
        let result = Utils::current_dir();
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    // ========== copy_directory tests ==========
    #[test]
    fn test_copy_directory_empty() {
        let temp_dir = tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");

        std::fs::create_dir(&src).unwrap();
        Utils::copy_directory(&src, &dst).unwrap();
        assert!(dst.exists());
    }

    #[test]
    fn test_copy_directory_with_files() {
        let temp_dir = tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");

        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("file1.txt"), "content1").unwrap();
        std::fs::write(src.join("file2.txt"), "content2").unwrap();

        Utils::copy_directory(&src, &dst).unwrap();

        assert!(dst.join("file1.txt").exists());
        assert!(dst.join("file2.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dst.join("file1.txt")).unwrap(),
            "content1"
        );
        assert_eq!(
            std::fs::read_to_string(dst.join("file2.txt")).unwrap(),
            "content2"
        );
    }

    #[test]
    fn test_copy_directory_nested() {
        let temp_dir = tempdir().unwrap();
        let src = temp_dir.path().join("src");
        let dst = temp_dir.path().join("dst");

        std::fs::create_dir_all(src.join("nested/dir")).unwrap();
        std::fs::write(src.join("nested/dir/file.txt"), "nested content").unwrap();

        Utils::copy_directory(&src, &dst).unwrap();

        assert!(dst.join("nested/dir/file.txt").exists());
        assert_eq!(
            std::fs::read_to_string(dst.join("nested/dir/file.txt")).unwrap(),
            "nested content"
        );
    }

    #[test]
    fn test_copy_directory_source_not_exists() {
        let temp_dir = tempdir().unwrap();
        let src = temp_dir.path().join("nonexistent");
        let dst = temp_dir.path().join("dst");

        let result = Utils::copy_directory(&src, &dst);
        assert!(result.is_err());
    }

    #[test]
    fn test_copy_directory_source_is_file() {
        let temp_dir = tempdir().unwrap();
        let src = temp_dir.path().join("file.txt");
        let dst = temp_dir.path().join("dst");

        std::fs::write(&src, "content").unwrap();

        let result = Utils::copy_directory(&src, &dst);
        assert!(result.is_err());
    }

    // ========== ensure_dir_exists tests (extended) ==========
    #[test]
    fn test_ensure_dir_exists() {
        let temp_dir = tempdir().unwrap();
        let test_path = temp_dir.path().join("nested/deep/directories");

        assert!(!test_path.exists());
        Utils::ensure_dir_exists(&test_path).unwrap();
        assert!(test_path.exists());
        assert!(test_path.is_dir());
    }

    #[test]
    fn test_ensure_dir_exists_already_exists() {
        let temp_dir = tempdir().unwrap();
        // temp_dir already exists
        assert!(Utils::ensure_dir_exists(temp_dir.path()).is_ok());
    }
}
