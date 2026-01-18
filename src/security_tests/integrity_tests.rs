//! Integrity verification security tests.
//!
//! These tests verify the security properties of integrity verification:
//! - BLAKE3 produces unique checksums for different data
//! - Small data changes cause large checksum differences (avalanche effect)
//! - HMAC signatures detect tampering
//! - Integrity chains can be verified

use crate::config::IntegrityConfig;
use crate::core::integrity::IntegrityHandler;
use tempfile::tempdir;

/// Test that different data produces different BLAKE3 checksums.
///
/// This is a fundamental property of cryptographic hash functions.
#[test]
fn test_blake3_checksum_unique() {
    let key = vec![1u8; 32];

    let data1 = b"First medical record: Patient A";
    let data2 = b"Second medical record: Patient B";
    let data3 = b""; // Empty data

    let checksum1 = IntegrityHandler::compute_checksum(data1, "blake3", &key).unwrap();
    let checksum2 = IntegrityHandler::compute_checksum(data2, "blake3", &key).unwrap();
    let checksum3 = IntegrityHandler::compute_checksum(data3, "blake3", &key).unwrap();

    // SAFETY: Different inputs MUST produce different checksums.
    // If this fails, there's a catastrophic collision vulnerability.
    assert_ne!(
        checksum1, checksum2,
        "Different data should have different checksums"
    );
    assert_ne!(
        checksum1, checksum3,
        "Non-empty vs empty should have different checksums"
    );
    assert_ne!(
        checksum2, checksum3,
        "Non-empty vs empty should have different checksums"
    );

    // All checksums should be 32 bytes (BLAKE3 output size)
    assert_eq!(checksum1.len(), 32);
    assert_eq!(checksum2.len(), 32);
    assert_eq!(checksum3.len(), 32);
}

/// Test BLAKE3's collision resistance (avalanche effect).
///
/// Small changes in input should cause large changes in output.
#[test]
fn test_blake3_collision_resistance() {
    let key = vec![1u8; 32];

    let base_data = b"Patient diagnosis: Hypertension, Stage 1";

    // Test various single-bit changes - each data must differ from base_data
    // Use Vec<u8> to avoid fixed-size array type issues
    let test_cases: Vec<(Vec<u8>, &str)> = vec![
        (
            b"Patient diagnosis: Hypertension, Stage 2".to_vec(),
            "Changed last digit",
        ),
        (
            b"Patient diagnosis: Hypertension, Stabe 1".to_vec(),
            "Typo in middle",
        ),
        (
            b"patienT diagnosis: Hypertension, Stage 1".to_vec(),
            "Case change at start",
        ),
        (
            b"Patient diagnosis:Hypertension, Stage 1".to_vec(),
            "Removed space",
        ),
        (
            b"\0atient diagnosis: Hypertension, Stage 1".to_vec(),
            "Null byte at start",
        ),
    ];

    let base_checksum = IntegrityHandler::compute_checksum(base_data, "blake3", &key).unwrap();

    for (modified_data, description) in test_cases {
        let modified_checksum =
            IntegrityHandler::compute_checksum(&modified_data, "blake3", &key).unwrap();

        // SAFETY: Even small changes must produce completely different checksums.
        assert_ne!(
            base_checksum, modified_checksum,
            "Checksum changed unexpectedly for: {}",
            description
        );

        // Count differing bits (measure of avalanche effect)
        let diff_bits = base_checksum
            .iter()
            .zip(modified_checksum.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();

        // For BLAKE3, expect approximately half the bits to differ (128 bits)
        // Allow significant margin: at least 64 bits different
        assert!(
            diff_bits >= 64,
            "Avalanche effect weak: only {} bits differ for '{}'",
            diff_bits,
            description
        );
    }
}

/// Test that HMAC signatures prevent tampering.
///
/// HMAC provides an additional layer of security by signing checksums.
#[test]
fn test_hmac_signature_prevents_tampering() {
    let key = vec![1u8; 32];
    let hmac_key = vec![2u8; 32];

    let data = b"Medical record: Patient #12345\nDiagnosis: Confidential";

    let checksum = IntegrityHandler::compute_checksum(data, "blake3", &key).unwrap();
    let signature = IntegrityHandler::compute_hmac_signature(&checksum, &hmac_key).unwrap();

    // Verify original signature passes
    assert!(
        IntegrityHandler::verify_hmac_signature(&checksum, &signature, &hmac_key).unwrap(),
        "Original signature should verify"
    );

    // SAFETY: Tampering with checksum should be detected.
    let mut tampered_checksum = checksum.clone();
    tampered_checksum[0] ^= 0xFF; // Flip bits in first byte

    assert!(
        !IntegrityHandler::verify_hmac_signature(&tampered_checksum, &signature, &hmac_key)
            .unwrap(),
        "Tampered checksum should fail HMAC verification"
    );

    // SAFETY: Tampering with signature should be detected.
    let mut tampered_signature = signature.clone();
    tampered_signature[0] ^= 0xFF;

    assert!(
        !IntegrityHandler::verify_hmac_signature(&checksum, &tampered_signature, &hmac_key)
            .unwrap(),
        "Tampered signature should fail HMAC verification"
    );

    // SAFETY: Wrong HMAC key should fail verification.
    let wrong_key = vec![3u8; 32];
    assert!(
        !IntegrityHandler::verify_hmac_signature(&checksum, &signature, &wrong_key).unwrap(),
        "Wrong HMAC key should fail verification"
    );
}

/// Test integrity chain verification.
///
/// When storing and retrieving data with checksums, the full chain
/// should be verifiable.
#[test]
fn test_integrity_chain_verification() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("integrity_test.dat");

    let key = vec![1u8; 32];
    let hmac_key = vec![2u8; 32];

    let config = IntegrityConfig::with_hmac_signing(key.clone(), hmac_key);

    let data = b"Complete patient record with multiple entries:\n\
        - Name: John Doe\n\
        - Age: 45\n\
        - Blood Type: A+\n\
        - Allergies: Penicillin\n\
        - Last Visit: 2025-01-15";

    // Compute checksum
    let checksum = IntegrityHandler::compute_checksum(data, "blake3", &key).unwrap();

    // Write file and checksum
    std::fs::write(&test_file, data).unwrap();
    IntegrityHandler::set_checksum_xattr(&test_file, &checksum, &config).unwrap();

    // Read back and verify integrity
    let retrieved_data = std::fs::read(&test_file).unwrap();
    let retrieved_checksum =
        IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();

    // SAFETY: Verify the integrity chain:
    // 1. Data was not corrupted
    assert_eq!(retrieved_data, data, "Stored data should match original");

    // 2. Checksum was stored and retrieved correctly
    assert_eq!(
        retrieved_checksum,
        Some(checksum.clone()),
        "Stored checksum should match computed checksum"
    );

    // 3. The checksum still verifies against the data
    assert!(
        IntegrityHandler::verify_integrity(&retrieved_data, &checksum, "blake3", &key).unwrap(),
        "Retrieved checksum should verify against retrieved data"
    );

    // Now test tampering detection
    let mut tampered_data = retrieved_data.clone();
    tampered_data[0] ^= 0xFF;
    std::fs::write(&test_file, &tampered_data).unwrap();

    // Verification should fail
    assert!(
        !IntegrityHandler::verify_integrity(&tampered_data, &checksum, "blake3", &key).unwrap(),
        "Tampered data should fail integrity verification"
    );
}

/// Test that checksums with different keys are different.
///
/// BLAKE3 keyed hash acts as a MAC - different keys produce different outputs.
#[test]
fn test_checksum_key_isolation() {
    let key1 = vec![1u8; 32];
    let key2 = vec![2u8; 32];

    let data = b"Medical data requiring keyed integrity";

    let checksum1 = IntegrityHandler::compute_checksum(data, "blake3", &key1).unwrap();
    let checksum2 = IntegrityHandler::compute_checksum(data, "blake3", &key2).unwrap();

    assert_ne!(
        checksum1, checksum2,
        "Different keys should produce different checksums"
    );

    // Each checksum should only verify with its own key
    assert!(IntegrityHandler::verify_integrity(data, &checksum1, "blake3", &key1).unwrap());
    assert!(IntegrityHandler::verify_integrity(data, &checksum2, "blake3", &key2).unwrap());

    // Cross-key verification should fail
    assert!(
        !IntegrityHandler::verify_integrity(data, &checksum1, "blake3", &key2).unwrap(),
        "Checksum should not verify with wrong key"
    );
    assert!(
        !IntegrityHandler::verify_integrity(data, &checksum2, "blake3", &key1).unwrap(),
        "Checksum should not verify with wrong key"
    );
}

/// Test HMAC key length requirements.
///
/// HMAC keys should be at least 32 bytes for security.
#[test]
fn test_hmac_key_length_requirements() {
    let checksum = b"test_checksum_value_32_bytes!!!!";

    // 32-byte key should work
    let valid_key = vec![1u8; 32];
    assert!(
        IntegrityHandler::compute_hmac_signature(checksum, &valid_key).is_ok(),
        "32-byte key should be accepted"
    );

    // 64-byte key should also work
    let long_key = vec![1u8; 64];
    assert!(
        IntegrityHandler::compute_hmac_signature(checksum, &long_key).is_ok(),
        "64-byte key should be accepted"
    );

    // 16-byte key should be rejected
    let short_key = vec![1u8; 16];
    assert!(
        IntegrityHandler::compute_hmac_signature(checksum, &short_key).is_err(),
        "Short key should be rejected"
    );
}

/// Test checksum storage and retrieval with extended attributes.
///
/// Verify that the integrity system correctly stores checksums as xattrs.
#[test]
fn test_checksum_xattr_operations() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("xattr_test.dat");

    let key = vec![1u8; 32];
    let config = IntegrityConfig::with_key(key.clone());

    let data = b"Test data for xattr integrity verification";
    let checksum = IntegrityHandler::compute_checksum(data, "blake3", &key).unwrap();

    // Create the file
    std::fs::write(&test_file, data).unwrap();

    // Set checksum
    IntegrityHandler::set_checksum_xattr(&test_file, &checksum, &config).unwrap();

    // Retrieve checksum
    let retrieved = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();

    assert_eq!(
        retrieved,
        Some(checksum.clone()),
        "Retrieved checksum should match original"
    );

    // Remove checksum
    IntegrityHandler::remove_checksum_xattr(&test_file, &config).unwrap();

    // Verify it's gone
    let after_removal = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();
    assert_eq!(after_removal, None, "Checksum should be None after removal");
}

/// Test HMAC signature storage and verification.
///
/// Verify that HMAC signatures are correctly stored and verified.
#[test]
fn test_hmac_signature_storage() {
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("hmac_test.dat");

    let key = vec![1u8; 32];
    let hmac_key = vec![2u8; 32];

    let config = IntegrityConfig::with_hmac_signing(key, hmac_key.clone());

    let data = b"Data requiring HMAC-protected integrity";
    let checksum = b"test_checksum_value_32_bytes!!!!";

    // Create the file
    std::fs::write(&test_file, data).unwrap();

    // Set checksum with HMAC
    IntegrityHandler::set_checksum_xattr(&test_file, checksum, &config).unwrap();

    // Verify checksum can be retrieved
    let retrieved = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();
    assert_eq!(retrieved, Some(checksum.to_vec()));

    // Tamper with the checksum directly via xattr
    xattr::set(
        &test_file,
        "user.zthfs.checksum",
        b"tampered_checksum_value_32b!!",
    )
    .unwrap();

    // HMAC verification should detect the tampering
    let after_tamper = IntegrityHandler::get_checksum_from_xattr(&test_file, &config).unwrap();
    assert_eq!(
        after_tamper, None,
        "Tampered checksum should be rejected by HMAC verification"
    );
}

/// Test that CRC32c is non-cryptographic but functional.
///
/// CRC32c is provided for legacy compatibility but is NOT collision-resistant.
#[test]
fn test_crc32c_properties() {
    let key = vec![1u8; 32];

    let data1 = b"Data for CRC32c test";
    let data2 = b"Different data for CRC32c test";

    let checksum1 = IntegrityHandler::compute_checksum(data1, "crc32c", &key).unwrap();
    let checksum2 = IntegrityHandler::compute_checksum(data2, "crc32c", &key).unwrap();

    // Different data should produce different checksums (usually)
    assert_ne!(
        checksum1, checksum2,
        "Different data should produce different CRC32c"
    );

    // CRC32c is only 4 bytes
    assert_eq!(checksum1.len(), 4, "CRC32c should be 4 bytes");
    assert_eq!(checksum2.len(), 4, "CRC32c should be 4 bytes");

    // Verify correctness
    assert!(IntegrityHandler::verify_integrity(data1, &checksum1, "crc32c", &key).unwrap());
    assert!(IntegrityHandler::verify_integrity(data2, &checksum2, "crc32c", &key).unwrap());
}

/// Test algorithm validation.
///
/// Unsupported algorithms should be rejected.
#[test]
fn test_unsupported_algorithm_rejection() {
    let key = vec![1u8; 32];
    let data = b"Test data";

    // These algorithms should fail
    let unsupported = vec!["md5", "sha1", "sha256", "sha512", "blake2"];

    for algo in unsupported {
        let result = IntegrityHandler::compute_checksum(data, algo, &key);
        assert!(result.is_err(), "Algorithm '{}' should be rejected", algo);

        if let Err(e) = result {
            assert!(
                e.to_string().contains("Unsupported"),
                "Error should mention unsupported algorithm: {}",
                e
            );
        }
    }
}

/// Test checksum length validation for different algorithms.
///
/// Each algorithm produces a fixed-length output.
#[test]
fn test_checksum_length_validation() {
    let key = vec![1u8; 32];
    let data = b"Test data for length validation";

    let blake3_checksum = IntegrityHandler::compute_checksum(data, "blake3", &key).unwrap();
    let crc32c_checksum = IntegrityHandler::compute_checksum(data, "crc32c", &key).unwrap();

    assert_eq!(blake3_checksum.len(), 32, "BLAKE3 should produce 32 bytes");
    assert_eq!(crc32c_checksum.len(), 4, "CRC32c should produce 4 bytes");

    // Setting wrong-length checksum should fail
    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("length_test.dat");
    std::fs::write(&test_file, data).unwrap();

    let blake3_config = IntegrityConfig::with_key(key.clone());

    // Wrong length for BLAKE3
    let result = IntegrityHandler::set_checksum_xattr(&test_file, &[1, 2, 3], &blake3_config);
    assert!(
        result.is_err(),
        "Setting 3-byte checksum for BLAKE3 should fail"
    );
}

/// Test case insensitivity of algorithm names.
///
/// Algorithm names should be case-insensitive for user convenience.
#[test]
fn test_algorithm_case_insensitivity() {
    let key = vec![1u8; 32];
    let data = b"Test data for case insensitivity";

    let test_cases = ["blake3", "BLAKE3", "BlAkE3", "bLaKe3"];

    let mut checksums = Vec::new();
    for algo in test_cases {
        let checksum = IntegrityHandler::compute_checksum(data, algo, &key).unwrap();
        checksums.push((algo, checksum));
    }

    // All should produce the same checksum
    for (i, (algo1, checksum1)) in checksums.iter().enumerate() {
        for (algo2, checksum2) in checksums.iter().skip(i + 1) {
            assert_eq!(
                checksum1, checksum2,
                "Algorithms {} and {} should produce same checksum",
                algo1, algo2
            );
        }
    }
}
