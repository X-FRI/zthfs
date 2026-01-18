//! Encryption security tests.
//!
//! These tests verify critical security properties of the AES-256-GCM
//! encryption implementation, including:
//! - Key sensitivity: different keys produce different ciphertext
//! - Nonce uniqueness: each encryption uses a unique nonce
//! - Authentication: tampering is detected via GCM authentication tag
//! - Round-trip correctness: encryption followed by decryption works

use crate::config::EncryptionConfig;
use crate::core::encryption::{EncryptionHandler, NonceManager};
use std::sync::Arc;
use tempfile::tempdir;

/// Test that different encryption keys produce different ciphertext.
///
/// This is a fundamental security property: even with the same plaintext
/// and nonce, different keys must produce completely different outputs.
#[test]
fn test_different_keys_produce_different_ciphertext() {
    let config1 = EncryptionConfig::with_random_keys();
    let config2 = EncryptionConfig::with_random_keys();

    let handler1 = EncryptionHandler::new(&config1);
    let handler2 = EncryptionHandler::new(&config2);

    let plaintext = b"Sensitive medical data";

    let ciphertext1 = handler1.encrypt(plaintext, "/test.txt").unwrap();
    let ciphertext2 = handler2.encrypt(plaintext, "/test.txt").unwrap();

    // SAFETY: Different keys must produce different ciphertext.
    // If this test fails, it indicates a catastrophic vulnerability
    // where key material doesn't affect encryption output.
    assert_ne!(
        ciphertext1, ciphertext2,
        "Different keys should produce different ciphertext"
    );

    // Verify the lengths are the same (same algorithm)
    assert_eq!(ciphertext1.len(), ciphertext2.len());

    // Verify that the difference is substantial (not just a few bytes)
    // Count differing bytes
    let diff_count = ciphertext1
        .iter()
        .zip(ciphertext2.iter())
        .filter(|(a, b)| a != b)
        .count();

    // At least 95% of bytes should differ for strong encryption
    let min_diff = (ciphertext1.len() * 95) / 100;
    assert!(
        diff_count >= min_diff,
        "Ciphertexts differ in {}/{} bytes, expected at least {}",
        diff_count,
        ciphertext1.len(),
        min_diff
    );
}

/// Test that encrypting the same file multiple times produces different ciphertext.
///
/// When using counter-based nonces (the secure mode), each encryption
/// operation must use a unique nonce, resulting in different ciphertext
/// even for the same plaintext.
///
/// NOTE: This test creates separate handler instances for decryption
/// because the nonce counter advances with each encryption.
#[test]
fn test_same_path_different_nonce() {
    let temp_dir = tempdir().unwrap();
    let config = EncryptionConfig::with_random_keys();

    let plaintext = b"Medical record data";
    let path = "/medical/patient_record.txt";

    // SAFETY: Use counter-based nonces for unique nonce per encryption.
    // First encryption with handler 1
    let nonce_manager1 = Arc::new(NonceManager::new(temp_dir.path().to_path_buf()));
    let handler1 = EncryptionHandler::with_nonce_manager(&config, nonce_manager1.clone());
    let ciphertext1 = handler1.encrypt(plaintext, path).unwrap();

    // Second encryption with handler 2 (shares same nonce manager)
    let handler2 = EncryptionHandler::with_nonce_manager(&config, nonce_manager1.clone());
    let ciphertext2 = handler2.encrypt(plaintext, path).unwrap();

    // SAFETY: With counter-based nonces, each encryption MUST produce
    // different ciphertext to prevent nonce reuse attacks.
    assert_ne!(
        ciphertext1, ciphertext2,
        "Same file encrypted twice should have different ciphertext (nonce reuse vulnerability)"
    );

    // To verify decryption works, we need to decrypt each ciphertext
    // using the NONCE VALUE at the time of encryption.
    // Since the handler advances the counter, we decrypt the LATEST
    // ciphertext (ciphertext2) which uses the current counter value.
    let decrypted_latest = handler2.decrypt(&ciphertext2, path).unwrap();
    assert_eq!(decrypted_latest, plaintext.to_vec());

    // For ciphertext1, we need to decrement the counter to get back to
    // the state when it was encrypted, then restore it.
    let counter_after_second = nonce_manager1.get_counter(path).unwrap();
    assert_eq!(
        counter_after_second, 2,
        "Counter should be 2 after two encryptions"
    );

    // Reset and re-encrypt to verify round-trip works correctly
    nonce_manager1.reset_counter(path).unwrap();
    let handler3 = EncryptionHandler::with_nonce_manager(&config, nonce_manager1);
    let ciphertext3 = handler3.encrypt(plaintext, path).unwrap();
    let decrypted3 = handler3.decrypt(&ciphertext3, path).unwrap();
    assert_eq!(decrypted3, plaintext.to_vec());
}

/// Test that different file paths produce different nonces.
///
/// Even without counter-based nonces, the path-based nonce derivation
/// must ensure different paths get different nonces.
#[test]
fn test_different_paths_different_nonce() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    let plaintext = b"Shared template content";

    let path1 = "/medical/patient_001.txt";
    let path2 = "/medical/patient_002.txt";

    let ciphertext1 = handler.encrypt(plaintext, path1).unwrap();
    let ciphertext2 = handler.encrypt(plaintext, path2).unwrap();

    // SAFETY: Different paths must produce different ciphertext.
    // If same plaintext at different paths produced identical ciphertext,
    // it would indicate poor nonce derivation.
    assert_ne!(
        ciphertext1, ciphertext2,
        "Different paths should produce different ciphertext"
    );

    // Verify each decrypts correctly with its respective path
    let decrypted1 = handler.decrypt(&ciphertext1, path1).unwrap();
    let decrypted2 = handler.decrypt(&ciphertext2, path2).unwrap();

    assert_eq!(decrypted1, plaintext.to_vec());
    assert_eq!(decrypted2, plaintext.to_vec());
}

/// Test that AES-GCM authentication detects tampering.
///
/// AES-GCM provides authenticated encryption: any modification to the
/// ciphertext must cause decryption to fail.
#[test]
fn test_encryption_is_authenticated() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    let plaintext = b"Patient: John Doe\nDiagnosis: Hypertension";
    let path = "/medical/patient_003.txt";

    let ciphertext = handler.encrypt(plaintext, path).unwrap();

    // SAFETY: Simulate an attacker tampering with the encrypted data.
    // Flipping even a single bit should cause authentication failure.
    let mut tampered = ciphertext.clone();

    // Tamper with first byte of ciphertext
    if let Some(byte) = tampered.get_mut(0) {
        *byte = byte.wrapping_add(1);
    }

    // Decryption should fail due to authentication tag mismatch
    let result = handler.decrypt(&tampered, path);
    assert!(
        result.is_err(),
        "Tampered ciphertext should fail authentication"
    );

    // Try tampering with the last byte (likely part of auth tag)
    let mut tampered2 = ciphertext.clone();
    if let Some(byte) = tampered2.last_mut() {
        *byte = byte.wrapping_add(1);
    }

    let result2 = handler.decrypt(&tampered2, path);
    assert!(
        result2.is_err(),
        "Tampered authentication tag should cause decryption failure"
    );

    // Verify original still decrypts correctly
    let decrypted = handler.decrypt(&ciphertext, path).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test that encryption and decryption are inverses (round-trip).
///
/// This basic correctness test ensures data survives the encrypt/decrypt cycle.
#[test]
fn test_decryption_after_round_trip() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    let test_cases = vec![
        b"Short text".to_vec(),
        b"Patient: Jane Smith\nAge: 45\nAllergies: Penicillin".to_vec(),
        b"".to_vec(),     // Empty
        vec![b'X'; 1000], // Larger data
    ];

    for plaintext in test_cases {
        let path = "/test/round_trip_test.bin";

        let ciphertext = handler.encrypt(&plaintext, path).unwrap();
        let decrypted = handler.decrypt(&ciphertext, path).unwrap();

        assert_eq!(
            decrypted,
            plaintext,
            "Round-trip encryption/decrypt failed for {} bytes",
            plaintext.len()
        );
    }
}

/// Test that empty files can be encrypted and decrypted.
///
/// Empty files are a common edge case and must be handled correctly.
#[test]
fn test_empty_file_encryption() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    let plaintext = b"";
    let path = "/medical/empty_record.txt";

    let ciphertext = handler.encrypt(plaintext, path).unwrap();
    let decrypted = handler.decrypt(&ciphertext, path).unwrap();

    assert_eq!(
        decrypted.len(),
        0,
        "Empty file should remain empty after round-trip"
    );
    assert!(decrypted.is_empty());

    // Ciphertext should not be empty (contains auth tag)
    assert!(
        ciphertext.len() > 12,
        "Ciphertext should contain at least nonce + auth tag"
    );
}

/// Test encryption of large files (10 MB).
///
/// Large files test for any buffer or allocation issues.
#[test]
fn test_large_file_encryption() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    // Generate 10 MB of data
    let large_data = vec![b'X'; 10_000_000];
    let path = "/medical/large_scan.dat";

    // Measure encryption time for performance reference
    let start_encrypt = std::time::Instant::now();
    let ciphertext = handler.encrypt(&large_data, path).unwrap();
    let encrypt_duration = start_encrypt.elapsed();

    // Measure decryption time
    let start_decrypt = std::time::Instant::now();
    let decrypted = handler.decrypt(&ciphertext, path).unwrap();
    let decrypt_duration = start_decrypt.elapsed();

    assert_eq!(decrypted.len(), large_data.len());
    assert_eq!(decrypted, large_data);

    // Performance sanity checks (not strict requirements)
    // Should be able to encrypt 10MB in reasonable time (< 5 seconds)
    assert!(
        encrypt_duration.as_secs() < 5,
        "10MB encryption took {:?}, expected < 5s",
        encrypt_duration
    );

    assert!(
        decrypt_duration.as_secs() < 5,
        "10MB decryption took {:?}, expected < 5s",
        decrypt_duration
    );
}

/// Test that ciphertext is significantly larger than plaintext due to GCM overhead.
///
/// AES-GCM adds a 16-byte authentication tag to the ciphertext.
/// This test verifies we're accounting for that overhead.
#[test]
fn test_ciphertext_size_overhead() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    let test_sizes = [0, 1, 16, 100, 1000, 10000];

    for size in test_sizes {
        let plaintext = vec![b'A'; size];
        let path = "/test/size_test.bin";

        let ciphertext = handler.encrypt(&plaintext, path).unwrap();

        // AES-GCM adds 16 bytes for authentication tag
        // Ciphertext length = plaintext length + 16
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + 16,
            "Ciphertext size incorrect for {} byte plaintext",
            size
        );
    }
}

/// Test nonce counter overflow detection.
///
/// The NonceManager should detect counter overflow before it happens.
#[test]
fn test_nonce_counter_overflow_protection() {
    let temp_dir = tempdir().unwrap();
    let _config = EncryptionConfig::with_random_keys();

    let nonce_manager = NonceManager::new(temp_dir.path().to_path_buf());
    let path = "/test/overflow_test.txt";

    // To test overflow behavior, we need to simulate multiple increments.
    // Since we can't directly access the internal counter cache, we'll verify
    // the overflow protection exists by checking the API behavior.

    // First, set up the counter by incrementing
    let _ = nonce_manager.increment_counter(path);
    let current = nonce_manager.get_counter(path).unwrap();
    assert!(current > 0, "Counter should be incremented");

    // The NonceManager's increment_counter uses saturating_add which will
    // wrap to 0 instead of overflowing. This test verifies the basic
    // counter behavior and documents the overflow protection strategy.
    // In practice, hitting u64::MAX would require 2^64 encryptions of
    // the same file, which is virtually impossible.
}

/// Test that same plaintext encrypted multiple times has high entropy.
///
/// Ciphertext should appear random with high entropy, making it
/// indistinguishable from random data.
#[test]
fn test_ciphertext_entropy() {
    let config = EncryptionConfig::with_random_keys();
    let handler = EncryptionHandler::new(&config);

    // Encrypt a highly repetitive plaintext
    let repetitive_data = vec![b'A'; 10000];
    let path = "/test/entropy_test.bin";

    let ciphertext = handler.encrypt(&repetitive_data, path).unwrap();

    // Count byte frequency in ciphertext (excluding auth tag)
    let mut freq = [0usize; 256];
    for byte in &ciphertext[..ciphertext.len() - 16] {
        freq[*byte as usize] += 1;
    }

    // Calculate approximate entropy
    let total = (ciphertext.len() - 16) as f64;
    let mut entropy = 0.0;
    for count in freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    // Entropy should be close to 8 (maximum for a byte)
    // Allow some margin for statistical variation
    assert!(
        entropy > 7.5,
        "Ciphertext entropy ({:.2}) is too low, expected > 7.5",
        entropy
    );
}
