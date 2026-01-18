//! Security tests for ZTHFS.
//!
//! This module contains comprehensive security-focused tests that verify:
//! - Encryption security properties (AES-256-GCM)
//! - Integrity verification (BLAKE3, HMAC)
//! - Access control and authorization
//!
//! These tests are separate from unit tests and focus specifically on
//! security properties and attack resistance.

mod encryption_tests;
mod integrity_tests;
mod access_control_tests;
