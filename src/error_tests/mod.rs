//! Error path testing
//!
//! Tests various error conditions and edge cases in the filesystem implementation.
//! These tests focus on how the filesystem handles and recovers from errors
//! rather than on testing the error type conversions themselves (which are covered
//! in src/errors.rs).

mod corruption_tests;
mod io_tests;
mod permission_tests;
