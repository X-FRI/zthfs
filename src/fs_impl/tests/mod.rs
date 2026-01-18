//! FUSE operation unit tests
//!
//! Tests the Filesystem trait implementation in mod.rs

mod fuse_test_utils;

// Placeholder test modules for each FUSE callback
// These will be implemented in subsequent tasks

mod lookup_tests;
mod access_tests;
mod getattr_tests;
mod create_tests;
mod read_tests;
mod write_tests;
mod readdir_tests;
mod mkdir_tests;
mod unlink_tests;
mod rmdir_tests;
mod rename_tests;
mod setattr_tests;
mod open_tests;
mod flush_tests;
mod release_tests;
mod fsync_tests;
