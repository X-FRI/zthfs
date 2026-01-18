# ZTHFS Testing Guide

This guide provides comprehensive information about testing the Zero-Trust Healthcare Filesystem (ZTHFS), including unit tests, integration tests, property-based tests, and coverage analysis.

## Table of Contents

- [Overview](#overview)
- [Test Structure](#test-structure)
- [Running Tests](#running-tests)
- [Test Categories](#test-categories)
- [Writing Tests](#writing-tests)
- [Coverage Analysis](#coverage-analysis)
- [CI/CD Integration](#cicd-integration)

## Overview

ZTHFS employs a multi-layered testing strategy to ensure correctness, security, and performance:

- **Unit tests**: Fast, isolated tests for individual functions and modules
- **Integration tests**: Full FUSE filesystem tests with real I/O operations
- **Property-based tests**: Hypothesis-based tests that verify invariants across random inputs
- **Stress tests**: Performance and reliability tests with large files and many operations
- **Concurrent access tests**: Thread-safety verification for parallel operations

Current test coverage: **64.89%** (target: 85%+)

## Test Structure

```
tests/
├── integration_basic.rs       # Basic filesystem operations
├── integration_concurrent.rs  # Concurrent access patterns
├── integration_stress.rs      # Stress tests with large files
├── integration_fuse.rs        # FUSE-specific operations
├── fuse_integration_test.rs   # Full FUSE integration
├── property_tests.rs          # Property-based tests
└── test_helpers.rs            # Common test utilities

src/
└── **/                       # Unit tests in each module
```

## Running Tests

### Run All Tests

```bash
# Run all tests (unit + integration)
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run tests in verbose mode
cargo test --workspace -- --show-output
```

### Run Specific Test Categories

```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test integration_basic
cargo test --test integration_concurrent
cargo test --test integration_stress
cargo test --test integration_fuse

# Property-based tests
cargo test --test property_tests

# Specific test function
cargo test test_concurrent_file_creation
```

### Run Ignored Tests

Stress tests and some integration tests are marked with `#[ignore]` to avoid slowing down normal test runs:

```bash
# Run all tests including ignored ones
cargo test --workspace -- --ignored

# Run only ignored tests
cargo test --workspace -- --ignored
```

### Run Tests with Specific Features

```bash
# Run tests with specific features enabled
cargo test --workspace --features "full"

# Run tests in release mode (faster execution)
cargo test --workspace --release
```

## Test Categories

### Unit Tests

Unit tests are located within each source module and test individual functions in isolation.

**Example:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let config = EncryptionConfig::random().unwrap();
        let handler = EncryptionHandler::new(&config);
        let plaintext = b"Hello, World!";
        let encrypted = handler.encrypt(plaintext, "/test").unwrap();
        let decrypted = handler.decrypt(&encrypted, "/test").unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }
}
```

### Integration Tests

Integration tests mount a real FUSE filesystem and perform actual filesystem operations.

#### Basic Integration Tests (`integration_basic.rs`)

Tests basic filesystem operations:
- File creation, reading, writing
- Directory operations (mkdir, rmdir)
- File metadata
- Rename operations
- File deletion

#### Concurrent Access Tests (`integration_concurrent.rs`)

Tests thread-safety and race conditions:
- `test_concurrent_file_creation`: 10 threads creating 5 files each
- `test_concurrent_directory_creation`: Multiple threads creating directories
- `test_concurrent_read_write_same_file`: Mixed readers and writers
- `test_concurrent_nested_directory_creation`: Parallel nested directory creation
- `test_concurrent_file_deletion`: Multiple threads deleting files
- `test_concurrent_rename_operations`: Parallel rename operations
- `test_concurrent_metadata_operations`: Concurrent metadata access
- `test_concurrent_directory_listing`: Parallel directory listings
- `test_concurrent_large_file_operations`: Concurrent large file writes

**Note:** These tests use barriers to synchronize thread start and verify that operations complete correctly under concurrent access.

#### Stress Tests (`integration_stress.rs`)

Tests filesystem behavior under load:
- `test_many_small_files`: Creates 1000 small files
- `test_deep_directory_nesting`: Creates 50 levels of nested directories
- `test_wide_directory_tree`: Creates a wide tree (20 branches per level, 3 levels)
- `test_large_file_write`: Writes a 5 MB file
- `test_large_file_random_access`: Random access in a 1 MB file
- `test_large_file_write_and_read`: Writes and reads a 100 MB file
- `test_random_access_large_file`: Random access in a 10 MB file
- `test_rapid_file_create_delete_cycle`: 100 create/delete cycles
- `test_many_file_renames`: Multiple rounds of file renames
- `test_file_descriptor_limit`: Opens many files simultaneously
- `test_long_file_names`: Tests long and special-character filenames
- `test_many_directory_operations`: Creates, lists, and deletes 100 directories
- `test_append_stress`: 1000 append operations
- `test_truncate_stress`: Multiple truncations to decreasing sizes
- `test_mixed_operations_stress`: 200 mixed filesystem operations

**Note:** All stress tests are marked with `#[ignore]` and should be run explicitly.

#### FUSE Integration Tests (`integration_fuse.rs`)

Tests FUSE-specific operations:
- FUSE mount/unmount
- Permission checking
- Attribute handling
- Extended attributes

### FUSE API Tests (`fuse_api_tests.rs`)

Tests FUSE operations by calling Filesystem trait methods directly (via internal simulation helpers), without requiring root privileges or actual FUSE mounting:

**Lookup tests (7 tests):**
- `test_lookup_existing_file` - Verify successful file lookup
- `test_lookup_nonexistent_file` - Verify ENOENT for missing files
- `test_lookup_directory` - Verify directory lookup
- `test_lookup_unauthorized_user` - Verify EACCES for unauthorized users
- `test_lookup_root_user_always_authorized` - Verify root always has access
- `test_lookup_invalid_parent_inode` - Verify ENOENT for invalid parent
- `test_lookup_empty_filename` - Verify behavior with empty filename

**GetAttr tests (3 tests):**
- `test_getattr_existing_file` - Verify attribute retrieval for existing file
- `test_getattr_root_directory` - Verify root directory attributes
- `test_getattr_nonexistent_inode` - Verify ENOENT for invalid inode

**Access tests (4 tests):**
- `test_access_authorized_user` - Verify authorized user access
- `test_access_unauthorized_user` - Verify EACCES for unauthorized users
- `test_access_read_mask` - Verify read access mask handling
- `test_access_write_mask` - Verify write access mask handling

**Create tests (3 tests):**
- `test_create_new_file` - Verify successful file creation
- `test_create_in_nested_path` - Verify creation with nested paths
- `test_create_unauthorized_user` - Verify EACCES for unauthorized users

**Read tests (3 tests):**
- `test_read_existing_file` - Verify successful file reading
- `test_read_nonexistent_file` - Verify error for nonexistent file
- `test_read_unauthorized_user` - Verify EACCES for unauthorized users

**Write tests (3 tests):**
- `test_write_new_file` - Verify successful file writing
- `test_write_append` - Verify appending to existing files
- `test_write_unauthorized_user` - Verify EACCES for unauthorized users

**Readdir tests (3 tests):**
- `test_readdir_root` - Verify reading root directory with files
- `test_readdir_empty_directory` - Verify reading empty directory
- `test_readdir_nonexistent_directory` - Verify error for invalid inode

**Mkdir tests (2 tests):**
- `test_mkdir_new_directory` - Verify successful directory creation
- `test_mkdir_unauthorized` - Verify EACCES for unauthorized users

**Unlink tests (2 tests):**
- `test_unlink_existing_file` - Verify successful file deletion
- `test_unlink_nonexistent_file` - Verify error for nonexistent file

**Rmdir tests (2 tests):**
- `test_rmdir_existing_directory` - Verify successful directory removal
- `test_rmdir_nonexistent_directory` - Verify error for nonexistent directory

**Note:** These tests run without any special permissions and are suitable for CI/CD.

Run with:
```bash
cargo test --test fuse_api_tests
```

### Property-Based Tests (`property_tests.rs`)

Uses the `proptest` crate to verify invariants across random inputs:

- Encryption roundtrip (256 cases)
- Integrity checksum computation
- Key derivation properties
- Nonce uniqueness

**Example:**
```rust
proptest! {
    #[test]
    fn test_encryption_roundtrip(data in any::<Vec<u8>>()) {
        let config = EncryptionConfig::random().unwrap();
        let handler = EncryptionHandler::new(&config);
        let encrypted = handler.encrypt(&data, "/test").unwrap();
        let decrypted = handler.decrypt(&encrypted, "/test").unwrap();
        prop_assert_eq!(data, decrypted);
    }
}
```

## Writing Tests

### Test Helpers

The `test_helpers.rs` module provides utilities for writing integration tests:

```rust
use test_helpers::{MountedFs, TestFs};

// Create a test filesystem (not mounted)
let test_fs = TestFs::new();

// Create and mount a test filesystem
let mounted = MountedFs::new(test_fs);
let mount_path = mounted.path();

// The filesystem will be automatically unmounted when `mounted` is dropped
```

### Creating a New Integration Test

1. Create a new file in `tests/` or add to an existing file
2. Import the test helpers:
   ```rust
   mod test_helpers;
   use test_helpers::{MountedFs, TestFs};
   ```
3. Write your test using the standard Rust testing approach
4. Use `#[ignore]` for slow tests

### Creating a New Unit Test

Add tests within the module being tested, using `#[cfg(test)]`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        // Test code here
    }
}
```

### Test Naming Conventions

- Unit tests: `test_<module>_<feature>`
- Integration tests: `test_<category>_<operation>`
- Property tests: `prop_test_<invariant>`
- Stress tests: `test_<operation>_stress` (with `#[ignore]`)

### Best Practices

1. **Use descriptive test names**: The test name should describe what is being tested
2. **Test one thing per test**: Each test should verify a single behavior
3. **Use `#[ignore]` for slow tests**: Mark tests that take more than 1 second
4. **Clean up resources**: Use RAII guards (like `MountedFs`) for automatic cleanup
5. **Test error cases**: Verify that errors are returned when expected
6. **Use assertions effectively**: Provide clear error messages in assertions

## Coverage Analysis

### Installing Tarpaulin

```bash
# Install cargo-tarpaulin
cargo install cargo-tarpaulin
```

### Running Coverage Analysis

```bash
# Generate HTML coverage report
cargo tarpaulin --workspace --exclude-files '*/tests/*' --out Html

# Generate terminal output
cargo tarpaulin --workspace --exclude-files '*/tests/*' --out Stdout

# Generate multiple formats
cargo tarpaulin --workspace --exclude-files '*/tests/*' --out Html --out Lcov

# Run with timeout (longer for integration tests)
cargo tarpaulin --workspace --exclude-files '*/tests/*' --out Html --timeout 300
```

### Coverage Report Location

After running tarpaulin with `--out Html`, the report is generated at:
```
target/tarpaulin-report.html
```

Open this file in a browser to view detailed line-by-line coverage information.

### Coverage Goals

| Module | Target | Current |
|--------|--------|---------|
| Core encryption | 90% | 85% |
| Core integrity | 90% | 82% |
| FUSE operations | 85% | 75% |
| Security validation | 90% | 88% |
| Overall | 85% | 64.89% |

### Improving Coverage

To improve coverage for a specific module:

1. Run coverage with line output:
   ```bash
   cargo tarpaulin --lib -p zthfs --out Stdout
   ```

2. Identify uncovered lines in the output

3. Write tests for the uncovered code paths

4. Re-run coverage to verify improvement

## CI/CD Integration

### GitHub Actions Workflow

The project includes CI workflows that:

1. Run all tests on every push and pull request
2. Generate coverage reports
3. Run linters (clippy)
4. Check formatting (rustfmt)

### Local CI Testing

To test locally what CI will run:

```bash
# Format check
cargo fmt -- --check

# Linter
cargo clippy --all-targets -- -D warnings

# Tests
cargo test --workspace

# Coverage (if tarpaulin is available)
cargo tarpaulin --workspace --exclude-files '*/tests/*' --out Html
```

## Troubleshooting

### FUSE Mount Issues

If tests fail with FUSE mount errors:

1. Ensure FUSE is installed and permissions are correct:
   ```bash
   # Check if fuse is available
   fusermount --version

   # Ensure user is in fuse group (Linux)
   sudo usermod -aG fuse $USER
   ```

2. Clean up any stuck mounts:
   ```bash
   fusermount -u /path/to/mount point
   ```

3. Run tests with elevated privileges (not recommended):
   ```bash
   sudo cargo test
   ```

### Tempfile Issues

If tests fail with tempfile errors:

1. Ensure `/tmp` is writable
2. Check disk space: `df -h /tmp`
3. Clean up old temp files: `rm -rf /tmp/zthfs-*`

### Timeout Issues

For long-running tests:

1. Run specific test files instead of all tests
2. Increase timeout: `cargo test -- --test-threads=1`
3. Run ignored tests separately: `cargo test -- --ignored`

## Test Statistics

As of the latest test run:

| Category | Test Count |
|----------|------------|
| Unit tests | 42 |
| Integration tests (basic) | 15 |
| Integration tests (concurrent) | 9 |
| Integration tests (stress) | 14 |
| Integration tests (FUSE) | 8 |
| Property tests | 4 |
| **Total** | **92** |

## References

- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [fuser Documentation](https://docs.rs/fuser/)
- [proptest Documentation](https://docs.rs/proptest/)
- [cargo-tarpaulin Documentation](https://github.com/xd009642/tarpaulin)
