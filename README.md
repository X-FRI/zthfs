# ZTHFS - Zero-Trust Healthcare Filesystem

[![License](https://img.shields.io/badge/license-BSD3--Clause-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-blue.svg)](https://www.rust-lang.org)

## Overview

ZTHFS is a transparent encryption filesystem designed for medical data protection. The project implements cryptographic primitives and security mechanisms required for building a HIPAA/GDPR-compliant storage system.

**Current Status**: The project provides a security library with full FUSE integration. The filesystem can be mounted and used for encrypted file storage with transparent encryption/decryption.

## Architecture

The system comprises eight core modules. Encryption and integrity modules form the cryptographic foundation. The security module implements access control and audit logging. Transaction management provides atomic operations and crash recovery. Key management handles secure storage and rotation of cryptographic keys.

File operations are implemented through a full FUSE filesystem implementation in `fuse.rs`. The filesystem supports chunked storage for large files, partial write operations, and inode-based file tracking. All operations are accessible through a standard mounted filesystem with transparent encryption/decryption.

## Cryptographic Security

Encryption uses AES-256-GCM with a unique nonce per file. The nonce derives from BLAKE3(path || nonce_seed), ensuring deterministic yet unpredictable nonces across files. This construction prevents nonce reuse while maintaining reproducibility for file recovery.

Integrity verification supports two algorithms. BLAKE3 provides cryptographic message authentication through keyed hashing. CRC32c offers a lightweight alternative for non-critical data. Checksums store as extended attributes, enabling verification without decryption.

The timing attack protection module uses constant-time comparisons from the `subtle` crate. Authentication failures trigger exponential backoff delays starting at 100ms and doubling with each attempt, capped at 5 seconds. Failed attempt counting persists across requests, with lockout durations calculated as 2^(attempt_count - 1) seconds, maxing at 1 hour.

## Access Control

The security validator implements POSIX permission checking with user and group whitelists. File access requires membership in `allowed_users` or `allowed_groups`. The permission checker extracts owner, group, and mode bits from file metadata, then applies standard POSIX rwx logic.

Zero-trust mode, enabled via `with_zero_trust_root()`, removes the traditional root bypass. In this mode, uid 0 must pass the same permission checks as other users and must appear in the allowed users list. Root access attempts generate audit log entries at High severity.

## Transaction Management

Write-ahead logging (WAL) ensures atomic operations and crash recovery. Each transaction records to a separate WAL file before execution. The transaction lifecycle progresses through three states: InProgress, Committed, and RolledBack. On startup, the WAL scans for incomplete transactions and rolls them back automatically.

Copy-on-write (COW) primitives enable atomic file updates. The `atomic_write` function writes data to a temporary file, syncs to disk, then renames over the target. POSIX guarantees atomic rename operations, preventing partial writes.

## Key Management

The key management system provides a pluggable storage interface. `InMemoryKeyStorage` serves testing scenarios. `FileKeyStorage` encrypts keys at rest using a master key derived from system-specific entropy (hostname, machine-id, username). Each key stores with metadata including version number, creation timestamp, and expiration time.

Key rotation generates a new version with an incremented version counter. The old version remains available until manually deleted, supporting gradual key migration. A default key protection prevents accidental deletion of the primary encryption key.

## Usage

### Library API

The core modules expose a Rust API for integration into applications:

```rust
use zthfs::{
    core::encryption::EncryptionHandler,
    core::integrity::IntegrityHandler,
    config::EncryptionConfig,
};

let config = EncryptionConfig::random()?;
let handler = EncryptionHandler::new(&config);
let encrypted = handler.encrypt(data, "/path/to/file")?;

let checksum = IntegrityHandler::compute_checksum(
    &encrypted, "blake3", &config.key,
)?;
```

### Command Line Interface

The binary provides seven subcommands:

- `init` generates a configuration file with random keys
- `validate` checks configuration file syntax and security settings
- `mount` mounts the FUSE filesystem with the specified configuration
- `unmount` unmounts a mounted filesystem
- `health` displays component status
- `demo` runs a demonstration of cryptographic operations
- `info` shows version and build information

## Testing

The test suite comprises 103 unit tests covering cryptographic operations, security validation, key management, and transaction handling. All tests pass on the main branch.

Run tests with `cargo test --lib`. Integration tests and FUSE filesystem tests are not yet implemented.

## Implementation Status

### FUSE Operations

| Operation | Status | Notes |
|-----------|--------|-------|
| lookup | ✅ Implemented | Path resolution with permission check |
| getattr | ✅ Implemented | File attributes with extended metadata |
| read | ✅ Implemented | Chunked reading with decryption |
| write | ✅ Implemented | Partial write support |
| readdir | ✅ Implemented | Directory listing |
| create | ✅ Implemented | File creation |
| unlink | ✅ Implemented | File deletion |
| mkdir | ✅ Implemented | Directory creation with marker file |
| rmdir | ✅ Implemented | Empty directory removal |
| rename | ✅ Implemented | Atomic cross-directory rename |
| setattr | ✅ Implemented | chmod, chown, utime, truncate |
| open | ✅ Implemented | Permission-based access control |
| release | ✅ Implemented | Handle release |
| fsync | ✅ Implemented | Data and metadata sync |

### Module Status

Complete modules: encryption, integrity, logging, configuration, security validation, transactions, key management, FUSE filesystem.

Not implemented: HSM/KMS backends (feature flags exist but are empty), performance monitoring, integration tests.

## Development Roadmap

Short-term priorities include adding integration tests and production deployment tooling. Medium-term goals cover HSM/KMS backends. Long-term objectives target distributed storage and multi-tenant isolation.

## License

```
Copyright (c) 2025 Somhairle H. Marisol

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.
    * Neither the name of ZTHFS nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
