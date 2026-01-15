//! Concurrent operation integration tests
//!
//! These tests verify that the filesystem handles multiple concurrent
//! operations correctly, including thread safety and race conditions.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::{self, JoinHandle};
use std::time::Duration;

mod test_helpers;
use test_helpers::{MountedFs, TestFs};

/// Helper to create and mount a test filesystem
fn setup_mounted_fs() -> MountedFs {
    let test_fs = TestFs::new();
    std::thread::sleep(Duration::from_millis(200));
    MountedFs::new(test_fs)
}

#[test]
#[ignore]
fn test_concurrent_file_creation() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_threads = 10;
    let files_per_thread = 5;
    let barrier = Arc::new(Barrier::new(num_threads));
    let error_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for thread_id in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let error_count = Arc::clone(&error_count);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait(); // Synchronize start

            for file_id in 0..files_per_thread {
                let file_path =
                    mount_path.join(format!("thread_{}_file_{}.txt", thread_id, file_id));

                match File::create(&file_path) {
                    Ok(mut file) => {
                        if file.write_all(b"Concurrent test").is_err() {
                            error_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        error_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify no errors occurred
    assert_eq!(
        error_count.load(Ordering::Relaxed),
        0,
        "No errors should occur"
    );

    // Verify all files were created
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_threads * files_per_thread);
}

#[test]
#[ignore]
fn test_concurrent_directory_creation() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_threads = 5;
    let dirs_per_thread = 3;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for thread_id in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            for dir_id in 0..dirs_per_thread {
                let dir_path = mount_path.join(format!("dir_thread_{}_{}", thread_id, dir_id));
                let _ = fs::create_dir(&dir_path);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify directories were created
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_threads * dirs_per_thread);
}

#[test]
#[ignore]
fn test_concurrent_read_write_same_file() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let file_path = mount_path.join("shared_file.txt");
    let initial_data = b"Initial data for concurrent access test";

    // Create and initialize file
    {
        let mut file = File::create(&file_path).expect("Failed to create file");
        file.write_all(initial_data)
            .expect("Failed to write initial data");
    }

    let num_writers = 3;
    let num_readers = 5;
    let total_threads = num_writers + num_readers;
    let barrier = Arc::new(Barrier::new(total_threads));
    let write_count = Arc::new(AtomicUsize::new(0));
    let read_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // Writer threads
    for writer_id in 0..num_writers {
        let barrier = Arc::clone(&barrier);
        let write_count = Arc::clone(&write_count);
        let file_path = file_path.clone();

        let handle = thread::spawn(move || {
            barrier.wait();

            match OpenOptions::new().write(true).append(true).open(&file_path) {
                Ok(mut file) => {
                    let data = format!(" Writer {}", writer_id);
                    if file.write_all(data.as_bytes()).is_ok() {
                        write_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {}
            }
        });

        handles.push(handle);
    }

    // Reader threads
    for _reader_id in 0..num_readers {
        let barrier = Arc::clone(&barrier);
        let read_count = Arc::clone(&read_count);
        let file_path = file_path.clone();

        let handle = thread::spawn(move || {
            barrier.wait();

            if File::open(&file_path).is_ok() {
                read_count.fetch_add(1, Ordering::Relaxed);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify operations completed
    assert_eq!(write_count.load(Ordering::Relaxed), num_writers);
    assert_eq!(read_count.load(Ordering::Relaxed), num_readers);
}

#[test]
#[ignore]
fn test_concurrent_nested_directory_creation() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_threads = 4;
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for thread_id in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            // Each thread creates a different nested structure
            for depth in 0..3 {
                let nested_path = mount_path
                    .join(format!("thread_{}", thread_id))
                    .join(format!("level_{}", depth));

                if fs::create_dir_all(&nested_path).is_err() {
                    // Ignore errors - some directories may already exist
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify directories were created
    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), num_threads);
}

#[test]
#[ignore]
fn test_concurrent_file_deletion() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 20;

    // Create files first
    for i in 0..num_files {
        let file_path = mount_path.join(format!("delete_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    let num_deleters = 5;
    let files_per_deleter = num_files / num_deleters;
    let barrier = Arc::new(Barrier::new(num_deleters));
    let deleted_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for deleter_id in 0..num_deleters {
        let barrier = Arc::clone(&barrier);
        let deleted_count = Arc::clone(&deleted_count);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            for i in 0..files_per_deleter {
                let file_idx = deleter_id * files_per_deleter + i;
                let file_path = mount_path.join(format!("delete_{}.txt", file_idx));

                if fs::remove_file(&file_path).is_ok() {
                    deleted_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all files were deleted
    assert_eq!(deleted_count.load(Ordering::Relaxed), num_files);

    let entries: Vec<_> = fs::read_dir(mount_path)
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    assert_eq!(entries.len(), 0);
}

#[test]
#[ignore]
fn test_concurrent_rename_operations() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 10;

    // Create initial files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("file_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    let num_threads = 5;
    let barrier = Arc::new(Barrier::new(num_threads));
    let rename_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for thread_id in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let rename_count = Arc::clone(&rename_count);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            for i in 0..num_files {
                let old_path = mount_path.join(format!("file_{}.txt", i));
                let new_path = mount_path.join(format!("renamed_t{}_f{}.txt", thread_id, i));

                if fs::rename(&old_path, &new_path).is_ok() {
                    rename_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // At least some renames should succeed
    assert!(rename_count.load(Ordering::Relaxed) > 0);
}

#[test]
#[ignore]
fn test_concurrent_metadata_operations() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 5;

    // Create files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("meta_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let operation_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for _ in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let operation_count = Arc::clone(&operation_count);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            for i in 0..num_files {
                let file_path = mount_path.join(format!("meta_{}.txt", i));

                // Perform various metadata operations
                if fs::metadata(&file_path).is_ok() {
                    operation_count.fetch_add(1, Ordering::Relaxed);
                }

                let perms = fs::Permissions::from_mode(0o644);
                let _ = fs::set_permissions(&file_path, perms);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify operations completed
    assert_eq!(
        operation_count.load(Ordering::Relaxed),
        num_files * num_threads
    );
}

#[test]
#[ignore]
fn test_concurrent_directory_listing() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_files = 50;

    // Create many files
    for i in 0..num_files {
        let file_path = mount_path.join(format!("list_{}.txt", i));
        File::create(&file_path).expect("Failed to create file");
    }

    let num_threads = 10;
    let barrier = Arc::new(Barrier::new(num_threads));
    let listing_count = Arc::new(AtomicUsize::new(0));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for _ in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let listing_count = Arc::clone(&listing_count);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            if fs::read_dir(&mount_path).is_ok() {
                let entries: Vec<_> = fs::read_dir(&mount_path)
                    .unwrap()
                    .filter_map(Result::ok)
                    .collect();

                if entries.len() == num_files {
                    listing_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // All listings should succeed and show correct count
    assert_eq!(listing_count.load(Ordering::Relaxed), num_threads);
}

#[test]
#[ignore]
fn test_concurrent_large_file_operations() {
    let mounted = setup_mounted_fs();
    let mount_path = mounted.path();

    let num_threads = 4;
    let chunk_size = 10_000; // 10 KB per thread
    let barrier = Arc::new(Barrier::new(num_threads));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for thread_id in 0..num_threads {
        let barrier = Arc::clone(&barrier);
        let mount_path = mount_path.to_path_buf();

        let handle = thread::spawn(move || {
            barrier.wait();

            let file_path = mount_path.join(format!("large_{}.bin", thread_id));
            let data = vec![0x42u8; chunk_size];

            if let Ok(mut file) = File::create(&file_path) {
                let _ = file.write_all(&data);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    // Verify all files exist with correct size
    for thread_id in 0..num_threads {
        let file_path = mount_path.join(format!("large_{}.bin", thread_id));
        let metadata = fs::metadata(&file_path).expect("Failed to get metadata");
        assert_eq!(metadata.len(), chunk_size as u64);
    }
}
