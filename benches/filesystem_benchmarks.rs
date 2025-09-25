use criterion::{Criterion, criterion_group, criterion_main};
use std::path::Path;
use tempfile::tempdir;
use zthfs::{
    config::{FilesystemConfigBuilder, LogConfig},
    fs_impl::Zthfs,
    operations::FileSystemOperations,
};

fn create_test_filesystem() -> (Zthfs, tempfile::TempDir) {
    let temp_dir = tempdir().unwrap();
    let log_dir = tempdir().unwrap();

    let config = FilesystemConfigBuilder::new()
        .data_dir(temp_dir.path().to_string_lossy().to_string())
        .logging(LogConfig {
            enabled: false, // Disable logging for benchmarks
            file_path: log_dir
                .path()
                .join("test.log")
                .to_string_lossy()
                .to_string(),
            level: "info".to_string(),
            max_size: 1024 * 1024,
            rotation_count: 3,
        })
        .build()
        .unwrap();

    let fs = Zthfs::new(&config).unwrap();
    (fs, temp_dir)
}

fn bench_file_read_1kb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_read_1kb.txt");
    let test_data = vec![0u8; 1024]; // 1KB of data

    // Write test data first
    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("file_read_1kb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::read_file(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
            );
        })
    });
}

fn bench_file_write_1kb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_write_1kb.txt");
    let test_data = vec![0u8; 1024]; // 1KB of data

    c.bench_function("file_write_1kb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::write_file(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
                std::hint::black_box(&test_data),
            );
        })
    });
}

fn bench_file_read_1mb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_read_1mb.txt");
    let test_data = vec![0u8; 1024 * 1024]; // 1MB of data

    // Write test data first
    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("file_read_1mb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::read_file(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
            );
        })
    });
}

fn bench_file_write_1mb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_write_1mb.txt");
    let test_data = vec![0u8; 1024 * 1024]; // 1MB of data

    c.bench_function("file_write_1mb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::write_file(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
                std::hint::black_box(&test_data),
            );
        })
    });
}

fn bench_get_file_size_1kb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_size.txt");
    let test_data = vec![0u8; 1024]; // 1KB of data
    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("get_file_size_1kb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::get_file_size(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
            );
        })
    });
}

fn bench_get_file_size_10mb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_size.txt");
    let test_data = vec![0u8; 1024 * 1024 * 10]; // 10MB of data
    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("get_file_size_10mb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::get_file_size(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
            );
        })
    });
}

fn bench_path_exists_check(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_exists.txt");
    let test_data = b"test data".to_vec();
    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("path_exists_check", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::path_exists(
                std::hint::black_box(&fs),
                std::hint::black_box(test_path),
            );
        })
    });
}

fn bench_chunked_file_operations(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    // Test chunked file (8MB - will be split into chunks)
    let chunked_path = Path::new("/chunked_8mb.dat");
    let chunked_data = vec![0xAAu8; 8 * 1024 * 1024]; // 8MB

    // Write chunked file
    FileSystemOperations::write_file_chunked(&fs, chunked_path, &chunked_data).unwrap();

    c.bench_function("chunked_file_read_8mb", |b| {
        b.iter(|| {
            let _ = FileSystemOperations::read_file_chunked(
                std::hint::black_box(&fs),
                std::hint::black_box(chunked_path),
            );
        })
    });
}

fn bench_file_operations_by_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_operations_by_size");

    // Test different file sizes to see chunking behavior
    let sizes = vec![
        ("512b", 512),
        ("1kb", 1024),
        ("10kb", 10 * 1024),
        ("100kb", 100 * 1024),
        ("1mb", 1024 * 1024),
        ("2mb", 2 * 1024 * 1024),
        ("4mb_minus_1", 4 * 1024 * 1024 - 1), // Just under chunk threshold
        ("4mb", 4 * 1024 * 1024),             // Exactly at chunk threshold
        ("4mb_plus_1", 4 * 1024 * 1024 + 1),  // Just over chunk threshold
        ("8mb", 8 * 1024 * 1024),
    ];

    // Read and size benchmarks
    for &(label, size) in &sizes {
        // Create filesystem and file for each size
        let (fs, _temp_dir) = create_test_filesystem();
        let path_str = format!("/test_{label}.dat");
        let test_path = Path::new(&path_str);
        let test_data = vec![0x42u8; size];

        // Pre-write file for read benchmarks
        FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

        group.bench_function(format!("read_{label}"), |b| {
            b.iter(|| {
                let _ = FileSystemOperations::read_file(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                );
            })
        });

        group.bench_function(format!("get_size_{label}"), |b| {
            b.iter(|| {
                let _ = FileSystemOperations::get_file_size(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                );
            })
        });
    }

    // Separate write benchmarks (don't reuse the same filesystem instance)
    for &(label, size) in &sizes {
        let (fs, _temp_dir) = create_test_filesystem();
        let path_str = format!("/write_test_{label}.dat");
        let test_path = Path::new(&path_str);
        let test_data = vec![0x42u8; size];

        group.bench_function(format!("write_{label}"), |b| {
            b.iter(|| {
                let _ = FileSystemOperations::write_file(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                    std::hint::black_box(&test_data),
                );
            })
        });
    }

    group.finish();
}

fn bench_partial_reads(c: &mut Criterion) {
    let mut group = c.benchmark_group("partial_reads");

    // Create a large file for partial read testing
    let (fs, _temp_dir) = create_test_filesystem();
    let test_path = Path::new("/partial_read_test.dat");
    let file_size = 8 * 1024 * 1024; // 8MB file (reduced for better performance)
    let test_data = (0..file_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

    FileSystemOperations::write_file(&fs, test_path, &test_data).unwrap();

    // Test different partial read sizes and offsets
    let partial_tests = vec![
        ("start_4kb", 0, 4096),                                   // Beginning, 4KB
        ("middle_4kb", file_size / 2, 4096),                      // Middle, 4KB
        ("end_4kb", file_size - 4096, 4096),                      // End, 4KB
        ("start_64kb", 0, 65536),                                 // Beginning, 64KB
        ("cross_chunk_64kb", 4 * 1024 * 1024 - 32 * 1024, 65536), // Cross chunk boundary
    ];

    for (label, offset, size) in partial_tests {
        group.bench_function(format!("partial_read_{label}"), |b| {
            b.iter(|| {
                let _ = FileSystemOperations::read_partial_chunked(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                    std::hint::black_box(offset as i64),
                    std::hint::black_box(size as u32),
                );
            })
        });
    }

    group.finish();
}

fn bench_directory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("directory_operations");
    let (fs, _temp_dir) = create_test_filesystem();

    // Create test directory structure
    let base_dir = Path::new("/bench_test_dir");
    FileSystemOperations::create_directory(&fs, base_dir, 0o755).unwrap();

    // Create multiple files in directory for listing tests
    for i in 0..10 {
        let file_path = base_dir.join(format!("file_{i}.txt"));
        let data = format!("Test data for file {i}").into_bytes();
        FileSystemOperations::write_file(&fs, &file_path, &data).unwrap();
    }

    group.bench_function("read_directory", |b| {
        b.iter(|| {
            // Note: read_dir requires a ReplyDirectory, so we'll just test get_dir_entry_count
            let _ = FileSystemOperations::get_dir_entry_count(
                std::hint::black_box(&fs),
                std::hint::black_box(base_dir),
            );
        })
    });

    group.bench_function("create_directory", |b| {
        b.iter(|| {
            let dir_path = Path::new("/temp_dir");
            let _ = FileSystemOperations::create_directory(
                std::hint::black_box(&fs),
                std::hint::black_box(dir_path),
                std::hint::black_box(0o755),
            );
        })
    });

    group.finish();
}

fn bench_file_metadata_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_operations");
    let (fs, _temp_dir) = create_test_filesystem();

    // Create test files of different sizes
    let test_files = vec![
        ("small", 1024),            // 1KB
        ("medium", 1024 * 1024),    // 1MB
        ("large", 8 * 1024 * 1024), // 8MB - chunked
    ];

    for (label, size) in test_files {
        let path_str = format!("/metadata_test_{label}.dat");
        let file_path = Path::new(&path_str);
        let data = vec![0x55u8; size];
        FileSystemOperations::write_file(&fs, file_path, &data).unwrap();

        group.bench_function(format!("get_attr_{label}"), |b| {
            b.iter(|| {
                let _ = FileSystemOperations::get_attr(
                    std::hint::black_box(&fs),
                    std::hint::black_box(file_path),
                );
            })
        });
    }

    group.finish();
}

fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");
    let fs = std::sync::Arc::new(create_test_filesystem().0);

    group.bench_function("concurrent_reads", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    let fs_clone = std::sync::Arc::clone(&fs);
                    std::thread::spawn(move || {
                        let path_str = format!("/concurrent_test_{i}.txt");
                        let path = Path::new(&path_str);
                        let data = format!("Data {i}").into_bytes();

                        // Create file first
                        let _ = FileSystemOperations::write_file(&fs_clone, path, &data);

                        // Then read it multiple times
                        for _ in 0..10 {
                            let _ = FileSystemOperations::read_file(&fs_clone, path);
                        }
                    })
                })
                .collect();

            for handle in handles {
                let _ = handle.join();
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_file_read_1kb,
    bench_file_write_1kb,
    bench_file_read_1mb,
    bench_file_write_1mb,
    bench_get_file_size_1kb,
    bench_get_file_size_10mb,
    bench_path_exists_check,
    bench_chunked_file_operations,
    bench_file_operations_by_size,
    bench_partial_reads,
    bench_directory_operations,
    bench_file_metadata_operations,
    bench_concurrent_operations
);

criterion_main!(benches);
