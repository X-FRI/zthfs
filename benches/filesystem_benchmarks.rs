use criterion::{Criterion, criterion_group, criterion_main};
use std::path::Path;
use tempfile::tempdir;
use zthfs::{
    config::{FilesystemConfigBuilder, LogConfig},
    fs_impl::{Zthfs, attr_ops, chunk_ops, dir_modify, dir_read, file_read, file_write, path_ops},
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
    file_write::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("file_read_1kb", |b| {
        b.iter(|| {
            let _ =
                file_read::read_file(std::hint::black_box(&fs), std::hint::black_box(test_path));
        })
    });
}

fn bench_file_write_1kb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_write_1kb.txt");
    let test_data = vec![0u8; 1024]; // 1KB of data

    c.bench_function("file_write_1kb", |b| {
        b.iter(|| {
            let _ = file_write::write_file(
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
    file_write::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("file_read_1mb", |b| {
        b.iter(|| {
            let _ =
                file_read::read_file(std::hint::black_box(&fs), std::hint::black_box(test_path));
        })
    });
}

fn bench_file_write_1mb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_write_1mb.txt");
    let test_data = vec![0u8; 1024 * 1024]; // 1MB of data

    c.bench_function("file_write_1mb", |b| {
        b.iter(|| {
            let _ = file_write::write_file(
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
    file_write::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("get_file_size_1kb", |b| {
        b.iter(|| {
            let _ =
                path_ops::get_file_size(std::hint::black_box(&fs), std::hint::black_box(test_path));
        })
    });
}

fn bench_get_file_size_10mb(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_size.txt");
    let test_data = vec![0u8; 1024 * 1024 * 10]; // 10MB of data
    file_write::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("get_file_size_10mb", |b| {
        b.iter(|| {
            let _ =
                path_ops::get_file_size(std::hint::black_box(&fs), std::hint::black_box(test_path));
        })
    });
}

fn bench_path_exists_check(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    let test_path = Path::new("/test_exists.txt");
    let test_data = b"test data".to_vec();
    file_write::write_file(&fs, test_path, &test_data).unwrap();

    c.bench_function("path_exists_check", |b| {
        b.iter(|| {
            let _ =
                path_ops::path_exists(std::hint::black_box(&fs), std::hint::black_box(test_path));
        })
    });
}

fn bench_chunked_file_operations(c: &mut Criterion) {
    let (fs, _temp_dir) = create_test_filesystem();

    // Test chunked file (8MB - will be split into chunks)
    let chunked_path = Path::new("/chunked_8mb.dat");
    let chunked_data = vec![0xAAu8; 8 * 1024 * 1024]; // 8MB

    // Write chunked file
    chunk_ops::write_file_chunked(&fs, chunked_path, &chunked_data).unwrap();

    c.bench_function("chunked_file_read_8mb", |b| {
        b.iter(|| {
            let _ = chunk_ops::read_file_chunked(
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
        file_write::write_file(&fs, test_path, &test_data).unwrap();

        group.bench_function(format!("read_{label}"), |b| {
            b.iter(|| {
                let _ = file_read::read_file(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                );
            })
        });

        group.bench_function(format!("get_size_{label}"), |b| {
            b.iter(|| {
                let _ = path_ops::get_file_size(
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
                let _ = file_write::write_file(
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

    // Create a large chunked file for partial read testing
    let (fs, _temp_dir) = create_test_filesystem();
    let test_path = Path::new("/partial_read_test.dat");
    let chunk_size = 4 * 1024 * 1024; // 4MB chunks
    let file_size = chunk_size * 3 + 1024 * 1024; // 13MB file (will be chunked)
    let test_data = (0..file_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

    // Create chunked file
    chunk_ops::write_file_chunked(&fs, test_path, &test_data).unwrap();

    // Test different partial read sizes and offsets
    let partial_tests = vec![
        ("start_4kb", 0, 4096),                                // Beginning, 4KB
        ("middle_4kb", file_size / 2, 4096),                   // Middle, 4KB
        ("end_4kb", file_size - 4096, 4096),                   // End, 4KB
        ("start_64kb", 0, 65536),                              // Beginning, 64KB
        ("cross_chunk_64kb", chunk_size - 32 * 1024, 65536),   // Cross chunk boundary
        ("cross_chunk_128kb", chunk_size - 64 * 1024, 131072), // Cross chunk boundary, larger
        ("multi_chunk_256kb", chunk_size - 64 * 1024, 262144), // Span multiple chunks
    ];

    for (label, offset, size) in partial_tests {
        group.bench_function(format!("chunked_partial_read_{label}"), |b| {
            b.iter(|| {
                let _ = file_read::read_partial_chunked(
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
    dir_modify::create_directory(&fs, base_dir, 0o755).unwrap();

    // Create multiple files in directory for listing tests
    for i in 0..10 {
        let file_path = base_dir.join(format!("file_{i}.txt"));
        let data = format!("Test data for file {i}").into_bytes();
        file_write::write_file(&fs, &file_path, &data).unwrap();
    }

    group.bench_function("read_directory", |b| {
        b.iter(|| {
            // Note: read_dir requires a ReplyDirectory, so we'll just test get_dir_entry_count
            let _ = dir_read::get_dir_entry_count(
                std::hint::black_box(&fs),
                std::hint::black_box(base_dir),
            );
        })
    });

    group.bench_function("create_directory", |b| {
        b.iter(|| {
            let dir_path = Path::new("/temp_dir");
            let _ = dir_modify::create_directory(
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
        file_write::write_file(&fs, file_path, &data).unwrap();

        group.bench_function(format!("get_attr_{label}"), |b| {
            b.iter(|| {
                let _ =
                    attr_ops::get_attr(std::hint::black_box(&fs), std::hint::black_box(file_path));
            })
        });
    }

    group.finish();
}

fn bench_partial_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("partial_writes");

    // Test partial writes on chunked files
    let (fs, _temp_dir) = create_test_filesystem();
    let chunk_size = 4 * 1024 * 1024; // 4MB chunks
    let file_size = chunk_size * 3 + 1024 * 1024; // 13MB file (will be chunked)
    let test_data = (0..file_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();
    let chunked_path = Path::new("/chunked_partial_write_test.dat");

    // Create chunked file
    chunk_ops::write_file_chunked(&fs, chunked_path, &test_data).unwrap();

    // Test partial writes on chunked file
    let chunked_partial_tests = vec![
        ("chunk_start", 0, "MODIFIED_START".as_bytes()),
        ("chunk_middle", chunk_size / 2, "MODIFIED_MIDDLE".as_bytes()),
        (
            "chunk_cross_boundary",
            chunk_size - 5,
            "CROSS_BOUNDARY".as_bytes(),
        ),
        (
            "chunk_second_chunk",
            chunk_size + 1000,
            "SECOND_CHUNK".as_bytes(),
        ),
        (
            "chunk_extend_file",
            file_size + 100,
            "EXTEND_FILE".as_bytes(),
        ),
    ];

    for (label, offset, data) in chunked_partial_tests {
        let data_clone = data.to_vec();
        group.bench_function(format!("chunked_partial_write_{label}"), |b| {
            b.iter(|| {
                let _ = file_write::write_partial(
                    std::hint::black_box(&fs),
                    std::hint::black_box(chunked_path),
                    std::hint::black_box(offset),
                    std::hint::black_box(&data_clone),
                );
            })
        });
    }

    // Test partial writes on regular files (< chunk size)
    let regular_path = Path::new("/regular_partial_write_test.txt");
    let small_data = b"Small file content for partial write testing. This is a regular file that won't be chunked.";
    file_write::write_file(&fs, regular_path, small_data).unwrap();

    let regular_partial_tests = vec![
        ("regular_start", 0, "START_".as_bytes()),
        ("regular_middle", 10, "MIDDLE_".as_bytes()),
        ("regular_end", small_data.len() as i64, "_END".as_bytes()),
        ("regular_overwrite", 5, "OVERWRITE".as_bytes()),
    ];

    for (label, offset, data) in regular_partial_tests {
        let data_clone = data.to_vec();
        group.bench_function(format!("regular_partial_write_{label}"), |b| {
            b.iter(|| {
                let _ = file_write::write_partial(
                    std::hint::black_box(&fs),
                    std::hint::black_box(regular_path),
                    std::hint::black_box(offset),
                    std::hint::black_box(&data_clone),
                );
            })
        });
    }

    group.finish();
}

fn bench_chunking_performance_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunking_comparison");

    // Test file sizes around the chunking threshold
    let chunk_size = 4 * 1024 * 1024; // 4MB
    let test_sizes = vec![
        ("small_1mb", 1024 * 1024),      // 1MB - regular file
        ("medium_3mb", 3 * 1024 * 1024), // 3MB - regular file
        ("threshold_4mb", chunk_size),   // 4MB - at threshold
        ("large_5mb", 5 * 1024 * 1024),  // 5MB - chunked file
        ("xlarge_8mb", 8 * 1024 * 1024), // 8MB - chunked file
    ];

    for (label, size) in test_sizes {
        // Create filesystem and file for each size
        let (fs, _temp_dir) = create_test_filesystem();
        let path_str = format!("/chunking_test_{label}.dat");
        let test_path = Path::new(&path_str);
        let test_data = vec![0x42u8; size];

        // Full write benchmark
        group.bench_function(format!("write_full_{label}"), |b| {
            b.iter(|| {
                let _ = file_write::write_file(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                    std::hint::black_box(&test_data),
                );
            })
        });

        // Full read benchmark
        group.bench_function(format!("read_full_{label}"), |b| {
            b.iter(|| {
                let _ = file_read::read_file(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                );
            })
        });

        // Partial write benchmark (write 4KB in the middle)
        let partial_offset = (size / 2) as i64;
        let partial_data = vec![0xFFu8; 4096];
        group.bench_function(format!("write_partial_4kb_{label}"), |b| {
            b.iter(|| {
                let _ = file_write::write_partial(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                    std::hint::black_box(partial_offset),
                    std::hint::black_box(&partial_data),
                );
            })
        });
    }

    group.finish();
}

fn bench_chunked_file_operations_detailed(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunked_operations");

    let (fs, _temp_dir) = create_test_filesystem();
    let chunk_size = 4 * 1024 * 1024; // 4MB chunks

    // Test with different chunked file sizes
    let file_sizes = vec![
        ("2_chunks", chunk_size * 2), // 8MB - 2 chunks
        ("3_chunks", chunk_size * 3), // 12MB - 3 chunks
        ("5_chunks", chunk_size * 5), // 20MB - 5 chunks
    ];

    for (label, file_size) in file_sizes {
        let path_str = format!("/detailed_chunked_{label}.dat");
        let test_path = Path::new(&path_str);
        let test_data = (0..file_size).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

        // Create chunked file
        chunk_ops::write_file_chunked(&fs, test_path, &test_data).unwrap();

        // Benchmark chunked read
        group.bench_function(format!("chunked_read_{label}"), |b| {
            b.iter(|| {
                let _ = chunk_ops::read_file_chunked(
                    std::hint::black_box(&fs),
                    std::hint::black_box(test_path),
                );
            })
        });

        // Benchmark partial read in different chunks
        let chunk_positions = vec![
            ("first_chunk", 1000),
            ("second_chunk", chunk_size + 1000),
            ("last_chunk_start", file_size - chunk_size + 1000),
        ];

        for (pos_label, offset) in &chunk_positions {
            let bench_name = format!("chunked_partial_read_{}_{}_{}", label, pos_label, "64kb");
            group.bench_function(bench_name, |b| {
                b.iter(|| {
                    let _ = file_read::read_partial_chunked(
                        std::hint::black_box(&fs),
                        std::hint::black_box(test_path),
                        std::hint::black_box(*offset as i64),
                        std::hint::black_box(65536), // 64KB
                    );
                })
            });
        }

        // Benchmark partial write in different chunks
        let write_data = b"MODIFY_CHUNK_DATA";
        for (pos_label, offset) in &chunk_positions {
            let bench_name = format!("chunked_partial_write_{label}_{pos_label}");
            group.bench_function(bench_name, |b| {
                b.iter(|| {
                    let _ = file_write::write_partial(
                        std::hint::black_box(&fs),
                        std::hint::black_box(test_path),
                        std::hint::black_box(*offset as i64),
                        std::hint::black_box(write_data),
                    );
                })
            });
        }
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
                        let _ = file_write::write_file(&fs_clone, path, &data);

                        // Then read it multiple times
                        for _ in 0..10 {
                            let _ = file_read::read_file(&fs_clone, path);
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
    bench_partial_writes,
    bench_chunking_performance_comparison,
    bench_chunked_file_operations_detailed,
    bench_directory_operations,
    bench_file_metadata_operations,
    bench_concurrent_operations
);

criterion_main!(benches);
