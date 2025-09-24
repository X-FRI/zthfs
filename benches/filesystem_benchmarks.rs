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

criterion_group!(
    benches,
    bench_file_read_1kb,
    bench_file_write_1kb,
    bench_file_read_1mb,
    bench_file_write_1mb,
    bench_get_file_size_1kb,
    bench_get_file_size_10mb,
    bench_path_exists_check
);

criterion_main!(benches);
