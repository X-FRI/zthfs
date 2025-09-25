use criterion::{Criterion, criterion_group, criterion_main};
use tempfile::tempdir;
use zthfs::config::LogConfig;
use zthfs::core::logging::LogHandler;

fn bench_log_single_message(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("benchmark.log");

    let config = LogConfig {
        enabled: true,
        file_path: log_path.to_string_lossy().to_string(),
        level: "info".to_string(),
        max_size: 100 * 1024 * 1024, // 100MB
        rotation_count: 5,
    };

    let logger = LogHandler::new(&config).unwrap();

    c.bench_function("async_log_single_message", |b| {
        b.iter(|| {
            let _ = logger.log_access(
                std::hint::black_box("read"),
                std::hint::black_box("/test/file.txt"),
                1000,
                1000,
                std::hint::black_box("success"),
                None,
            );
        })
    });

    // Flush and shutdown
    let _ = logger.flush_all();
}

fn bench_log_batch_messages(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("benchmark_batch.log");

    let config = LogConfig {
        enabled: true,
        file_path: log_path.to_string_lossy().to_string(),
        level: "info".to_string(),
        max_size: 100 * 1024 * 1024, // 100MB
        rotation_count: 5,
    };

    let logger = LogHandler::new(&config).unwrap();

    c.bench_function("async_log_batch_100_messages", |b| {
        b.iter(|| {
            for i in 0..100 {
                let path = format!("/test/file_{i}.txt");
                let _ = logger.log_access(
                    std::hint::black_box("read"),
                    std::hint::black_box(&path),
                    1000,
                    1000,
                    std::hint::black_box("success"),
                    None,
                );
            }
            // Flush after batch
            let _ = logger.flush_logs();
        })
    });

    // Final shutdown
    let _ = logger.flush_all();
}

fn bench_log_with_performance_data(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    let log_path = temp_dir.path().join("benchmark_perf.log");

    let config = LogConfig {
        enabled: true,
        file_path: log_path.to_string_lossy().to_string(),
        level: "debug".to_string(),
        max_size: 100 * 1024 * 1024, // 100MB
        rotation_count: 5,
    };

    let logger = LogHandler::new(&config).unwrap();

    c.bench_function("async_log_with_performance_data", |b| {
        b.iter(|| {
            let _ = logger.log_performance(zthfs::core::logging::PerformanceLogParams {
                operation: std::hint::black_box("encrypt".to_string()),
                path: std::hint::black_box("/test/large_file.dat".to_string()),
                uid: 1000,
                gid: 1000,
                duration_ms: 150,
                file_size: Some(1024 * 1024),
                checksum: Some("abc123".to_string()),
            });
        })
    });

    // Flush and shutdown
    let _ = logger.flush_all();
}

criterion_group!(
    benches,
    bench_log_single_message,
    bench_log_batch_messages,
    bench_log_with_performance_data
);
criterion_main!(benches);
