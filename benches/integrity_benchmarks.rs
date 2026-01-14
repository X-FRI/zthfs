use criterion::{Criterion, criterion_group, criterion_main};
use zthfs::core::integrity::IntegrityHandler;

fn bench_checksum_computation_1kb(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB of data
    let key = vec![0u8; 32]; // 32-byte key for BLAKE3

    c.bench_function("checksum_computation_1kb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::compute_checksum(
                std::hint::black_box(&data),
                std::hint::black_box("blake3"),
                std::hint::black_box(&key),
            )
            .unwrap();
        })
    });
}

fn bench_checksum_computation_1mb(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let key = vec![0u8; 32]; // 32-byte key for BLAKE3

    c.bench_function("checksum_computation_1mb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::compute_checksum(
                std::hint::black_box(&data),
                std::hint::black_box("blake3"),
                std::hint::black_box(&key),
            )
            .unwrap();
        })
    });
}

fn bench_integrity_verification_1kb(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB of data
    let key = vec![0u8; 32]; // 32-byte key for BLAKE3
    let checksum = IntegrityHandler::compute_checksum(&data, "blake3", &key).unwrap();

    c.bench_function("integrity_verification_1kb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::verify_integrity(
                std::hint::black_box(&data),
                std::hint::black_box(&checksum),
                std::hint::black_box("blake3"),
                std::hint::black_box(&key),
            )
            .unwrap();
        })
    });
}

fn bench_integrity_verification_1mb(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let key = vec![0u8; 32]; // 32-byte key for BLAKE3
    let checksum = IntegrityHandler::compute_checksum(&data, "blake3", &key).unwrap();

    c.bench_function("integrity_verification_1mb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::verify_integrity(
                std::hint::black_box(&data),
                std::hint::black_box(&checksum),
                std::hint::black_box("blake3"),
                std::hint::black_box(&key),
            )
            .unwrap();
        })
    });
}

criterion_group!(
    benches,
    bench_checksum_computation_1kb,
    bench_checksum_computation_1mb,
    bench_integrity_verification_1kb,
    bench_integrity_verification_1mb
);

criterion_main!(benches);
