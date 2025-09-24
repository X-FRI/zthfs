use criterion::{Criterion, criterion_group, criterion_main};
use zthfs::core::integrity::IntegrityHandler;

fn bench_checksum_computation_1kb(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB of data

    c.bench_function("checksum_computation_1kb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::compute_checksum(std::hint::black_box(&data));
        })
    });
}

fn bench_checksum_computation_1mb(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1MB of data

    c.bench_function("checksum_computation_1mb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::compute_checksum(std::hint::black_box(&data));
        })
    });
}

fn bench_integrity_verification_1kb(c: &mut Criterion) {
    let data = vec![0u8; 1024]; // 1KB of data
    let checksum = IntegrityHandler::compute_checksum(&data);

    c.bench_function("integrity_verification_1kb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::verify_integrity(
                std::hint::black_box(&data),
                std::hint::black_box(checksum),
            );
        })
    });
}

fn bench_integrity_verification_1mb(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let checksum = IntegrityHandler::compute_checksum(&data);

    c.bench_function("integrity_verification_1mb", |b| {
        b.iter(|| {
            let _ = IntegrityHandler::verify_integrity(
                std::hint::black_box(&data),
                std::hint::black_box(checksum),
            );
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
