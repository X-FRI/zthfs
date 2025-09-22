use criterion::{Criterion, black_box, criterion_group, criterion_main};
use zthfs::{config::EncryptionConfig, core::encryption::EncryptionHandler};

fn bench_encrypt_1kb(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let data = vec![0u8; 1024]; // 1KB of data
    let path = "/test/file.txt";

    c.bench_function("encrypt_1kb", |b| {
        b.iter(|| {
            let _ = encryptor.encrypt(black_box(&data), black_box(path));
        })
    });
}

fn bench_decrypt_1kb(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let data = vec![0u8; 1024]; // 1KB of data
    let path = "/test/file.txt";

    let encrypted = encryptor.encrypt(&data, path).unwrap();

    c.bench_function("decrypt_1kb", |b| {
        b.iter(|| {
            let _ = encryptor.decrypt(black_box(&encrypted), black_box(path));
        })
    });
}

fn bench_encrypt_1mb(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let path = "/test/large_file.txt";

    c.bench_function("encrypt_1mb", |b| {
        b.iter(|| {
            let _ = encryptor.encrypt(black_box(&data), black_box(path));
        })
    });
}

fn bench_decrypt_1mb(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let data = vec![0u8; 1024 * 1024]; // 1MB of data
    let path = "/test/large_file.txt";

    let encrypted = encryptor.encrypt(&data, path).unwrap();

    c.bench_function("decrypt_1mb", |b| {
        b.iter(|| {
            let _ = encryptor.decrypt(black_box(&encrypted), black_box(path));
        })
    });
}

fn bench_nonce_generation(c: &mut Criterion) {
    let config = EncryptionConfig::default();
    let encryptor = EncryptionHandler::new(&config);

    let path = "/test/file.txt";

    c.bench_function("nonce_generation", |b| {
        b.iter(|| {
            let _ = encryptor.generate_nonce(black_box(path));
        })
    });
}

criterion_group!(
    benches,
    bench_encrypt_1kb,
    bench_decrypt_1kb,
    bench_encrypt_1mb,
    bench_decrypt_1mb,
    bench_nonce_generation
);

criterion_main!(benches);
