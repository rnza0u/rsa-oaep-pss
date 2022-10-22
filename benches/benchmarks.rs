use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use rsa_oaep_pss::generate_rsa_keys;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("2048 bits", |b| {
        b.iter(|| generate_rsa_keys(&mut OsRng, black_box(2048)))
    });
    c.bench_function("3072 bits", |b| {
        b.iter(|| generate_rsa_keys(&mut OsRng, black_box(3072)))
    });
    c.bench_function("4096 bits", |b| {
        b.iter(|| generate_rsa_keys(&mut OsRng, black_box(4096)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
