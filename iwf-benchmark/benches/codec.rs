//! Criterion micro-benchmarks for the Diameter codec hot path.
//!
//! Interpretation against the 100k TPS target: one transaction costs one
//! decode + one encode on the Diameter side. With N worker cores the codec
//! budget per message is `N / 100_000` seconds; these benches verify the
//! codec is orders of magnitude inside that (sub-microsecond per op on
//! commodity cores), leaving the budget to I/O and translation.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use iwf_benchmark::{sample_uar, sample_uar_wire};
use iwf_diameter::message::Message;

fn bench_decode(c: &mut Criterion) {
    let wire = sample_uar_wire();
    let mut group = c.benchmark_group("codec");
    group.throughput(Throughput::Elements(1));
    group.bench_function("decode_uar", |b| {
        b.iter(|| {
            let msg = Message::decode(std::hint::black_box(wire.clone())).expect("decode");
            std::hint::black_box(msg);
        })
    });
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let msg = sample_uar(1, 2);
    let mut group = c.benchmark_group("codec");
    group.throughput(Throughput::Elements(1));
    group.bench_function("encode_uar", |b| {
        b.iter(|| std::hint::black_box(std::hint::black_box(&msg).encode()))
    });
    group.finish();
}

fn bench_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec");
    group.throughput(Throughput::Elements(1));
    group.bench_function("encode_decode_uar", |b| {
        let msg = sample_uar(1, 2);
        b.iter(|| {
            let wire = std::hint::black_box(&msg).encode();
            std::hint::black_box(Message::decode(wire).expect("decode"));
        })
    });
    group.finish();
}

criterion_group!(benches, bench_decode, bench_encode, bench_round_trip);
criterion_main!(benches);
