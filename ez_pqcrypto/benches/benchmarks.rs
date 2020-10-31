#[macro_use]
extern crate criterion;

use criterion::{Criterion, ParameterizedBenchmark, Benchmark};

fn criterion_benchmark(c: &mut Criterion) {
    
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);