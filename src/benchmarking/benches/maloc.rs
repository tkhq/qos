extern crate criterion;
use criterion::{criterion_group, criterion_main, Criterion};

fn memory_allocation_benchmark(c: &mut Criterion) {
    c.bench_function("vec_allocation", |b| {
        b.iter(|| {
            let mut v = Vec::with_capacity(1000);
            for i in 0..1000 {
                v.push(i);
            }
        })
    });
}

criterion_group!(benches, memory_allocation_benchmark);
criterion_main!(benches);
