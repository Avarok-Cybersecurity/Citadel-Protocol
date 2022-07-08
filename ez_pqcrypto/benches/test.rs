use criterion::{criterion_group, criterion_main, Criterion};
use ez_pqcrypto::replay_attack_container::unordered::AntiReplayAttackContainer;

const COUNT: u64 = ez_pqcrypto::replay_attack_container::unordered::HISTORY_LEN * 4;

fn default_routine() {
    let ara = AntiReplayAttackContainer::default();
    for x in 0..COUNT {
        assert!(ara.on_pid_received(x));
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("default", |b| b.iter(default_routine));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
