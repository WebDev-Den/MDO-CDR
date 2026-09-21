use criterion::{Criterion, criterion_group, criterion_main};
use file_defender::{DefenseContext, FileDefender, policy::DefensePolicy};

fn benchmark_defend_bytes(c: &mut Criterion) {
    let defender = FileDefender::new(DefensePolicy::default());
    let bytes = b"benchmark payload for defender".to_vec();
    c.bench_function("defend_bytes_small_payload", |b| {
        b.iter(|| {
            let _ = defender
                .defend_bytes(
                    bytes.clone(),
                    Some("sample.txt".to_string()),
                    DefenseContext::default(),
                )
                .ok();
        })
    });
}

criterion_group!(benches, benchmark_defend_bytes);
criterion_main!(benches);
