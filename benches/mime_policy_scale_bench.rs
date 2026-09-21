use criterion::{Criterion, criterion_group, criterion_main};
use mdo_cdr::{DefenseContext, FileDefender, policy::DefensePolicy};

fn bench_mime_policy_lookups(c: &mut Criterion) {
    let mut policy_1k = DefensePolicy::default();
    for index in 0..1000 {
        policy_1k
            .output_mime_denylist
            .push(format!("application/x-custom-{index}"));
    }
    let defender_1k = FileDefender::new(policy_1k);

    let mut policy_10k = DefensePolicy::default();
    for index in 0..10000 {
        policy_10k
            .output_mime_denylist
            .push(format!("application/x-custom-{index}"));
    }
    let defender_10k = FileDefender::new(policy_10k);

    c.bench_function("mime_lookup_1k_rules", |b| {
        b.iter(|| {
            let _ = defender_1k
                .defend_bytes(
                    b"payload".to_vec(),
                    Some("blob.bin".to_string()),
                    DefenseContext::default(),
                )
                .ok();
        })
    });

    c.bench_function("mime_lookup_10k_rules", |b| {
        b.iter(|| {
            let _ = defender_10k
                .defend_bytes(
                    b"payload".to_vec(),
                    Some("blob.bin".to_string()),
                    DefenseContext::default(),
                )
                .ok();
        })
    });
}

criterion_group!(benches, bench_mime_policy_lookups);
criterion_main!(benches);
