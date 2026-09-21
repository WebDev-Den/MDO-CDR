use mdo_cdr::{
    DefenseContext, DefenseVerdict, FileDefender, SignatureRule,
    policy::{DefensePolicy, OtherPolicy, ProbeFailureMode},
};

#[test]
fn simulation_pack_shows_component_reaction() {
    let mut policy = DefensePolicy::default();
    policy.signature_rules.push(SignatureRule::anywhere(
        "eicar-like",
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
    ));
    policy.other = OtherPolicy {
        max_entropy: 0.7,
        structured_probe_mode: ProbeFailureMode::Warn,
    };
    let defender = FileDefender::new(policy);

    // Minimal valid GIF89a (1×1, single frame) with delay=10cs (0.1s) to
    // avoid the delay-clamp warning that the hardened GIF handler now emits
    // for 0-delay frames.
    let clean_gif = vec![
        71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 255, 255, 255, 0, 0, 0, 33, 249, 4, 1, 10,
        0, 1, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
    ];
    let clean = defender
        .defend_bytes(
            clean_gif,
            Some("clean.gif".to_string()),
            DefenseContext::default(),
        )
        .expect("clean file should pass");
    assert_eq!(clean.verdict, DefenseVerdict::Clean);

    let signature = defender
        .defend_bytes(
            b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
            Some("note.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("signature case should return result");
    assert_eq!(signature.verdict, DefenseVerdict::Blocked);

    let blocked_extension = defender.defend_bytes(
        b"payload".to_vec(),
        Some("payload.exe".to_string()),
        DefenseContext::default(),
    );
    assert!(blocked_extension.is_err());

    let mismatch = defender.defend_bytes(
        vec![137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0],
        Some("movie.mp4".to_string()),
        DefenseContext::default(),
    );
    assert!(mismatch.is_err());

    let mut high_entropy = Vec::new();
    let start = 0u16;
    let end = 2048u16;
    for value in start..end {
        high_entropy.push((value % 256) as u8);
    }
    let high_entropy = defender
        .defend_bytes(
            high_entropy,
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("high entropy case should return result");
    // Media-only policy: GenericHandler now blocks all non-media files.
    assert_eq!(high_entropy.verdict, DefenseVerdict::Blocked);
}
