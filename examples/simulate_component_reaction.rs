use file_defender::{
    DefenseContext, DefenseVerdict, FileDefender, SignatureRule,
    policy::{DefensePolicy, OtherPolicy, ProbeFailureMode},
};

fn main() {
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
    let cases = simulated_cases();

    println!("file_defender simulation start");
    for (name, file_name, bytes) in cases {
        let result = defender.defend_bytes(
            bytes,
            Some(file_name.to_string()),
            DefenseContext::default(),
        );

        match result {
            Ok(value) => {
                let verdict = match value.verdict {
                    DefenseVerdict::Clean => "clean",
                    DefenseVerdict::Suspicious => "suspicious",
                    DefenseVerdict::Blocked => "blocked",
                };
                println!("[{name}] verdict={verdict} alerts={}", value.alerts.len());
                for alert in value.alerts {
                    println!(
                        "  - code={} severity={:?} message={}",
                        alert.code, alert.severity, alert.message
                    );
                }
            }
            Err(err) => {
                println!("[{name}] error={err}");
            }
        }
    }
    println!("file_defender simulation end");
}

fn simulated_cases() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let mut high_entropy = Vec::new();
    let start = 0u16;
    let end = 2048u16;
    for value in start..end {
        high_entropy.push((value % 256) as u8);
    }

    let clean_gif = vec![
        71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 255, 255, 255, 0, 0, 0, 33, 249, 4, 1, 0, 0,
        1, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
    ];

    vec![
        ("clean_gif", "clean.gif", clean_gif),
        (
            "signature_trigger",
            "note.txt",
            b"safe EICAR-STANDARD-ANTIVIRUS-TEST-FILE content".to_vec(),
        ),
        ("blocked_extension", "payload.exe", b"not-exe".to_vec()),
        (
            "kind_mismatch_png_named_mp4",
            "movie.mp4",
            vec![137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0],
        ),
        ("high_entropy", "blob.bin", high_entropy),
    ]
}
