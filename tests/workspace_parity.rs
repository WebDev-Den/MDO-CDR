use defender_core::policy_schema::{PolicyDocumentV1, VersionedPolicyDocument, migrate_to_latest};
use defender_ffi::{FileKind, Stage, Verdict};
use defender_handlers_media::{HandlerKind, ProbeDecision};
use defender_signatures::{SignatureEngine, SignatureRule};

#[test]
fn workspace_crates_are_wired() {
    let engine =
        SignatureEngine::from_rules(vec![SignatureRule::anywhere("needle", b"needle".to_vec())]);
    let hits = engine.scan(b"abcneedlexyz");
    assert_eq!(hits.len(), 1);

    let doc = VersionedPolicyDocument::V1(PolicyDocumentV1 {
        profile: "staging".to_string(),
        max_input_size_bytes: 1,
        max_output_size_bytes: 1,
        max_output_expansion_ratio: 1.0,
        blocked_extensions: vec!["exe".to_string()],
    });
    let migrated = migrate_to_latest(doc);
    assert!(migrated.validate().is_ok());

    assert_eq!(Verdict::Blocked as i32, 2);
    assert_eq!(FileKind::Audio as i32, 3);
    assert_eq!(Stage::AudioProbe as i32, 4);
    assert_eq!(HandlerKind::Audio as u8, 3);
    assert_eq!(ProbeDecision::Blocked as u8, 2);
}
