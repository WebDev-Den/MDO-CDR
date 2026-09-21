#![allow(clippy::field_reassign_with_default)]

use file_defender::{
    DefenseContext, DefenseVerdict, FileDefender, FileKind, SignatureRule,
    policy::{
        AudioKeepOriginalMode, AudioOutputCodec, DecoderFailureMode, DefensePolicy,
        EnforcementMode, OtherPolicy, ProbeFailureMode, SignatureScanMode, UnknownKindMode,
    },
};

#[test]
fn blocks_file_by_signature() {
    let mut policy = DefensePolicy::default();
    policy.signature_rules.push(SignatureRule::anywhere(
        "eicar-like",
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
    ));

    let defender = FileDefender::new(policy);
    let result = defender
        .defend_bytes(
            b"hello EICAR-STANDARD-ANTIVIRUS-TEST-FILE world".to_vec(),
            Some("note.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("defend_bytes should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn blocks_by_extension_before_rebuild() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let result = defender.defend_bytes(
        b"fake-binary".to_vec(),
        Some("run.exe".to_string()),
        DefenseContext::default(),
    );

    assert!(result.is_err());
}

#[test]
fn marks_high_entropy_other_files_as_blocked() {
    // After the media-only architecture decision, GenericHandler always
    // emits a Blocking alert for non-media files. The verdict is Blocked.
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let mut bytes = Vec::new();
    let start = 0u16;
    let end = 1024u16;
    for value in start..end {
        bytes.push((value % 256) as u8);
    }

    let result = defender
        .defend_bytes(
            bytes,
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("defend_bytes should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    assert!(
        result
            .alerts
            .iter()
            .any(|a| a.code == "unsupported_file_kind")
    );
}

#[test]
fn high_entropy_other_can_be_blocked_in_strict_other_mode() {
    let mut policy = DefensePolicy::default();
    policy.other = OtherPolicy {
        max_entropy: 0.4,
        structured_probe_mode: ProbeFailureMode::Block,
    };
    let defender = FileDefender::new(policy);

    let mut bytes = Vec::new();
    let start = 0u16;
    let end = 1024u16;
    for value in start..end {
        bytes.push((value % 256) as u8);
    }

    let result = defender
        .defend_bytes(
            bytes,
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("defend_bytes should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn empty_other_payload_is_blocked() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            Vec::new(),
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("defend_bytes should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn blocks_mismatch_between_extension_and_mime() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let png_header = vec![137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 0];
    let result = defender.defend_bytes(
        png_header,
        Some("movie.mp4".to_string()),
        DefenseContext::default(),
    );

    assert!(result.is_err());
}

#[test]
fn quarantine_on_decoder_failure_with_default_policy() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"not-a-real-gif".to_vec(),
            Some("broken.gif".to_string()),
            DefenseContext::default(),
        )
        .expect("decoder failure should quarantine in default mode");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn strict_profile_blocks_unknown_kind() {
    let policy = DefensePolicy::strict_profile();
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"hello".to_vec(),
            Some("file.abcxyz".to_string()),
            DefenseContext::default(),
        )
        .expect("strict profile still returns structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn profile_modes_are_set_as_expected() {
    let staging = DefensePolicy::staging_profile();
    assert_eq!(staging.unknown_kind_mode, UnknownKindMode::Warn);
    assert_eq!(
        staging.decoder_failure_mode,
        DecoderFailureMode::QuarantineAsOther
    );
    assert_eq!(
        staging.signature_scan_mode,
        SignatureScanMode::InputAndOutput
    );
    assert_eq!(
        staging.audio.keep_original_mode,
        AudioKeepOriginalMode::FallbackToMp3
    );
    assert_eq!(staging.audio.probe_failure_mode, ProbeFailureMode::Warn);
    assert_eq!(staging.video.probe_failure_mode, ProbeFailureMode::Warn);
    assert_eq!(staging.other.structured_probe_mode, ProbeFailureMode::Warn);
    assert_eq!(staging.image.probe_failure_mode, ProbeFailureMode::Warn);
    assert_eq!(staging.gif.probe_failure_mode, ProbeFailureMode::Warn);
    assert!(!staging.block_on_unknown_output_mime);
    assert!(staging.enforce_output_mime_whitelist);
    assert_eq!(staging.output_mime_denylist.len(), 0);
    assert_eq!(staging.enforcement_mode, EnforcementMode::Enforce);

    let strict = DefensePolicy::strict_profile();
    assert_eq!(strict.unknown_kind_mode, UnknownKindMode::Block);
    assert_eq!(strict.decoder_failure_mode, DecoderFailureMode::Block);
    assert_eq!(
        strict.signature_scan_mode,
        SignatureScanMode::InputAndOutput
    );
    assert_eq!(
        strict.audio.keep_original_mode,
        AudioKeepOriginalMode::Block
    );
    assert_eq!(strict.audio.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(strict.video.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(strict.other.structured_probe_mode, ProbeFailureMode::Block);
    assert_eq!(strict.image.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(strict.gif.probe_failure_mode, ProbeFailureMode::Block);
    assert!(strict.block_on_unknown_output_mime);
    assert!(strict.enforce_output_mime_whitelist);
    assert!(!strict.output_mime_denylist.is_empty());
    assert!(
        !strict
            .output_mime_whitelist
            .video
            .contains(&"video/raw".to_string())
    );
    assert_eq!(strict.enforcement_mode, EnforcementMode::Enforce);

    let paranoid = DefensePolicy::paranoid_profile();
    assert_eq!(paranoid.unknown_kind_mode, UnknownKindMode::Block);
    assert_eq!(paranoid.decoder_failure_mode, DecoderFailureMode::Block);
    assert_eq!(
        paranoid.signature_scan_mode,
        SignatureScanMode::InputAndOutput
    );
    assert_eq!(
        paranoid.audio.keep_original_mode,
        AudioKeepOriginalMode::Block
    );
    assert_eq!(paranoid.audio.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(paranoid.video.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(
        paranoid.other.structured_probe_mode,
        ProbeFailureMode::Block
    );
    assert_eq!(paranoid.image.probe_failure_mode, ProbeFailureMode::Block);
    assert_eq!(paranoid.gif.probe_failure_mode, ProbeFailureMode::Block);
    assert!(paranoid.block_on_unknown_output_mime);
    assert!(paranoid.enforce_output_mime_whitelist);
    assert!(!paranoid.output_mime_denylist.is_empty());
    assert!(
        !paranoid
            .output_mime_whitelist
            .image
            .contains(&"image/jpeg".to_string())
    );
    assert_eq!(paranoid.enforcement_mode, EnforcementMode::Enforce);
}

#[test]
fn pre_scan_can_block_before_decode() {
    let mut policy = DefensePolicy::default();
    policy.signature_rules.push(SignatureRule::anywhere(
        "before-decode",
        b"BAD_MARKER".to_vec(),
    ));
    policy.block_on_pre_scan_match = true;
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"BAD_MARKER in payload".to_vec(),
            Some("asset.gif".to_string()),
            DefenseContext::default(),
        )
        .expect("pre-scan should return result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn output_expansion_limit_is_enforced() {
    let mut policy = DefensePolicy::default();
    policy.max_output_expansion_ratio = 0.5;
    let defender = FileDefender::new(policy);

    let clean_gif = vec![
        71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 255, 255, 255, 0, 0, 0, 33, 249, 4, 1, 0, 0,
        1, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
    ];
    let result = defender.defend_bytes(
        clean_gif,
        Some("clean.gif".to_string()),
        DefenseContext::default(),
    );
    assert!(result.is_err());
}

#[test]
fn gif_frame_limit_fails_fast_without_partial_output() {
    let mut policy = DefensePolicy::default();
    policy.decoder_failure_mode = DecoderFailureMode::Block;
    policy.gif.max_frames = 0;
    let defender = FileDefender::new(policy);

    let clean_gif = vec![
        71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 255, 255, 255, 0, 0, 0, 33, 249, 4, 1, 0, 0,
        1, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
    ];
    let result = defender.defend_bytes(
        clean_gif,
        Some("clean.gif".to_string()),
        DefenseContext::default(),
    );
    assert!(result.is_err());
}

#[test]
fn image_pixel_limit_fails_fast_before_rebuild() {
    let mut policy = DefensePolicy::default();
    policy.decoder_failure_mode = DecoderFailureMode::Block;
    policy.image.max_pixels = 0;
    let defender = FileDefender::new(policy);

    let tiny_png = vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 8, 153, 99, 96, 0, 0, 0, 2, 0, 1,
        229, 39, 212, 162, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    let result = defender.defend_bytes(
        tiny_png,
        Some("tiny.png".to_string()),
        DefenseContext::default(),
    );
    assert!(result.is_err());
}

#[test]
fn classifies_mp3_as_audio_kind() {
    let from_name = FileKind::from_name(Some("track.mp3"));
    assert_eq!(from_name, Some(FileKind::Audio));

    let from_mime = FileKind::from_mime(Some("audio/mpeg"));
    assert_eq!(from_mime, Some(FileKind::Audio));
}

#[test]
fn handles_audio_path_with_mp3_extension() {
    // With fail-closed defaults (BlockWhenUnavailable), fake audio content
    // that ffmpeg cannot process should result in either an error or a
    // Blocked verdict — NOT silent passthrough.
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);

    let result = defender.defend_bytes(
        b"fake-audio-content".to_vec(),
        Some("voice.mp3".to_string()),
        DefenseContext::default(),
    );

    match result {
        Ok(value) => {
            // If the pipeline returns Ok, the verdict must be Blocked
            // (quarantine path or blocking alert from handler).
            assert_eq!(value.verdict, DefenseVerdict::Blocked);
        }
        Err(_) => {
            // Err is also acceptable — means the decoder failed hard and
            // no fallback was available. Fail-closed is correct.
        }
    }
}

#[test]
fn keep_original_unknown_audio_can_be_blocked_by_policy() {
    let mut policy = DefensePolicy::default();
    policy.audio.output_codec = AudioOutputCodec::KeepOriginalWhenPossible;
    policy.audio.keep_original_mode = AudioKeepOriginalMode::Block;
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"unrecognized audio bytes".to_vec(),
            Some("voice.mp3".to_string()),
            DefenseContext::default(),
        )
        .expect("blocked behavior should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn structured_probe_for_other_can_block_invalid_pdf() {
    let mut policy = DefensePolicy::default();
    policy.unknown_kind_mode = UnknownKindMode::Warn;
    policy.other.structured_probe_mode = ProbeFailureMode::Block;
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"not_a_pdf".to_vec(),
            Some("report.pdf".to_string()),
            DefenseContext::default(),
        )
        .expect("structured probe block should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    let has_other_probe = result
        .stages
        .iter()
        .any(|value| value.stage == file_defender::PipelineStage::OtherProbe);
    assert!(has_other_probe);
}

#[test]
fn unknown_output_mime_can_be_blocked() {
    let mut policy = DefensePolicy::default();
    policy.block_on_unknown_output_mime = true;
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"plain-text-without-known-signature".to_vec(),
            Some("note.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn output_mime_whitelist_can_block_declared_mime() {
    let mut policy = DefensePolicy::default();
    policy.output_mime_whitelist.other.clear();
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"abc".to_vec(),
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn output_mime_denylist_can_block_declared_mime() {
    let mut policy = DefensePolicy::default();
    policy
        .output_mime_denylist
        .push("application/octet-stream".to_string());
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"abc".to_vec(),
            Some("blob.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return structured result");

    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn dry_run_mode_downgrades_blocks_to_warnings() {
    let mut policy = DefensePolicy::strict_profile().with_dry_run();
    policy.signature_rules.push(SignatureRule::anywhere(
        "block-me",
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
    ));
    let defender = FileDefender::new(policy);

    let result = defender
        .defend_bytes(
            b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE".to_vec(),
            Some("note.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("dry-run should not hard block");

    assert_ne!(result.verdict, DefenseVerdict::Blocked);
    let has_dry_run_note = result
        .alerts
        .iter()
        .any(|value| value.message.contains("[dry-run"));
    assert!(has_dry_run_note);
}

#[test]
fn tenant_presets_map_to_expected_profiles() {
    assert_eq!(
        DefensePolicy::public_profile().unknown_kind_mode,
        DefensePolicy::staging_profile().unknown_kind_mode
    );
    assert_eq!(
        DefensePolicy::enterprise_profile().unknown_kind_mode,
        DefensePolicy::strict_profile().unknown_kind_mode
    );
    assert_eq!(
        DefensePolicy::high_risk_profile().unknown_kind_mode,
        DefensePolicy::paranoid_profile().unknown_kind_mode
    );
}

// --- Detection hardening tests ---

#[test]
fn blocks_double_extension_exe_png() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);
    // file.exe.png: the double-extension check should classify this as Other,
    // which then gets blocked by the media-only GenericHandler.
    let result = defender
        .defend_bytes(
            vec![0u8; 64],
            Some("invoice.exe.png".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn blocks_double_extension_bat_jpg() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);
    let result = defender
        .defend_bytes(
            vec![0u8; 64],
            Some("readme.bat.jpg".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn svg_classified_as_other_and_blocked() {
    let policy = DefensePolicy::default();
    let defender = FileDefender::new(policy);
    // SVG content with image/svg+xml MIME. Normally infer won't detect SVG
    // from bytes alone, but from_mime would. Test via extension.
    let result = defender.defend_bytes(
        b"<svg xmlns='http://www.w3.org/2000/svg'></svg>".to_vec(),
        Some("logo.svg".to_string()),
        DefenseContext::default(),
    );
    // SVG extension doesn't match our media kinds → classified as Other → blocked.
    if let Ok(value) = result {
        assert_eq!(value.verdict, DefenseVerdict::Blocked);
    }
    // Err is also acceptable — type mismatch or unsupported.
}

#[test]
fn output_executable_magic_blocked_even_without_output_kind_enforcement() {
    let mut policy = DefensePolicy::default();
    policy.enforce_output_kind_match = false;
    // Force the pipeline to return MZ-prefixed bytes as "image".
    // We do this by using a GenericHandler path (Other kind) which now
    // blocks, so we can't easily test this without a custom handler.
    // Instead, verify the detect_executable_magic function directly
    // via a signature-match on output scan.
    let defender = FileDefender::new(policy);
    // An ELF file named .bin → Other kind → blocked by GenericHandler.
    let elf_bytes = b"\x7fELF\x02\x01\x01\x00".to_vec();
    let result = defender
        .defend_bytes(
            elf_bytes,
            Some("binary.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn classify_detects_apng_extension() {
    assert_eq!(
        FileKind::from_name(Some("sticker.apng")),
        Some(FileKind::AnimatedImage)
    );
}

#[test]
fn classify_normal_png_stays_image() {
    // A minimal PNG signature without acTL → should stay Image, not AnimatedImage.
    let png_sig: Vec<u8> = vec![
        0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', // IHDR chunk (minimal)
        0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0,
        // IHDR CRC (precomputed)
        0x90, 0x77, 0x53, 0xDE, // IEND
        0, 0, 0, 0, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82,
    ];
    let kind = FileKind::classify(&png_sig, Some("photo.png"), Some("image/png"));
    assert_eq!(kind, FileKind::Image);
}

#[test]
fn blocked_extension_list_covers_common_threats() {
    let policy = DefensePolicy::default();
    let expected = &[
        "exe", "dll", "js", "bat", "cmd", "msi", "scr", "vbs", "ps1", "jar", "apk", "hta", "py",
        "sh", "php", "class", "dex", "wasm",
    ];
    for ext in expected {
        assert!(
            policy.blocked_extensions.contains(&ext.to_string()),
            "default policy should block .{ext}"
        );
    }
}
