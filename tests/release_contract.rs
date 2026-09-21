//! Regression tests for the public delivery boundary. Container-looking bytes
//! are deliberately not treated as proof of a playable media artifact.
use std::ffi::CString;
use std::io::{Cursor, Write};

use mdo_cdr::{
    DefenderError, DefenseContext, DefenseVerdict, FileDefender, PipelineStage,
    PipelineStageStatus, ffi,
    policy::{DefensePolicy, SignatureScanMode},
};

fn png() -> Vec<u8> {
    let mut bytes = Vec::new();
    image::DynamicImage::new_rgb8(3, 2)
        .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
        .unwrap();
    bytes
}

fn gif(delay: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut encoder = gif::Encoder::new(&mut bytes, 1, 1, &[0, 0, 0, 255, 255, 255]).unwrap();
        let frame = gif::Frame {
            width: 1,
            height: 1,
            delay,
            buffer: vec![0].into(),
            ..Default::default()
        };
        encoder.write_frame(&frame).unwrap();
    }
    bytes
}

fn apng(valid_pixels: bool) -> Vec<u8> {
    fn chunk(bytes: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
        bytes.extend_from_slice(kind);
        bytes.extend_from_slice(data);
        let mut crc = 0xffff_ffffu32;
        for byte in kind.iter().chain(data.iter()) {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
            }
        }
        bytes.extend_from_slice(&(!crc).to_be_bytes());
    }
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(
        &mut bytes,
        b"IHDR",
        &[0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0],
    );
    chunk(&mut bytes, b"acTL", &[0, 0, 0, 1, 0, 0, 0, 0]);
    let mut frame = vec![0; 26];
    frame[7] = 1;
    frame[11] = 1;
    frame[21] = 1;
    frame[23] = 10;
    chunk(&mut bytes, b"fcTL", &frame);
    let payload = if valid_pixels {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0, 255, 0, 0, 255]).unwrap();
        encoder.finish().unwrap()
    } else {
        b"invalid compressed pixels".to_vec()
    };
    chunk(&mut bytes, b"IDAT", &payload);
    chunk(&mut bytes, b"IEND", &[]);
    bytes
}

#[test]
fn clean_image_is_reread_then_released() {
    let result = FileDefender::new(DefensePolicy::default())
        .defend_bytes(
            png(),
            Some("image.png".into()),
            DefenseContext {
                declared_mime: Some("Image/PNG; charset=binary".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(result.can_release());
    assert!(image::load_from_memory(&result.artifact.output_bytes).is_ok());
    assert!(
        result
            .stages
            .iter()
            .any(|stage| stage.stage == PipelineStage::OutputValidation
                && stage.status == PipelineStageStatus::Success
                && stage.detail.starts_with("independent_read:"))
    );
}

#[test]
fn input_signature_block_never_returns_original_bytes() {
    let bytes = b"#!/bin/sh\necho secret".to_vec();
    let result = FileDefender::new(DefensePolicy::default())
        .defend_bytes(bytes, Some("note.txt".into()), DefenseContext::default())
        .unwrap();
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    assert!(!result.can_release());
    assert!(result.artifact.output_bytes.is_empty());
    assert_eq!(result.diagnostics.parser_used, "pre_scan_blocked");
}

#[test]
fn output_signature_block_never_returns_candidate_bytes() {
    let mut policy = DefensePolicy {
        signature_scan_mode: SignatureScanMode::OutputOnly,
        ..DefensePolicy::default()
    };
    policy
        .signature_rules
        .push(mdo_cdr::SignatureRule::anywhere(
            "PNG canary",
            b"IHDR".to_vec(),
        ));
    let result = FileDefender::new(policy)
        .defend_bytes(png(), Some("image.png".into()), DefenseContext::default())
        .unwrap();
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    assert!(result.artifact.output_bytes.is_empty());
    assert!(result.artifact.output_size > 0);
}

#[test]
fn suspicious_result_never_returns_candidate_bytes() {
    let result = FileDefender::new(DefensePolicy::default())
        .defend_bytes(
            gif(0),
            Some("animation.gif".into()),
            DefenseContext::default(),
        )
        .unwrap();
    assert_eq!(result.verdict, DefenseVerdict::Suspicious);
    assert!(!result.can_release());
    assert!(result.artifact.output_bytes.is_empty());
}

#[test]
fn rejected_path_does_not_create_or_replace_an_output() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("input.txt");
    let output = directory.path().join("output.txt");
    std::fs::write(&source, b"#!/bin/sh\necho rejected").unwrap();
    let defender = FileDefender::new(DefensePolicy::default());
    assert!(
        !defender
            .defend_path(&source, &output, DefenseContext::default())
            .unwrap()
            .can_release()
    );
    assert!(!output.exists());
    std::fs::write(&output, b"existing result").unwrap();
    defender
        .defend_path(&source, &output, DefenseContext::default())
        .unwrap();
    assert_eq!(std::fs::read(&output).unwrap(), b"existing result");
}

#[test]
fn clean_path_is_created_without_replacing_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("input.png");
    let output = directory.path().join("output.png");
    std::fs::write(&source, png()).unwrap();
    let defender = FileDefender::new(DefensePolicy::default());
    assert!(
        defender
            .defend_path(&source, &output, DefenseContext::default())
            .unwrap()
            .can_release()
    );
    let prior = std::fs::read(&output).unwrap();
    let error = defender
        .defend_path(&source, &output, DefenseContext::default())
        .unwrap_err();
    assert!(
        matches!(error, DefenderError::Io(ref error) if error.kind() == std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read(&output).unwrap(), prior);
}

#[test]
fn png_disguised_as_jpeg_is_rejected_even_within_the_image_family() {
    let result = FileDefender::new(DefensePolicy::default()).defend_bytes(
        png(),
        Some("photo.jpg".into()),
        DefenseContext::default(),
    );
    assert!(matches!(result, Err(DefenderError::FileTypeMismatch)));
}

#[test]
fn false_declared_mime_is_rejected() {
    let result = FileDefender::new(DefensePolicy::default()).defend_bytes(
        png(),
        Some("photo.png".into()),
        DefenseContext {
            declared_mime: Some("image/jpeg".into()),
            ..Default::default()
        },
    );
    assert!(matches!(result, Err(DefenderError::FileTypeMismatch)));
}

#[test]
fn valid_apng_can_pass_an_explicit_structural_profile_after_all_frames_are_read() {
    let mut policy = DefensePolicy::default();
    policy.output_mime_whitelist.image.push("image/apng".into());
    let result = FileDefender::new(policy)
        .defend_bytes(
            apng(true),
            Some("animation.apng".into()),
            DefenseContext {
                declared_mime: Some("image/apng".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(result.can_release(), "{:?}", result.alerts);
    assert!(
        result
            .stages
            .iter()
            .any(|stage| stage.detail.contains("all 1 animation frames decoded"))
    );
}

#[test]
fn valid_apng_chunks_with_invalid_pixels_fail_the_separate_output_reader() {
    let mut policy = DefensePolicy::default();
    policy.output_mime_whitelist.image.push("image/apng".into());
    let result = FileDefender::new(policy)
        .defend_bytes(
            apng(false),
            Some("animation.apng".into()),
            DefenseContext::default(),
        )
        .unwrap();
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    assert!(
        result
            .alerts
            .iter()
            .any(|alert| alert.code == "output_read_failed")
    );
    assert!(result.artifact.output_bytes.is_empty());
}

#[test]
fn dissertation_profile_does_not_downgrade_animated_images_to_structural_rebuild() {
    let result = FileDefender::new(DefensePolicy::dissertation_profile()).defend_bytes(
        apng(true),
        Some("animation.apng".into()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::UnsupportedReconstructionLevel)
    ));
}

#[test]
fn permissive_mismatch_policy_still_withholds_release() {
    let policy = DefensePolicy {
        block_kind_mismatch: false,
        ..Default::default()
    };
    let result = FileDefender::new(policy)
        .defend_bytes(png(), Some("photo.jpg".into()), DefenseContext::default())
        .unwrap();
    assert_eq!(result.verdict, DefenseVerdict::Suspicious);
    assert!(!result.can_release());
    assert!(result.artifact.output_bytes.is_empty());
}

#[test]
fn ffi_withholds_blocked_and_suspicious_buffers() {
    for (bytes, name, expected) in [
        (
            b"#!/bin/sh\necho rejected".to_vec(),
            "note.txt",
            ffi::FFI_VERDICT_BLOCKED,
        ),
        (gif(0), "animation.gif", ffi::FFI_VERDICT_SUSPICIOUS),
    ] {
        let name = CString::new(name).unwrap();
        let result = unsafe {
            ffi::file_defender_client_defend_default(
                bytes.as_ptr(),
                bytes.len(),
                name.as_ptr(),
                std::ptr::null(),
            )
        };
        assert_eq!(result.status_code, ffi::FFI_STATUS_OK);
        assert_eq!(result.verdict, expected);
        assert!(result.output_ptr.is_null());
        assert_eq!(result.output_len, 0);
        assert_eq!(result.output_cap, 0);
        assert!(!result.metadata_proto_ptr.is_null());
        unsafe {
            ffi::file_defender_free_buffer(result.output_ptr, result.output_len, result.output_cap);
            ffi::file_defender_free_buffer(
                result.metadata_proto_ptr,
                result.metadata_proto_len,
                result.metadata_proto_cap,
            );
            ffi::file_defender_free_buffer(
                result.error_proto_ptr,
                result.error_proto_len,
                result.error_proto_cap,
            );
        }
    }
}
