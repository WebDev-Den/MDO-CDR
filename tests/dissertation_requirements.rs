//! Generated controls linked to dissertation tables 4.5, 4.6, and 4.11.
//! These small deterministic fixtures do not reproduce the manuscript's
//! 523-record control register, 492-object descriptive corpus, or 769-record plan.
//! The application and these checks share image/gif decoder dependencies: a
//! second decoding call does not establish implementation independence (I*).
use std::io::Cursor;

use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use mdo_cdr::{
    DefendResult, DefenderError, DefenseContext, DefenseVerdict, FileDefender, PipelineStage,
    PipelineStageStatus, policy::DefensePolicy,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Outcome = Result<DefendResult, DefenderError>;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn generated_image(format: ImageFormat, width: u32, height: u32) -> Vec<u8> {
    let pixels = RgbImage::from_fn(width, height, |x, y| {
        Rgb([
            ((x * 7 + y * 13) % 256) as u8,
            ((x * 17 + y * 3) % 256) as u8,
            ((x * 11 + y * 19) % 256) as u8,
        ])
    });
    let mut bytes = Vec::new();
    DynamicImage::ImageRgb8(pixels)
        .write_to(&mut Cursor::new(&mut bytes), format)
        .expect("encode the deterministic image fixture");
    bytes
}

fn generated_low_correlation_webp() -> Vec<u8> {
    // Fixed xorshift32 seed supplies a reproducible low-correlation control.
    // The compact gradient WebP is retained separately as an S5 expansion case.
    let mut state = 0xa5a5_7474_u32;
    let pixels = RgbImage::from_fn(32, 24, |_, _| {
        let mut rgb = [0; 3];
        for channel in &mut rgb {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *channel = (state >> 24) as u8;
        }
        Rgb(rgb)
    });
    let mut bytes = Vec::new();
    DynamicImage::ImageRgb8(pixels)
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::WebP)
        .expect("encode the fixed-seed WebP fixture");
    bytes
}

fn defend(input: &[u8], filename: &str, declared_mime: Option<&str>) -> Outcome {
    FileDefender::new(DefensePolicy::dissertation_profile()).defend_bytes(
        input.to_vec(),
        Some(filename.into()),
        DefenseContext {
            declared_mime: declared_mime.map(str::to_owned),
            ..DefenseContext::default()
        },
    )
}

fn has_read_validation(result: &DefendResult) -> bool {
    result.stages.iter().any(|stage| {
        stage.stage == PipelineStage::OutputValidation
            && stage.status == PipelineStageStatus::Success
            && stage.detail.starts_with("independent_read:")
    })
}

fn withheld(outcome: &Outcome) -> bool {
    match outcome {
        Err(error) => !error.to_string().is_empty(),
        Ok(result) => !result.can_release() && result.artifact.output_bytes.is_empty(),
    }
}

fn decision(outcome: &Outcome) -> Value {
    match outcome {
        Err(error) => json!({"verdict": "Error", "reason": error.to_string(),
                             "released": false, "returned_bytes": 0}),
        Ok(result) => json!({
            "verdict": format!("{:?}", result.verdict),
            "released": result.can_release(),
            "returned_bytes": result.artifact.output_bytes.len(),
            "candidate_bytes": result.artifact.output_size,
            "output_mime": result.artifact.mime,
            "alerts": result.alerts.iter().map(|alert| json!({
                "code": alert.code, "severity": format!("{:?}", alert.severity),
                "reason": alert.message,
            })).collect::<Vec<_>>(),
            "stages": result.stages.iter().map(|stage| json!({
                "stage": format!("{:?}", stage.stage),
                "status": format!("{:?}", stage.status), "detail": stage.detail,
            })).collect::<Vec<_>>(),
            "read_validation_succeeded": has_read_validation(result),
        }),
    }
}

fn evidence(
    case_id: &str,
    group: &str,
    questions: &[&str],
    expected: &str,
    input: &[u8],
    outcome: &Outcome,
    check: (bool, Value),
) -> bool {
    let (passed, mut metrics) = check;
    metrics["decision"] = decision(outcome);
    metrics["input_bytes"] = json!(input.len());
    println!(
        "MDO_EVIDENCE {}",
        json!({
            "case_id": case_id, "group": group, "questions": questions,
            "expected": expected, "passed": passed,
            "fixture_origin": "deterministically_generated_control",
            "policy": "dissertation_profile (resource overrides reported in metrics)",
            "input_sha256": digest(input),
            "output_sha256": outcome.as_ref().ok()
                .filter(|result| !result.artifact.output_bytes.is_empty())
                .map(|result| digest(&result.artifact.output_bytes)),
            "metrics": metrics,
        })
    );
    passed
}

fn pixel_fidelity(input: &[u8], outcome: &Outcome) -> (bool, Value) {
    let before = image::load_from_memory(input).expect("generated input must fully decode");
    let Ok(result) = outcome else {
        return (false, json!({"output_decoded": false}));
    };
    match image::load_from_memory(&result.artifact.output_bytes) {
        Err(error) => (
            false,
            json!({"output_decoded": false, "decode_error": error.to_string()}),
        ),
        Ok(after) => {
            let geometry_equal =
                before.width() == after.width() && before.height() == after.height();
            let pixels_equal = before.to_rgba8() == after.to_rgba8();
            let passed = result.can_release()
                && result.artifact.mime == "image/png"
                && has_read_validation(result)
                && geometry_equal
                && pixels_equal;
            (
                passed,
                json!({
                    "output_decoded": true, "geometry_equal": geometry_equal,
                    "input_dimensions": [before.width(), before.height()],
                    "output_dimensions": [after.width(), after.height()],
                    "decoded_rgba_equal": pixels_equal,
                    "psnr_db": if pixels_equal { json!("Infinity") } else { Value::Null },
                    "psnr_threshold_db": 40,
                    "decoder_implementation_independence": false,
                    "consumed_bytes_measurement": "not exposed by public pipeline API",
                }),
            )
        }
    }
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(data);
    let mut crc = 0xffff_ffffu32;
    for byte in kind.iter().chain(data) {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    bytes.extend_from_slice(&(!crc).to_be_bytes());
    bytes
}

#[test]
fn s0_supported_rasters_preserve_geometry_and_decoded_pixels() {
    let mut all_passed = true;
    for (format, extension, mime) in [
        (ImageFormat::Png, "png", "image/png"),
        (ImageFormat::Jpeg, "jpg", "image/jpeg"),
        (ImageFormat::Bmp, "bmp", "image/bmp"),
        (ImageFormat::Tiff, "tiff", "image/tiff"),
        (ImageFormat::WebP, "webp", "image/webp"),
    ] {
        let input = if format == ImageFormat::WebP {
            generated_low_correlation_webp()
        } else {
            generated_image(format, 32, 24)
        };
        let outcome = defend(&input, &format!("pattern.{extension}"), Some(mime));
        let check = pixel_fidelity(&input, &outcome);
        all_passed &= evidence(
            &format!("S0-raster-{extension}"),
            "S0",
            &["Q1", "Q4"],
            "release PNG with equal dimensions and exactly equal decoded input pixels",
            &input,
            &outcome,
            check,
        );
    }
    assert!(all_passed, "see MDO_EVIDENCE for failing raster cases");
}

#[test]
fn s1_png_text_metadata_is_removed_without_pixel_loss() {
    let mut input = generated_image(ImageFormat::Png, 32, 24);
    let marker = b"Comment\0MDO_GENERATED_METADATA_CONTROL_2026";
    let chunk = png_chunk(b"tEXt", marker);
    input.splice(input.len() - 12..input.len() - 12, chunk.iter().copied());
    let outcome = defend(&input, "metadata.png", Some("image/png"));
    let (fidelity, mut metrics) = pixel_fidelity(&input, &outcome);
    let marker_absent = outcome.as_ref().is_ok_and(|result| {
        !result
            .artifact
            .output_bytes
            .windows(marker.len())
            .any(|part| part == marker)
    });
    metrics["input_contains_valid_text_chunk"] = json!(true);
    metrics["inserted_chunk_bytes"] = json!(chunk.len());
    metrics["metadata_marker_absent_from_output"] = json!(marker_absent);
    assert!(evidence(
        "S1-png-text-metadata",
        "S1",
        &["Q1"],
        "release PNG with the valid tEXt marker removed and decoded pixels unchanged",
        &input,
        &outcome,
        (fidelity && marker_absent, metrics),
    ));
}

#[test]
fn s2_truncated_and_invalid_compressed_pngs_withhold_bytes() {
    let original = generated_image(ImageFormat::Png, 32, 24);
    let truncated = original[..original.len() / 2].to_vec();
    // Preserve the full, valid IHDR and chunk CRCs. The IDAT payload itself is
    // invalid zlib data, so this tests decoding, not just a missing signature.
    let mut corrupt = original[..33].to_vec();
    corrupt.extend_from_slice(&png_chunk(b"IDAT", b"invalid zlib pixel stream"));
    corrupt.extend_from_slice(&png_chunk(b"IEND", &[]));
    let mut all_passed = true;
    for (case_id, input) in [
        ("S2-png-truncated", truncated),
        ("S2-png-invalid-idat", corrupt),
    ] {
        let input_decode_failed = image::load_from_memory(&input).is_err();
        let outcome = defend(&input, "damaged.png", Some("image/png"));
        all_passed &= evidence(
            case_id,
            "S2",
            &["Q2"],
            "withhold all result bytes for a PNG with undecodable pixel data",
            &input,
            &outcome,
            (
                input_decode_failed
                    && withheld(&outcome)
                    && matches!(&outcome, Err(DefenderError::Image(_))),
                json!({"input_decode_failed": input_decode_failed, "expected_error_class": "Image"}),
            ),
        );
    }
    assert!(all_passed, "see MDO_EVIDENCE for malformed PNG cases");
}

#[test]
fn s3_filename_mime_and_double_extension_conflicts_withhold_bytes() {
    let input = generated_image(ImageFormat::Png, 32, 24);
    let mut all_passed = true;
    for (case_id, filename, mime) in [
        ("S3-png-named-jpeg", "pattern.jpg", "image/png"),
        ("S3-false-declared-mime", "pattern.png", "image/jpeg"),
        (
            "S3-hidden-executable-extension",
            "pattern.exe.png",
            "image/png",
        ),
    ] {
        let outcome = defend(&input, filename, Some(mime));
        let hidden_extension = filename.contains(".exe.");
        let expected_error_matched = if hidden_extension {
            matches!(&outcome, Err(DefenderError::UnsupportedReconstructionLevel))
        } else {
            matches!(&outcome, Err(DefenderError::FileTypeMismatch))
        };
        all_passed &= evidence(
            case_id,
            "S3",
            &["Q2"],
            "withhold all result bytes when input type evidence conflicts",
            &input,
            &outcome,
            (
                withheld(&outcome) && expected_error_matched,
                json!({"filename": filename, "declared_mime": mime,
                    "actual_format": "PNG", "expected_error_class": if hidden_extension {
                        "UnsupportedReconstructionLevel (dangerous double extension routed to Other)"
                    } else { "FileTypeMismatch" }}),
            ),
        );
    }
    assert!(all_passed, "see MDO_EVIDENCE for type conflicts");
}

#[test]
fn s4_appended_foreign_bytes_are_removed_or_withheld() {
    let mut input = generated_image(ImageFormat::Png, 32, 24);
    let marker = b"MDO_BENIGN_TRAILING_CONTROL_2026";
    input.extend_from_slice(marker);
    // An empty ZIP end-of-central-directory record, without executable content.
    input.extend_from_slice(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    let outcome = defend(&input, "trailing.png", Some("image/png"));
    let (fidelity, mut metrics) = pixel_fidelity(&input, &outcome);
    let marker_absent = outcome.as_ref().is_ok_and(|result| {
        !result
            .artifact
            .output_bytes
            .windows(marker.len())
            .any(|part| part == marker)
            && !result
                .artifact
                .output_bytes
                .windows(4)
                .any(|part| part == b"PK\x05\x06")
    });
    metrics["appended_marker_and_zip_record_absent"] = json!(marker_absent);
    metrics["scope"] = json!(
        "controlled PNG plus benign appended data; not a general polyglot detector benchmark"
    );
    assert!(evidence(
        "S4-png-appended-data",
        "S4",
        &["Q2"],
        "withhold, or release equal decoded pixels with both appended signatures removed",
        &input,
        &outcome,
        (withheld(&outcome) || (fidelity && marker_absent), metrics),
    ));
}

#[test]
fn s5_resource_boundaries_are_inclusive_and_fail_closed_above_limit() {
    let mut all_passed = true;
    for pixels in [15, 16, 17] {
        let input = generated_image(ImageFormat::Png, pixels, 1);
        let mut policy = DefensePolicy::dissertation_profile();
        policy.image.max_pixels = 16;
        let outcome = FileDefender::new(policy).defend_bytes(
            input.clone(),
            Some("boundary.png".into()),
            DefenseContext::default(),
        );
        let expected_release = pixels <= 16;
        let passed = if expected_release {
            pixel_fidelity(&input, &outcome).0
        } else {
            withheld(&outcome)
                && matches!(&outcome, Err(DefenderError::Io(error))
                if error.kind() == std::io::ErrorKind::InvalidData && error.to_string().contains("max_pixels: 17 > 16"))
        };
        all_passed &= evidence(
            &format!("S5-pixels-{pixels}-limit-16"),
            "S5",
            &["Q3"],
            if expected_release {
                "release at or below the pixel limit"
            } else {
                "withhold above the pixel limit"
            },
            &input,
            &outcome,
            (passed, json!({"actual_pixels": pixels, "max_pixels": 16})),
        );
    }
    let input = generated_image(ImageFormat::Png, 32, 24);
    for relative in [-1_i64, 0, 1] {
        // Vary the policy limit, keeping the same small valid input: the actual
        // size is respectively L-1, L, L+1. No large allocation is needed.
        let limit = (input.len() as i64 - relative) as u64;
        let mut policy = DefensePolicy::dissertation_profile();
        policy.max_input_size_bytes = limit;
        let outcome = FileDefender::new(policy).defend_bytes(
            input.clone(),
            Some("boundary.png".into()),
            DefenseContext::default(),
        );
        let expected_release = relative <= 0;
        let passed = if expected_release {
            pixel_fidelity(&input, &outcome).0
        } else {
            withheld(&outcome)
                && matches!(&outcome, Err(DefenderError::FileTooLarge { limit: observed_limit, actual })
                if *observed_limit == limit && *actual == input.len() as u64)
        };
        all_passed &= evidence(
            &format!("S5-input-bytes-relative-{relative}"),
            "S5",
            &["Q3"],
            if expected_release {
                "release at or below the input byte limit"
            } else {
                "withhold above the input byte limit"
            },
            &input,
            &outcome,
            (
                passed,
                json!({"max_input_bytes": limit, "input_minus_limit": relative}),
            ),
        );
    }
    assert!(all_passed, "see MDO_EVIDENCE for resource boundary cases");
}

#[test]
fn s5_valid_compact_webp_exceeding_output_expansion_is_withheld() {
    let input = generated_image(ImageFormat::WebP, 32, 24);
    let decoded = image::load_from_memory(&input).expect("valid compact WebP");
    let mut png = Vec::new();
    decoded
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .unwrap();
    let expected_ratio = png.len() as f64 / input.len() as f64;
    let policy_limit = DefensePolicy::dissertation_profile().max_output_expansion_ratio;
    let outcome = defend(&input, "compact.webp", Some("image/webp"));
    let expansion_rejection = matches!(&outcome,
        Err(DefenderError::OutputExpansionTooHigh { limit, actual })
        if *limit == policy_limit && (*actual - expected_ratio).abs() < 1e-12);
    assert!(evidence(
        "S5-webp-output-expansion",
        "S5",
        &["Q3"],
        "withhold with OutputExpansionTooHigh when valid reconstructed PNG exceeds the unchanged profile ratio",
        &input,
        &outcome,
        (
            expected_ratio > policy_limit && expansion_rejection && withheld(&outcome),
            json!({
                "input_decoded": true, "reconstructed_png_bytes": png.len(),
                "expected_expansion_ratio": expected_ratio, "max_output_expansion_ratio": policy_limit,
                "fixture_classification_note": "valid pixels do not override the output expansion limit; resource case rather than an expected-release S0 case",
            })
        ),
    ));
}

#[test]
fn s6_unsupported_text_archive_and_executable_canary_withhold_bytes() {
    let mut all_passed = true;
    for (case_id, filename, input) in [
        (
            "S6-plain-text",
            "note.txt",
            b"Benign generated text; unsupported semantic reconstruction.".to_vec(),
        ),
        (
            "S6-empty-zip",
            "empty.zip",
            b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
        ),
        (
            "S6-executable-canary",
            "canary.png",
            b"MZ harmless header canary, not an executable program".to_vec(),
        ),
    ] {
        let outcome = defend(&input, filename, None);
        let expected_reason_matched = if case_id == "S6-executable-canary" {
            outcome.as_ref().is_ok_and(|result| {
                result.verdict == DefenseVerdict::Blocked
                    && result.diagnostics.parser_used == "pre_scan_blocked"
            })
        } else {
            matches!(&outcome, Err(DefenderError::UnsupportedReconstructionLevel))
        };
        all_passed &= evidence(
            case_id,
            "S6",
            &["Q2"],
            "withhold unsupported content or executable-header canary",
            &input,
            &outcome,
            (
                withheld(&outcome) && expected_reason_matched,
                json!({"filename": filename,
                "expected_reason_matched": expected_reason_matched}),
            ),
        );
    }
    assert!(all_passed, "see MDO_EVIDENCE for unsupported content cases");
}

#[test]
fn q4_same_input_repeats_and_accepted_png_is_a_fixed_point() {
    let input = generated_image(ImageFormat::Png, 32, 24);
    let runs = (0..3)
        .map(|_| defend(&input, "repeat.png", Some("image/png")))
        .collect::<Vec<_>>();
    let decisions = runs.iter().map(decision).collect::<Vec<_>>();
    let output_hashes = runs
        .iter()
        .map(|run| {
            run.as_ref()
                .ok()
                .map(|result| digest(&result.artifact.output_bytes))
        })
        .collect::<Vec<_>>();
    let repeated_input_stable = decisions.windows(2).all(|pair| pair[0] == pair[1])
        && output_hashes.windows(2).all(|pair| pair[0] == pair[1]);
    let all_runs_pass_fidelity = runs.iter().all(|run| pixel_fidelity(&input, run).0);
    let second_pass = runs[0]
        .as_ref()
        .ok()
        .filter(|result| result.can_release())
        .map(|result| {
            defend(
                &result.artifact.output_bytes,
                "accepted.png",
                Some("image/png"),
            )
        });
    let fixed_point = match (&runs[0], &second_pass) {
        (Ok(first), Some(Ok(second))) => {
            second.can_release()
                && has_read_validation(second)
                && first.artifact.output_bytes == second.artifact.output_bytes
        }
        _ => false,
    };
    assert!(evidence(
        "Q4-png-repeat-and-fixed-point",
        "S0",
        &["Q4"],
        "three equal decisions/stages/format/level/hashes and byte-identical accepted PNG on a second pass",
        &input,
        &runs[0],
        (
            all_runs_pass_fidelity && repeated_input_stable && fixed_point,
            json!({
                "same_input_runs": 3, "same_input_output_sha256": output_hashes,
                "same_input_decision_and_stages_equal": repeated_input_stable,
                "accepted_output_second_pass_byte_equal": fixed_point,
                "second_pass_decision": second_pass.as_ref().map(decision),
                "decoder_implementation_independence": false,
                "consumed_bytes_measurement": "not exposed by public pipeline API",
            })
        ),
    ));
}

fn generated_gif() -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut encoder = gif::Encoder::new(&mut bytes, 8, 6, &[0, 0, 0, 255, 255, 255]).unwrap();
        encoder.set_repeat(gif::Repeat::Infinite).unwrap();
        for index in 0..4 {
            let frame = gif::Frame {
                width: 8,
                height: 6,
                delay: 10,
                dispose: gif::DisposalMethod::Keep,
                buffer: (0..48)
                    .map(|pixel| ((pixel + index) % 2) as u8)
                    .collect::<Vec<_>>()
                    .into(),
                ..Default::default()
            };
            encoder.write_frame(&frame).unwrap();
        }
    }
    bytes
}

#[derive(PartialEq, Eq)]
struct GifFrames {
    width: u16,
    height: u16,
    pixels: Vec<Vec<u8>>,
    delays: Vec<u16>,
}

fn read_gif(bytes: &[u8]) -> Result<GifFrames, gif::DecodingError> {
    let mut options = gif::DecodeOptions::new();
    options.set_color_output(gif::ColorOutput::RGBA);
    let mut decoder = options.read_info(Cursor::new(bytes))?;
    let mut frames = GifFrames {
        width: decoder.width(),
        height: decoder.height(),
        pixels: Vec::new(),
        delays: Vec::new(),
    };
    while let Some(frame) = decoder.read_next_frame()? {
        // This control uses opaque full-canvas frames, so the frame RGBA buffer
        // is also the complete composited canvas; it needs no disposal emulation.
        if frame.width != frames.width
            || frame.height != frames.height
            || frame.left != 0
            || frame.top != 0
        {
            return Err(gif::DecodingError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "generated full-canvas GIF became a partial frame",
            )));
        }
        frames.pixels.push(frame.buffer.to_vec());
        frames.delays.push(frame.delay);
    }
    Ok(frames)
}

fn symmetric_difference(left: u64, right: u64) -> f64 {
    if left + right == 0 {
        0.0
    } else {
        2.0 * left.abs_diff(right) as f64 / (left + right) as f64
    }
}

#[test]
fn s0_gif_preserves_all_frames_pixels_and_timing_within_two_percent() {
    let input = generated_gif();
    let before = read_gif(&input).expect("generated GIF must fully decode");
    let outcome = defend(&input, "animation.gif", Some("image/gif"));
    let after = outcome
        .as_ref()
        .ok()
        .and_then(|result| read_gif(&result.artifact.output_bytes).ok());
    let mut metrics = json!({"input_frames": before.pixels.len(), "input_delays_cs": before.delays,
                             "duration_relative_error_limit": 0.02,
                             "decoder_implementation_independence": false});
    let mut passed = false;
    if let Some(after) = after {
        let input_duration = before.delays.iter().map(|delay| u64::from(*delay)).sum();
        let output_duration = after.delays.iter().map(|delay| u64::from(*delay)).sum();
        let duration_error = symmetric_difference(input_duration, output_duration);
        let frame_delays_pass = before.delays.len() == after.delays.len()
            && before
                .delays
                .iter()
                .zip(&after.delays)
                .all(|(left, right)| {
                    symmetric_difference(u64::from(*left), u64::from(*right)) <= 0.02
                });
        let geometry_equal = before.width == after.width && before.height == after.height;
        let pixels_equal = before.pixels == after.pixels;
        passed = outcome
            .as_ref()
            .is_ok_and(|result| result.can_release() && has_read_validation(result))
            && before.pixels.len() == 4
            && after.pixels.len() == 4
            && geometry_equal
            && pixels_equal
            && frame_delays_pass
            && duration_error <= 0.02;
        metrics["output_frames"] = json!(after.pixels.len());
        metrics["output_delays_cs"] = json!(after.delays);
        metrics["geometry_equal"] = json!(geometry_equal);
        metrics["all_decoded_canvas_pixels_equal"] = json!(pixels_equal);
        metrics["all_frame_delay_errors_within_limit"] = json!(frame_delays_pass);
        metrics["input_duration_cs"] = json!(input_duration);
        metrics["output_duration_cs"] = json!(output_duration);
        metrics["symmetric_duration_relative_error"] = json!(duration_error);
        metrics["psnr_db"] = if pixels_equal {
            json!("Infinity")
        } else {
            Value::Null
        };
    }
    assert!(evidence(
        "S0-gif-four-frames",
        "S0",
        &["Q1", "Q4"],
        "release all four full-canvas GIF frames with equal RGBA pixels and total/per-frame duration error <= 2%",
        &input,
        &outcome,
        (passed, metrics),
    ));
}
