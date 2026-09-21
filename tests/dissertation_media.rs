//! Generated S0 content controls and an S5 resource rejection for §4.6/Table 4.11.
//!
//! These fixtures are not members of the dissertation's 492-object corpus.
//! FFmpeg is the single external decoder used here; this is not a reproduction
//! of the dissertation's separate two-evaluator experimental procedure.
//! The fixtures, alignment, frame grid and thresholds are fixed before execution.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type TestResult<T> = Result<T, String>;

const SAMPLE_RATE: usize = 48_000;
const MAX_LAG_FRAMES: isize = 240; // ±5 ms, one shared lag for both stereo channels.
const ALIGNMENT_WINDOW_FRAMES: usize = 12_000;
const VIDEO_FRAMES: usize = 36;

fn successful(command: &mut Command) -> TestResult<Output> {
    let output = command.output().map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "{command:?}: {}: stderr: {}; stdout: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    Ok(output)
}

fn runtime() -> TestResult<(OsString, OsString)> {
    Ok((
        std::env::var_os("MDO_TEST_FFMPEG").ok_or("set MDO_TEST_FFMPEG")?,
        std::env::var_os("MDO_TEST_FFPROBE").ok_or("set MDO_TEST_FFPROBE")?,
    ))
}

fn evidence_case(
    case_id: &str,
    group: &str,
    expected: &str,
    run: impl FnOnce(&mut Value) -> TestResult<()>,
) {
    let start = Instant::now();
    let mut evidence = json!({
        "case_id": case_id,
        "group": group,
        "questions": ["Q1", "Q4"],
        "expected": expected,
        "passed": false,
        "input_sha256": null,
        "output_sha256": null,
        "metrics": {
            "fixture_origin": "generated_control_not_dissertation_corpus",
            "external_decoder": "FFmpeg",
            "external_evaluator_count": 1,
            "duration_relative_error_max": 0.02
        }
    });
    let result = run(&mut evidence);
    evidence["passed"] = json!(result.is_ok());
    evidence["metrics"]["wall_time_ms"] = json!(start.elapsed().as_secs_f64() * 1000.0);
    if let Err(error) = &result {
        evidence["metrics"]["failure"] = json!(error);
    }
    // One machine-readable record is emitted even when a measurement/check fails.
    println!("MDO_EVIDENCE {evidence}");
    assert!(result.is_ok(), "{case_id}: {result:?}");
}

fn reconstruct(
    input: &Path,
    destination: &Path,
    ffmpeg: &OsString,
    ffprobe: &OsString,
    evidence: &mut Value,
) -> TestResult<PathBuf> {
    let input_bytes = std::fs::read(input).map_err(|error| error.to_string())?;
    evidence["input_sha256"] = json!(hex::encode(Sha256::digest(&input_bytes)));
    evidence["metrics"]["input_bytes"] = json!(input_bytes.len());
    let invocation = Command::new(env!("CARGO_BIN_EXE_mdocdr"))
        .arg("--input")
        .arg(input)
        .arg("--output-dir")
        .arg(destination)
        .args(["--profile", "dissertation", "--ffmpeg"])
        .arg(ffmpeg)
        .arg("--ffprobe")
        .arg(ffprobe)
        .arg("--json")
        .output()
        .map_err(|error| error.to_string())?;
    let report: Value =
        serde_json::from_slice(&invocation.stdout).map_err(|error| error.to_string())?;
    evidence["metrics"]["released"] = report["released"].clone();
    evidence["metrics"]["cli_exit_code"] = json!(invocation.status.code());
    evidence["metrics"]["output_path_present"] = json!(!report["output_path"].is_null());
    let report_path = Path::new(
        report["report_path"]
            .as_str()
            .ok_or("missing report_path")?,
    );
    let persisted: Value =
        serde_json::from_slice(&std::fs::read(report_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    if persisted != report {
        return Err("persisted and stdout reports differ".into());
    }
    if std::fs::read(input).map_err(|error| error.to_string())? != input_bytes {
        return Err("the input file changed during reconstruction".into());
    }
    if !invocation.status.success() || report["released"] != true {
        evidence["metrics"]["release_error"] = report["error"].clone();
        return Err(
            "generated control was not released; content metrics are not applicable".into(),
        );
    }
    let output = PathBuf::from(
        report["output_path"]
            .as_str()
            .ok_or("missing output_path")?,
    );
    let output_bytes = std::fs::read(&output).map_err(|error| error.to_string())?;
    evidence["output_sha256"] = json!(hex::encode(Sha256::digest(&output_bytes)));
    evidence["metrics"]["output_bytes"] = json!(output_bytes.len());
    Ok(output)
}

fn probe(ffprobe: &OsString, path: &Path) -> TestResult<Value> {
    let output = successful(
        Command::new(ffprobe)
            .args([
                "-v",
                "error",
                "-count_frames",
                "-show_entries",
                "stream=codec_type,width,height,channels,sample_rate,nb_read_frames:format=duration,bit_rate",
                "-of",
                "json",
            ])
            .arg(path),
    )?;
    serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())
}

fn numeric(value: &Value) -> TestResult<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .filter(|number| number.is_finite())
        .ok_or_else(|| format!("missing/invalid numeric measurement: {value}"))
}

fn symmetric_duration_error(first: f64, second: f64) -> f64 {
    if first == 0.0 && second == 0.0 {
        0.0
    } else {
        2.0 * (first - second).abs() / (first + second)
    }
}

fn decode_audio(ffmpeg: &OsString, path: &Path) -> TestResult<Vec<f64>> {
    let output = successful(
        Command::new(ffmpeg)
            .args(["-nostdin", "-v", "error", "-xerror", "-i"])
            .arg(path)
            .args([
                "-map",
                "0:a:0",
                "-ar",
                "48000",
                "-c:a",
                "pcm_f32le",
                "-f",
                "f32le",
                "pipe:1",
            ]),
    )?;
    if output.stdout.is_empty() || output.stdout.len() % 4 != 0 {
        return Err("external decoder returned incomplete/empty PCM".into());
    }
    let samples: Vec<f64> = output
        .stdout
        .as_chunks::<4>()
        .0
        .iter()
        .map(|bytes| f32::from_le_bytes(*bytes) as f64)
        .collect();
    if !samples.iter().all(|sample| sample.is_finite()) {
        return Err("decoded PCM contains non-finite samples".into());
    }
    Ok(samples)
}

fn aligned_samples<'a>(
    input: &'a [f64],
    output: &'a [f64],
    channels: usize,
    lag: isize,
) -> (&'a [f64], &'a [f64]) {
    let input_start = (-lag).max(0) as usize * channels;
    let output_start = lag.max(0) as usize * channels;
    let length = (input.len() - input_start).min(output.len() - output_start);
    (
        &input[input_start..input_start + length],
        &output[output_start..output_start + length],
    )
}

fn shared_lag(input: &[f64], output: &[f64], channels: usize) -> isize {
    // Fixed normalized cross-correlation of the first 0.25 s. Ties retain
    // the first candidate: zero, +1, -1, +2, -2, ... samples at 48 kHz.
    let mut best = (f64::NEG_INFINITY, 0);
    for magnitude in 0..=MAX_LAG_FRAMES {
        for lag in [magnitude, -magnitude] {
            let (reference, estimate) = aligned_samples(input, output, channels, lag);
            let limit = reference.len().min(ALIGNMENT_WINDOW_FRAMES * channels);
            let mut dot = 0.0;
            let mut input_power = 0.0;
            let mut output_power = 0.0;
            for (&first, &second) in reference[..limit].iter().zip(&estimate[..limit]) {
                dot += first * second;
                input_power += first * first;
                output_power += second * second;
            }
            let score = dot / (input_power * output_power).sqrt();
            if score > best.0 {
                best = (score, lag);
            }
        }
    }
    best.1
}

fn si_sdr(reference: &[f64], estimate: &[f64]) -> TestResult<f64> {
    let reference_mean = reference.iter().sum::<f64>() / reference.len() as f64;
    let estimate_mean = estimate.iter().sum::<f64>() / estimate.len() as f64;
    let reference_power: f64 = reference
        .iter()
        .map(|sample| (sample - reference_mean).powi(2))
        .sum();
    if reference_power == 0.0 {
        return Err("SI-SDR is undefined for a constant reference".into());
    }
    let dot: f64 = reference
        .iter()
        .zip(estimate)
        .map(|(first, second)| (first - reference_mean) * (second - estimate_mean))
        .sum();
    let scale = dot / reference_power;
    let target_power = scale * scale * reference_power;
    let residual_power: f64 = reference
        .iter()
        .zip(estimate)
        .map(|(first, second)| {
            ((second - estimate_mean) - scale * (first - reference_mean)).powi(2)
        })
        .sum();
    if target_power == 0.0 {
        return Ok(f64::NEG_INFINITY);
    }
    Ok(10.0 * (target_power / residual_power).log10())
}

fn decibels(value: f64) -> Value {
    if value == f64::INFINITY {
        json!("positive_infinity")
    } else if value == f64::NEG_INFINITY {
        json!("negative_infinity")
    } else {
        json!(value)
    }
}

#[test]
#[ignore = "requires MDO_TEST_FFMPEG and MDO_TEST_FFPROBE; generated dissertation-threshold control"]
fn audio_content_matches_dissertation_thresholds() {
    // The original PCM16 control exceeds the dissertation profile's 1024 kb/s
    // admission limit. Preserve that observation as a resource rejection;
    // content similarity is not evaluated for its withheld output.
    evidence_case(
        "generated_stereo_pcm16_bitrate_rejected",
        "S5",
        "withhold stereo 48kHz PCM16 exceeding 1024000 bit/s; exit 2 with audio bitrate reason",
        |evidence| {
            let (ffmpeg, ffprobe) = runtime()?;
            let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
            let input = temp.path().join("generated stereo tones.wav");
            successful(
                Command::new(&ffmpeg)
                    .args([
                        "-nostdin",
                        "-v",
                        "error",
                        "-f",
                        "lavfi",
                        "-i",
                        "aevalsrc=0.25*sin(2*PI*440*t)|0.25*sin(2*PI*659*t):s=48000:d=3",
                        "-c:a",
                        "pcm_s16le",
                    ])
                    .arg(&input),
            )?;
            let input_probe = probe(&ffprobe, &input)?;
            let bitrate = numeric(&input_probe["format"]["bit_rate"])?;
            evidence["questions"] = json!(["Q2"]);
            evidence["metrics"]["input_encoding"] = json!("PCM signed 16-bit little-endian WAV");
            evidence["metrics"]["input_bitrate_bits_per_second"] = json!(bitrate);
            evidence["metrics"]["bitrate_limit_bits_per_second"] = json!(1_024_000);
            evidence["metrics"]["content_evaluation"] = json!("not_applicable_no_released_output");
            let destination = temp.path().join("result");
            let result = reconstruct(&input, &destination, &ffmpeg, &ffprobe, evidence);
            let metrics = &evidence["metrics"];
            let expected_reason = format!(
                "audio bitrate exceeds max_bitrate_kbps: {} > 1024000",
                bitrate as u64
            );
            let report_only = std::fs::read_dir(&destination)
                .map_err(|error| error.to_string())?
                .map(|entry| entry.map(|item| item.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            if result.is_ok()
                || bitrate <= 1_024_000.0
                || metrics["released"] != false
                || metrics["cli_exit_code"] != 2
                || metrics["output_path_present"] != false
                || !metrics["release_error"]
                    .as_str()
                    .unwrap_or("")
                    .contains(&expected_reason)
                || report_only.len() != 1
                || report_only[0].extension().and_then(|value| value.to_str()) != Some("json")
            {
                return Err(
                    "PCM16 admission did not produce the expected resource rejection".into(),
                );
            }
            Ok(())
        },
    );

    // PCM8 retains stereo/48 kHz/3 s while fitting the same admission policy.
    // This explicitly different generated fixture uses the unchanged fidelity
    // thresholds below; no metrics are claimed for the rejected PCM16 input.
    for (case_id, filename, codec, encoding) in [
        (
            "generated_stereo_audio_content",
            "generated stereo tones.wav",
            "pcm_u8",
            "PCM unsigned 8-bit WAV",
        ),
        (
            "generated_mp3_audio_content",
            "generated stereo tones.mp3",
            "libmp3lame",
            "MPEG Layer III in MP3",
        ),
        (
            "generated_flac_audio_content",
            "generated stereo tones.flac",
            "flac",
            "FLAC",
        ),
        (
            "generated_opus_audio_content",
            "generated stereo tones.ogg",
            "libopus",
            "Opus in Ogg",
        ),
    ] {
        evidence_case(
            case_id,
            "S0",
            "release; same channels; decoded duration error <= 0.02; bidirectional SI-SDR >= 20 dB",
            |evidence| {
                let (ffmpeg, ffprobe) = runtime()?;
                let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
                let input = temp.path().join(filename);
                evidence["metrics"]["input_encoding"] = json!(encoding);
                evidence["metrics"]["fixture_encoder"] = json!(codec);
                evidence["metrics"]["fixture_encoder_options"] = json!(["-c:a", codec]);
                evidence["metrics"]["fixture_filter"] =
                    json!("aevalsrc=0.25*sin(2*PI*440*t)|0.25*sin(2*PI*659*t):s=48000:d=3");
                successful(
                    Command::new(&ffmpeg)
                        .args([
                            "-nostdin",
                            "-v",
                            "error",
                            "-f",
                            "lavfi",
                            "-i",
                            "aevalsrc=0.25*sin(2*PI*440*t)|0.25*sin(2*PI*659*t):s=48000:d=3",
                            "-c:a",
                            codec,
                        ])
                        .arg(&input),
                )?;
                let output = reconstruct(
                    &input,
                    &temp.path().join("result"),
                    &ffmpeg,
                    &ffprobe,
                    evidence,
                )?;
                let source_probe = probe(&ffprobe, &input)?;
                let output_probe = probe(&ffprobe, &output)?;
                let input_channels = numeric(&source_probe["streams"][0]["channels"])? as usize;
                let output_channels = numeric(&output_probe["streams"][0]["channels"])? as usize;
                evidence["metrics"]["input_channels"] = json!(input_channels);
                evidence["metrics"]["output_channels"] = json!(output_channels);
                evidence["metrics"]["si_sdr_min_db_required"] = json!(20.0);
                if input_channels != 2 || output_channels != input_channels {
                    return Err("stereo channel count was not preserved".into());
                }
                let original = decode_audio(&ffmpeg, &input)?;
                let rebuilt = decode_audio(&ffmpeg, &output)?;
                if original.len() % input_channels != 0
                    || rebuilt.len() % input_channels != 0
                    || original.len().min(rebuilt.len()) / input_channels <= MAX_LAG_FRAMES as usize
                {
                    return Err("PCM does not contain enough complete interleaved frames".into());
                }
                let input_frames = original.len() / input_channels;
                let output_frames = rebuilt.len() / input_channels;
                let input_duration = input_frames as f64 / SAMPLE_RATE as f64;
                let output_duration = output_frames as f64 / SAMPLE_RATE as f64;
                let duration_error = symmetric_duration_error(input_duration, output_duration);
                let lag = shared_lag(&original, &rebuilt, input_channels);
                let (aligned_input, aligned_output) =
                    aligned_samples(&original, &rebuilt, input_channels, lag);
                let mut directions = Vec::new();
                let mut minimum = f64::INFINITY;
                for channel in 0..input_channels {
                    let first: Vec<f64> = aligned_input
                        .iter()
                        .skip(channel)
                        .step_by(input_channels)
                        .copied()
                        .collect();
                    let second: Vec<f64> = aligned_output
                        .iter()
                        .skip(channel)
                        .step_by(input_channels)
                        .copied()
                        .collect();
                    let forward = si_sdr(&first, &second)?;
                    let reverse = si_sdr(&second, &first)?;
                    minimum = minimum.min(forward).min(reverse);
                    directions.push(json!({
                        "channel": channel,
                        "input_reference_db": decibels(forward),
                        "output_reference_db": decibels(reverse)
                    }));
                }
                let metrics = &mut evidence["metrics"];
                metrics["decoded_sample_rate_hz"] = json!(SAMPLE_RATE);
                metrics["input_decoded_frames"] = json!(input_frames);
                metrics["output_decoded_frames"] = json!(output_frames);
                metrics["input_duration_seconds"] = json!(input_duration);
                metrics["output_duration_seconds"] = json!(output_duration);
                metrics["duration_relative_error"] = json!(duration_error);
                metrics["alignment_method"] = json!(
                    "shared_normalized_cross_correlation_first_12000_frames_lag_plus_minus_240"
                );
                metrics["alignment_lag_frames"] = json!(lag);
                metrics["aligned_frames"] = json!(aligned_input.len() / input_channels);
                metrics["si_sdr_directions_per_channel"] = json!(directions);
                metrics["si_sdr_min_db"] = decibels(minimum);
                if input_frames != 3 * SAMPLE_RATE || duration_error > 0.02 || minimum < 20.0 {
                    return Err(
                        "generated audio did not meet the fixed Table 4.11 thresholds".into(),
                    );
                }
                Ok(())
            },
        );
    }
}

#[test]
#[ignore = "requires MDO_TEST_FFMPEG and MDO_TEST_FFPROBE; generated dissertation-threshold control"]
fn video_content_matches_dissertation_thresholds() {
    for (case_id, filename, codec, encoding) in [
        (
            "generated_video_content",
            "generated test pattern.mp4",
            "mpeg4",
            "MPEG-4 Part 2 in MP4",
        ),
        (
            "generated_webm_video_content",
            "generated test pattern.webm",
            "libvpx-vp9",
            "VP9 in WebM",
        ),
    ] {
        evidence_case(
            case_id,
            "S0",
            "release; same 96x64 dimensions; duration error <= 0.02; SSIM >= 0.90 on all 36 fixed-grid frames",
            |evidence| {
                let (ffmpeg, ffprobe) = runtime()?;
                let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
                let input = temp.path().join(filename);
                evidence["metrics"]["input_encoding"] = json!(encoding);
                evidence["metrics"]["fixture_encoder"] = json!(codec);
                evidence["metrics"]["fixture_encoder_options"] =
                    json!(["-an", "-c:v", codec, "-pix_fmt", "yuv420p"]);
                evidence["metrics"]["fixture_filter"] =
                    json!("testsrc2=size=96x64:rate=12:duration=3");
                successful(
                    Command::new(&ffmpeg)
                        .args([
                            "-nostdin",
                            "-v",
                            "error",
                            "-f",
                            "lavfi",
                            "-i",
                            "testsrc2=size=96x64:rate=12:duration=3",
                            "-an",
                            "-c:v",
                            codec,
                            "-pix_fmt",
                            "yuv420p",
                        ])
                        .arg(&input),
                )?;
                let output = reconstruct(
                    &input,
                    &temp.path().join("result"),
                    &ffmpeg,
                    &ffprobe,
                    evidence,
                )?;
                let source_probe = probe(&ffprobe, &input)?;
                let output_probe = probe(&ffprobe, &output)?;
                let input_stream = &source_probe["streams"][0];
                let output_stream = &output_probe["streams"][0];
                let input_duration = numeric(&source_probe["format"]["duration"])?;
                let output_duration = numeric(&output_probe["format"]["duration"])?;
                let duration_error = symmetric_duration_error(input_duration, output_duration);
                let input_frames = numeric(&input_stream["nb_read_frames"])? as usize;
                let output_frames = numeric(&output_stream["nb_read_frames"])? as usize;
                let dimensions_match = input_stream["width"] == 96
                    && input_stream["height"] == 64
                    && input_stream["width"] == output_stream["width"]
                    && input_stream["height"] == output_stream["height"];
                let metrics = &mut evidence["metrics"];
                metrics["input_dimensions"] =
                    json!([input_stream["width"], input_stream["height"]]);
                metrics["output_dimensions"] =
                    json!([output_stream["width"], output_stream["height"]]);
                metrics["input_duration_seconds"] = json!(input_duration);
                metrics["output_duration_seconds"] = json!(output_duration);
                metrics["duration_relative_error"] = json!(duration_error);
                metrics["input_decoded_frames"] = json!(input_frames);
                metrics["output_decoded_frames"] = json!(output_frames);
                metrics["frame_grid_fps"] = json!(12);
                metrics["expected_compared_frames"] = json!(VIDEO_FRAMES);
                metrics["ssim_min_required"] = json!(0.90);
                if !dimensions_match {
                    return Err("video dimensions do not match the generated 96x64 source".into());
                }
                // The grid and pairing rule are set in advance: 12 fps starting at
                // zero, chronological pairs, all 36 frames, planar YUV 4:2:0.
                successful(
                Command::new(&ffmpeg)
                    .current_dir(temp.path())
                    .args(["-nostdin", "-v", "error", "-xerror", "-i"])
                    .arg(&input)
                    .arg("-i")
                    .arg(&output)
                    .args([
                        "-filter_complex",
                        "[0:v]fps=12,setpts=N/(12*TB),format=yuv420p[ref];[1:v]fps=12,setpts=N/(12*TB),format=yuv420p[out];[ref][out]ssim=stats_file=ssim.log:shortest=1",
                        "-an", "-f", "null", "-",
                    ]),
            )?;
                let stats = std::fs::read_to_string(temp.path().join("ssim.log"))
                    .map_err(|error| error.to_string())?;
                let scores: Vec<f64> = stats
                    .lines()
                    .map(|line| {
                        line.split_whitespace()
                            .find_map(|field| field.strip_prefix("All:"))
                            .and_then(|value| value.parse::<f64>().ok())
                            .filter(|value| value.is_finite())
                            .ok_or_else(|| format!("invalid all-plane SSIM measurement: {line}"))
                    })
                    .collect::<TestResult<_>>()?;
                if scores.is_empty() {
                    return Err("FFmpeg did not emit per-frame SSIM measurements".into());
                }
                let mean_ssim = scores.iter().sum::<f64>() / scores.len() as f64;
                evidence["metrics"]["compared_frames"] = json!(scores.len());
                evidence["metrics"]["ssim_all_frames"] = json!(scores);
                evidence["metrics"]["ssim_mean"] = json!(mean_ssim);
                if input_frames != VIDEO_FRAMES
                    || output_frames != VIDEO_FRAMES
                    || scores.len() != VIDEO_FRAMES
                    || duration_error > 0.02
                    || mean_ssim < 0.90
                {
                    return Err(
                        "generated video did not meet the fixed Table 4.11 thresholds".into(),
                    );
                }
                Ok(())
            },
        );
    }
}
