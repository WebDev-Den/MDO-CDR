//! Read the completed candidate from a fresh decoder before allowing release.
//! This is a separate procedure, not a claim of decoder implementation diversity.

use std::io::{Cursor, Write};

use image::{AnimationDecoder, ImageDecoder, ImageReader};

use crate::{
    DefenseAlert, DefenseContext, FileKind, PipelineStage, PipelineStageReport,
    PipelineStageStatus, policy::DefensePolicy,
};

pub(crate) fn verify_output(
    kind: FileKind,
    bytes: &[u8],
    policy: &DefensePolicy,
    context: &DefenseContext,
) -> (PipelineStageReport, Option<DefenseAlert>) {
    let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        context.check_limits().map_err(|error| error.to_string())?;
        match kind {
            FileKind::Image => verify_image(bytes, policy, context),
            FileKind::Gif | FileKind::AnimatedImage => {
                verify_animation(kind, bytes, policy, context)
            }
            FileKind::Audio => verify_audio(bytes, policy, context),
            FileKind::Video => verify_video(bytes, policy, context),
            FileKind::Other => {
                Err("No full output reader is implemented for this object type".into())
            }
        }
    }))
    .unwrap_or_else(|_| Err("Output reader panicked".into()));

    match verified {
        Ok(detail) => (
            PipelineStageReport {
                stage: PipelineStage::OutputValidation,
                status: PipelineStageStatus::Success,
                detail: format!("independent_read: {detail}"),
            },
            None,
        ),
        Err(detail) => {
            // Unsupported types and missing external decoders cannot pass this gate.
            let alert = DefenseAlert::blocking("output_read_failed", detail.clone());
            (
                PipelineStageReport {
                    stage: PipelineStage::OutputValidation,
                    status: PipelineStageStatus::Blocked,
                    detail: format!("independent_read_failed: {detail}"),
                },
                Some(alert),
            )
        }
    }
}

fn image_limits(max_pixels: u64) -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(max_pixels.saturating_mul(16));
    limits
}

fn check_pixels(width: u32, height: u32, max_pixels: u64) -> Result<u64, String> {
    let pixels = u64::from(width) * u64::from(height);
    if pixels == 0 || pixels > max_pixels {
        return Err(format!(
            "Output dimensions exceed the pixel budget: {width}x{height}"
        ));
    }
    Ok(pixels)
}

fn verify_image(
    bytes: &[u8],
    policy: &DefensePolicy,
    context: &DefenseContext,
) -> Result<String, String> {
    let probe = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let (width, height) = probe.into_dimensions().map_err(|error| error.to_string())?;
    check_pixels(width, height, policy.image.max_pixels)?;
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    reader.limits(image_limits(policy.image.max_pixels));
    let decoded = reader.decode().map_err(|error| error.to_string())?;
    if (decoded.width(), decoded.height()) != (width, height) {
        return Err("Output dimensions changed during decoding".into());
    }
    context.check_limits().map_err(|error| error.to_string())?;
    Ok(format!("image decoded completely, {width}x{height}"))
}

fn verify_animation(
    kind: FileKind,
    bytes: &[u8],
    policy: &DefensePolicy,
    context: &DefenseContext,
) -> Result<String, String> {
    let (max_frames, max_pixels, max_total_pixels) = if kind == FileKind::Gif {
        (
            policy.gif.max_frames as u64,
            policy.gif.max_pixels_per_frame,
            (policy.gif.max_frames as u64).saturating_mul(policy.gif.max_pixels_per_frame),
        )
    } else {
        (
            u64::from(policy.animated_image.max_frames),
            policy.animated_image.max_pixels_per_frame,
            policy.animated_image.max_total_pixels,
        )
    };
    let frames = if kind == FileKind::Gif {
        let mut decoder = image::codecs::gif::GifDecoder::new(Cursor::new(bytes))
            .map_err(|error| error.to_string())?;
        let (width, height) = decoder.dimensions();
        check_pixels(width, height, max_pixels)?;
        decoder
            .set_limits(image_limits(max_pixels))
            .map_err(|error| error.to_string())?;
        decoder.into_frames()
    } else {
        let mut decoder = image::codecs::png::PngDecoder::new(Cursor::new(bytes))
            .map_err(|error| error.to_string())?;
        let (width, height) = decoder.dimensions();
        check_pixels(width, height, max_pixels)?;
        decoder
            .set_limits(image_limits(max_pixels))
            .map_err(|error| error.to_string())?;
        decoder
            .apng()
            .map_err(|error| error.to_string())?
            .into_frames()
    };
    let mut count = 0u64;
    let mut total_pixels = 0u64;
    for frame in frames {
        context.check_limits().map_err(|error| error.to_string())?;
        count += 1;
        if count > max_frames {
            return Err("Output animation exceeds the frame budget".into());
        }
        let frame = frame.map_err(|error| error.to_string())?;
        let pixels = check_pixels(frame.buffer().width(), frame.buffer().height(), max_pixels)?;
        total_pixels = total_pixels.saturating_add(pixels);
        if total_pixels > max_total_pixels {
            return Err("Output animation exceeds the aggregate pixel budget".into());
        }
    }
    if count == 0 {
        return Err("Output animation contains no readable frames".into());
    }
    Ok(format!("all {count} animation frames decoded"))
}

fn verify_audio(
    bytes: &[u8],
    policy: &DefensePolicy,
    context: &DefenseContext,
) -> Result<String, String> {
    use symphonia::core::{
        codecs::DecoderOptions, errors::Error, formats::FormatOptions, io::MediaSourceStream,
        meta::MetadataOptions, probe::Hint,
    };
    let source = MediaSourceStream::new(Box::new(Cursor::new(bytes.to_vec())), Default::default());
    let mut reader = symphonia::default::get_probe()
        .format(
            &Hint::new(),
            source,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|error| error.to_string())?
        .format;
    // One audio stream is the release contract. Extra streams must not escape
    // examination through a default-track-only probe.
    if reader.tracks().len() != 1 {
        return Err("Output must contain exactly one supported audio track".into());
    }
    let track = &reader.tracks()[0];
    let track_id = track.id;
    let expected_frames = track.codec_params.n_frames;
    let sample_rate = track.codec_params.sample_rate;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions { verify: true })
        .map_err(|error| error.to_string())?;
    let mut sample_frames = 0u64;
    let mut packets = 0u64;
    loop {
        context.check_limits().map_err(|error| error.to_string())?;
        let packet = match reader.next_packet() {
            Ok(packet) => packet,
            Err(Error::IoError(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(error) => return Err(error.to_string()),
        };
        if packet.track_id() != track_id {
            return Err("Unexamined output audio track encountered".into());
        }
        let audio = decoder.decode(&packet).map_err(|error| error.to_string())?;
        if audio.spec().channels.count() > policy.audio.max_channels as usize {
            return Err("Output audio channel limit exceeded".into());
        }
        sample_frames = sample_frames.saturating_add(audio.frames() as u64);
        packets += 1;
        let max_frames =
            u64::from(audio.spec().rate).saturating_mul(policy.audio.max_duration_secs);
        if sample_frames > max_frames {
            return Err("Output audio duration limit exceeded".into());
        }
    }
    if packets == 0 || sample_frames == 0 {
        return Err("Output contains no decoded audio samples".into());
    }
    // Sample counts in compressed streams may include codec priming/padding;
    // do not treat their container timestamp units as PCM sample counts.
    if sample_rate.is_some()
        && matches!(
            infer::get(bytes).map(|t| t.mime_type()),
            Some("audio/x-wav" | "audio/wav")
        )
        && expected_frames.is_some_and(|expected| sample_frames < expected)
    {
        return Err("Output PCM payload is truncated".into());
    }
    if decoder.finalize().verify_ok == Some(false) {
        return Err("Output audio checksum verification failed".into());
    }
    Ok(format!(
        "all {packets} audio packets decoded, {sample_frames} sample frames"
    ))
}

fn verify_video(
    bytes: &[u8],
    policy: &DefensePolicy,
    context: &DefenseContext,
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let mut input = tempfile::Builder::new()
        .suffix(".mp4")
        .tempfile()
        .map_err(|error| error.to_string())?;
    input.write_all(bytes).map_err(|error| error.to_string())?;
    let mut command = Command::new(&policy.video.ffmpeg_bin);
    command
        .args([
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-abort_on",
            "empty_output",
            "-err_detect",
            "explode",
            "-protocol_whitelist",
            "file,pipe",
            "-threads",
            "2",
            "-i",
        ])
        .arg(input.path())
        .args([
            "-map", "0:v", "-map", "0:a?", "-threads", "2", "-f", "null", "-",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("Output video reader unavailable: {error}"))?;
    let started = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(policy.video.ffmpeg_timeout_secs.max(1));
    loop {
        let limit_error = context.check_limits().err();
        if limit_error.is_some() || started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(limit_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "Output video read timed out".into()));
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                return Ok(
                    "video and audio streams decoded completely by a separate FFmpeg invocation"
                        .into(),
                );
            }
            Ok(Some(_)) => return Err("Output video failed complete FFmpeg decoding".into()),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav(samples: usize) -> Vec<u8> {
        let payload_size = (samples * 2) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"RIFF");
        bytes.extend_from_slice(&(36 + payload_size).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt ");
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&8_000u32.to_le_bytes());
        bytes.extend_from_slice(&16_000u32.to_le_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(b"data");
        bytes.extend_from_slice(&payload_size.to_le_bytes());
        bytes.resize(44 + payload_size as usize, 0);
        bytes
    }

    #[test]
    fn audio_reader_checks_packets_after_the_first_successful_decode() {
        let bytes = wav(10_000);
        assert!(
            verify_audio(
                &bytes,
                &DefensePolicy::default(),
                &DefenseContext::default()
            )
            .is_ok()
        );
        let truncated = &bytes[..bytes.len() - 200];
        assert!(
            verify_audio(
                truncated,
                &DefensePolicy::default(),
                &DefenseContext::default()
            )
            .is_err()
        );
    }

    #[test]
    fn gif_reader_checks_the_second_frame_payload() {
        let mut bytes = Vec::new();
        {
            let mut encoder =
                gif::Encoder::new(&mut bytes, 2, 2, &[0, 0, 0, 255, 255, 255]).unwrap();
            let frame = gif::Frame {
                width: 2,
                height: 2,
                delay: 5,
                buffer: vec![0, 1, 0, 1].into(),
                ..Default::default()
            };
            encoder.write_frame(&frame).unwrap();
            encoder.write_frame(&frame).unwrap();
        }
        assert!(
            verify_animation(
                FileKind::Gif,
                &bytes,
                &DefensePolicy::default(),
                &DefenseContext::default()
            )
            .is_ok()
        );
        bytes.truncate(bytes.len() - 5);
        assert!(
            verify_animation(
                FileKind::Gif,
                &bytes,
                &DefensePolicy::default(),
                &DefenseContext::default()
            )
            .is_err()
        );
    }

    #[test]
    fn output_read_cannot_be_disabled_with_signature_policy_flags() {
        let policy = DefensePolicy {
            enforce_output_kind_match: false,
            ..Default::default()
        };
        let (stage, alert) = verify_output(
            FileKind::Image,
            b"\x89PNG\r\n\x1a\n",
            &policy,
            &DefenseContext::default(),
        );
        assert_eq!(stage.status, PipelineStageStatus::Blocked);
        assert_eq!(alert.unwrap().code, "output_read_failed");
    }

    #[test]
    fn cancellation_prevents_output_read_success() {
        let cancel = crate::CancellationToken::new();
        cancel.cancel();
        let context = DefenseContext {
            cancel: Some(cancel),
            ..Default::default()
        };
        let (stage, _) = verify_output(
            FileKind::Audio,
            &wav(80),
            &DefensePolicy::default(),
            &context,
        );
        assert_eq!(stage.status, PipelineStageStatus::Blocked);
    }
}
