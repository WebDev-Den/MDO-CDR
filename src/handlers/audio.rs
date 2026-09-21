use std::io::Write;
use std::process::Command;
use std::time::Duration;

use symphonia::core::codecs::DecoderOptions;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;
use symphonia::default::{get_codecs, get_probe};

use crate::{
    DefenderError,
    policy::{AudioKeepOriginalMode, AudioMode, AudioOutputCodec, AudioPolicy, ProbeFailureMode},
    types::{
        DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport, PipelineStageStatus,
    },
};

use super::HandlerResult;

#[derive(Debug, Clone)]
pub struct AudioHandler {
    policy: AudioPolicy,
}

#[derive(Debug, Clone, Copy)]
struct AudioTranscodePlan {
    codec_arg: &'static str,
    mime: &'static str,
    suffix: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct AudioProbeMetrics {
    duration_secs: Option<f64>,
    bitrate_bps: Option<u64>,
    channels: Option<u64>,
}

impl AudioHandler {
    pub fn new(policy: AudioPolicy) -> Self {
        Self { policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        _context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        // A required transcode cannot fall back to preserving the coded stream.
        if self.policy.mode == AudioMode::RequireFfmpeg {
            return self.rebuild_with_ffmpeg(input_bytes, true);
        }
        // Try native (pure-Rust, no-ffmpeg) container sanitization first.
        // This covers MP3, WAV, and FLAC — the three most common formats
        // that can be safely sanitized by stripping metadata at the
        // container level without any codec re-encoding.
        //
        // On mobile (where ffmpeg is never available), this is the ONLY
        // path that produces a real CDR result instead of a block.
        if let Some(native_result) = self.try_native_rebuild(&input_bytes) {
            return native_result.map(|mut result| {
                result.stages.push(PipelineStageReport {
                    stage: PipelineStage::Rebuild,
                    status: PipelineStageStatus::Success,
                    detail: "achieved_reconstruction=structural".to_string(),
                });
                result
            });
        }

        match self.policy.mode {
            AudioMode::RequireFfmpeg => self.rebuild_with_ffmpeg(input_bytes, true),
            AudioMode::BypassWhenUnavailable => self.rebuild_with_ffmpeg(input_bytes, false),
            AudioMode::BlockWhenUnavailable => self.block_if_ffmpeg_missing(input_bytes),
        }
    }

    /// Attempt native container-level CDR for MP3, WAV, and FLAC.
    /// Returns `None` if the format is not recognized natively (fall through
    /// to ffmpeg path). Returns `Some(Ok(...))` on success, `Some(Err(...))`
    /// on structural error in a recognized format.
    fn try_native_rebuild(
        &self,
        input_bytes: &[u8],
    ) -> Option<Result<HandlerResult, DefenderError>> {
        use super::audio_native::{try_sanitize_flac, try_sanitize_mp3, try_sanitize_wav};

        // Try OGG container sanitizer (strips VorbisComment/OpusTags).
        if let Some(ogg_result) = super::ogg_native::try_sanitize_ogg(input_bytes) {
            match ogg_result {
                Ok(native) => {
                    log::info!(
                        "audio native OGG rebuild succeeded: codec={} stripped_bytes={}",
                        native.codec,
                        native.stripped_bytes
                    );
                    let mut alerts = Vec::new();
                    if native.stripped_bytes > 0 {
                        alerts.push(DefenseAlert::info(
                            "audio_ogg_metadata_stripped",
                            format!(
                                "OGG/{} container CDR replaced comment header, stripped {} bytes of metadata.",
                                native.codec, native.stripped_bytes
                            ),
                        ));
                    }
                    let mime = match native.codec {
                        "opus" => "audio/opus",
                        "vorbis" => "audio/ogg",
                        _ => "audio/ogg",
                    };
                    return Some(Ok(HandlerResult {
                        mime: mime.to_string(),
                        output_bytes: native.output_bytes,
                        alerts,
                        stages: vec![PipelineStageReport {
                            stage: PipelineStage::AudioProbe,
                            status: PipelineStageStatus::Success,
                            detail: format!(
                                "native OGG/{} CDR: stripped_bytes={}",
                                native.codec, native.stripped_bytes
                            ),
                        }],
                    }));
                }
                Err(err) => {
                    log::warn!("audio native OGG rebuild failed: {err}");
                    return Some(Err(err));
                }
            }
        }

        // Try MP4/M4A container sanitizer (strips udta/meta atoms).
        if let Some(mp4_result) = super::mp4_native::try_sanitize_mp4(input_bytes) {
            match mp4_result {
                Ok(native) => {
                    log::info!(
                        "audio native MP4/M4A rebuild succeeded: stripped_count={} stripped_bytes={}",
                        native.stripped_count,
                        native.stripped_bytes
                    );
                    let mut alerts = Vec::new();
                    if native.stripped_count > 0 {
                        alerts.push(DefenseAlert::info(
                            "audio_mp4_metadata_stripped",
                            format!(
                                "MP4/M4A container CDR stripped {} metadata atom(s), {} bytes.",
                                native.stripped_count, native.stripped_bytes
                            ),
                        ));
                    }
                    return Some(Ok(HandlerResult {
                        mime: "audio/mp4".to_string(),
                        output_bytes: native.output_bytes,
                        alerts,
                        stages: vec![PipelineStageReport {
                            stage: PipelineStage::AudioProbe,
                            status: PipelineStageStatus::Success,
                            detail: format!(
                                "native MP4/M4A CDR: stripped={}",
                                native.stripped_count
                            ),
                        }],
                    }));
                }
                Err(err) => {
                    log::warn!("audio native MP4/M4A rebuild failed: {err}");
                    return Some(Err(err));
                }
            }
        }

        // Try each simple format in order of likelihood.
        type NativeSanitizer =
            fn(&[u8]) -> Option<Result<super::audio_native::NativeAudioResult, DefenderError>>;
        let sanitizers: &[NativeSanitizer] =
            &[try_sanitize_mp3, try_sanitize_wav, try_sanitize_flac];

        for sanitize in sanitizers {
            if let Some(result) = sanitize(input_bytes) {
                match result {
                    Ok(native) => {
                        log::info!(
                            "audio native rebuild succeeded: mime={} stripped_count={} stripped_bytes={}",
                            native.mime,
                            native.stripped_count,
                            native.stripped_bytes
                        );
                        let mut alerts = Vec::new();
                        if native.stripped_count > 0 {
                            alerts.push(DefenseAlert::info(
                                "audio_metadata_stripped",
                                format!(
                                    "Native audio CDR stripped {} metadata region(s), {} bytes.",
                                    native.stripped_count, native.stripped_bytes
                                ),
                            ));
                        }
                        return Some(Ok(HandlerResult {
                            mime: native.mime.to_string(),
                            output_bytes: native.output_bytes,
                            alerts,
                            stages: vec![PipelineStageReport {
                                stage: PipelineStage::AudioProbe,
                                status: PipelineStageStatus::Success,
                                detail: format!(
                                    "native audio CDR: mime={} stripped={}",
                                    native.mime, native.stripped_count
                                ),
                            }],
                        }));
                    }
                    Err(err) => {
                        log::warn!("audio native rebuild failed: {err}");
                        return Some(Err(err));
                    }
                }
            }
        }
        None // Format not recognized natively.
    }

    fn block_if_ffmpeg_missing(
        &self,
        input_bytes: Vec<u8>,
    ) -> Result<HandlerResult, DefenderError> {
        let ffmpeg_available = crate::process::run_bounded(
            Command::new(&self.policy.ffmpeg_bin).arg("-version"),
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        )
        .is_ok_and(|output| output.status.success());

        if ffmpeg_available {
            return self.rebuild_with_ffmpeg(input_bytes, true);
        }

        Ok(HandlerResult {
            mime: "audio/blocked".to_string(),
            output_bytes: Vec::new(),
            alerts: vec![DefenseAlert::blocking(
                "ffmpeg_missing",
                "ffmpeg is not installed and audio policy is BlockWhenUnavailable",
            )],
            stages: vec![PipelineStageReport {
                stage: PipelineStage::AudioProbe,
                status: PipelineStageStatus::Blocked,
                detail: "audio probe blocked because ffmpeg is missing".to_string(),
            }],
        })
    }

    fn rebuild_with_ffmpeg(
        &self,
        input_bytes: Vec<u8>,
        strict: bool,
    ) -> Result<HandlerResult, DefenderError> {
        if input_bytes.is_empty() {
            return Err(DefenderError::Audio(
                "audio input is empty and cannot be rebuilt".to_string(),
            ));
        }
        let input = tempfile::NamedTempFile::new()?;
        let input_kind = infer::get(&input_bytes);
        let input_mime = input_kind.map(|value| value.mime_type().to_string());
        let output_codec = if self.policy.mode == AudioMode::RequireFfmpeg
            && self.policy.output_codec == AudioOutputCodec::KeepOriginalWhenPossible
        {
            AudioOutputCodec::Mp3
        } else {
            self.policy.output_codec
        };
        let (plan, kept_original) = resolve_transcode_plan(output_codec, input_mime.as_deref());
        let output = tempfile::Builder::new().suffix(plan.suffix).tempfile()?;
        input
            .as_file()
            .write_all(&input_bytes)
            .map_err(DefenderError::from)?;

        let native_probe_failed = if self.policy.mode == AudioMode::RequireFfmpeg {
            // The required decoder also supports codecs absent from Symphonia,
            // such as Opus. This is input probing, not independent validation.
            self.run_audio_probe(input.path()).is_err()
        } else {
            native_decode_probe(&input_bytes).is_err()
        };
        let ffprobe_metrics = self.run_ffprobe_metrics(input.path());

        let mut command = Command::new(&self.policy.ffmpeg_bin);
        command
            .arg("-y")
            .arg("-nostdin")
            .arg("-v")
            .arg("error")
            .args(["-protocol_whitelist", "file,pipe", "-threads", "2"])
            .arg("-i")
            .arg(input.path())
            .args([
                "-map",
                "0:a:0",
                "-map_metadata",
                "-1",
                "-map_chapters",
                "-1",
            ])
            .args(["-vn", "-sn", "-dn", "-threads", "2"]);
        command.arg("-c:a").arg(plan.codec_arg).arg(output.path());

        let mut alerts = Vec::new();
        let mut stages = Vec::new();
        let ffprobe_metrics = match ffprobe_metrics {
            Ok(value) => Some(value),
            Err(value) => {
                match self.policy.probe_failure_mode {
                    ProbeFailureMode::Block => return Err(value),
                    ProbeFailureMode::Warn => {
                        alerts.push(DefenseAlert::warning(
                            "audio_ffprobe_failed",
                            "ffprobe metadata probe failed; proceeding with ffmpeg fallback behavior.",
                        ));
                    }
                }
                None
            }
        };
        if let Some(metrics) = ffprobe_metrics {
            if let Some(duration_secs) = metrics.duration_secs
                && duration_secs > self.policy.max_duration_secs as f64
            {
                return Err(DefenderError::Audio(format!(
                    "audio duration exceeds max_duration_secs: {duration_secs:.3} > {}",
                    self.policy.max_duration_secs
                )));
            }
            if let Some(bitrate_bps) = metrics.bitrate_bps {
                let max_bitrate_bps = self.policy.max_bitrate_kbps.saturating_mul(1000);
                if bitrate_bps > max_bitrate_bps {
                    return Err(DefenderError::Audio(format!(
                        "audio bitrate exceeds max_bitrate_kbps: {bitrate_bps} > {max_bitrate_bps}"
                    )));
                }
            }
            if let Some(channels) = metrics.channels
                && channels > self.policy.max_channels
            {
                return Err(DefenderError::Audio(format!(
                    "audio channels exceed max_channels: {channels} > {}",
                    self.policy.max_channels
                )));
            }
        }
        let native_ok = !native_probe_failed;
        let ffprobe_ok = ffprobe_metrics.is_some();
        if native_ok && ffprobe_ok {
            let Some(metrics) = ffprobe_metrics else {
                return Err(DefenderError::Audio(
                    "audio probe state is inconsistent".to_string(),
                ));
            };
            let duration_label = if let Some(value) = metrics.duration_secs {
                format!("{value:.3}")
            } else {
                "unknown".to_string()
            };
            let bitrate_label = if let Some(value) = metrics.bitrate_bps {
                value.to_string()
            } else {
                "unknown".to_string()
            };
            let channels_label = if let Some(value) = metrics.channels {
                value.to_string()
            } else {
                "unknown".to_string()
            };
            stages.push(PipelineStageReport {
                stage: PipelineStage::AudioProbe,
                status: PipelineStageStatus::Success,
                detail: format!(
                    "audio probe succeeded duration_secs={duration_label} bitrate_bps={bitrate_label} channels={channels_label}"
                ),
            });
        } else {
            if native_probe_failed {
                match self.policy.probe_failure_mode {
                    ProbeFailureMode::Block => {
                        return Err(DefenderError::Audio(
                            "audio decoder probe failed under block mode".to_string(),
                        ));
                    }
                    ProbeFailureMode::Warn => {
                        alerts.push(DefenseAlert::warning(
                            "audio_native_decoder_probe_failed",
                            "Audio decoder probe failed; proceeding with ffmpeg fallback behavior.",
                        ));
                    }
                }
            }
            stages.push(PipelineStageReport {
                stage: PipelineStage::AudioProbe,
                status: PipelineStageStatus::Warning,
                detail: "audio probe warning".to_string(),
            });
        }
        if output_codec == AudioOutputCodec::KeepOriginalWhenPossible && !kept_original {
            match self.policy.keep_original_mode {
                AudioKeepOriginalMode::FallbackToMp3 => {
                    alerts.push(DefenseAlert::warning(
                        "audio_keep_original_fallback",
                        "Could not detect original codec/container reliably; used mp3 fallback.",
                    ));
                }
                AudioKeepOriginalMode::Block => {
                    return Ok(HandlerResult {
                        mime: "audio/blocked".to_string(),
                        output_bytes: Vec::new(),
                        alerts: vec![DefenseAlert::blocking(
                            "audio_keep_original_blocked",
                            "Original audio codec/container cannot be trusted and fallback is blocked by policy.",
                        )],
                        stages,
                    });
                }
            }
        }
        // Start the encoder only after every preflight policy check has passed.
        let command_result = match crate::process::run_bounded(
            &mut command,
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        ) {
            Ok(output) => output,
            Err(error) => {
                if strict {
                    return Err(DefenderError::Audio(format!(
                        "ffmpeg audio execution failed: {error}"
                    )));
                }
                alerts.push(DefenseAlert::warning(
                    "ffmpeg_execution_failed_audio",
                    format!("ffmpeg audio execution failed: {error}"),
                ));
                return Ok(HandlerResult {
                    mime: "audio/raw".to_string(),
                    output_bytes: input_bytes,
                    alerts,
                    stages,
                });
            }
        };

        if !command_result.status.success() {
            if strict {
                let stderr = String::from_utf8_lossy(&command_result.stderr);
                return Err(DefenderError::Audio(format!(
                    "ffmpeg audio encode failed in strict mode: {stderr}"
                )));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_failed_audio",
                "ffmpeg failed; bypassing audio rebuild",
            ));
            return Ok(HandlerResult {
                mime: "audio/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }

        let output_bytes = std::fs::read(output.path())?;
        if output_bytes.is_empty() {
            if strict {
                return Err(DefenderError::Audio(
                    "ffmpeg produced empty audio output in strict mode".to_string(),
                ));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_empty_output_audio",
                "ffmpeg produced empty audio output; bypassing audio rebuild",
            ));
            return Ok(HandlerResult {
                mime: "audio/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        if has_executable_magic(&output_bytes) {
            if strict {
                return Err(DefenderError::Audio(
                    "ffmpeg audio output looks like executable payload".to_string(),
                ));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_executable_magic_audio",
                "ffmpeg audio output has executable signature; bypassing audio rebuild",
            ));
            return Ok(HandlerResult {
                mime: "audio/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        let sniffed = infer::get(&output_bytes).map(|value| value.mime_type().to_string());
        if let Some(sniffed_mime) = sniffed {
            if !is_audio_mime(&sniffed_mime) {
                if strict {
                    return Err(DefenderError::Audio(format!(
                        "ffmpeg audio output has non-audio mime: {sniffed_mime}"
                    )));
                }
                alerts.push(DefenseAlert::warning(
                    "ffmpeg_non_audio_mime_audio",
                    "ffmpeg output mime is not audio; bypassing audio rebuild",
                ));
                return Ok(HandlerResult {
                    mime: "audio/raw".to_string(),
                    output_bytes: input_bytes,
                    alerts,
                    stages,
                });
            }
            let output_canonical = canonical_audio_mime(&sniffed_mime);
            let declared_canonical = canonical_audio_mime(plan.mime);
            if output_canonical != declared_canonical {
                if strict {
                    return Err(DefenderError::Audio(format!(
                        "ffmpeg output mime mismatch: sniffed={sniffed_mime}, declared={}",
                        plan.mime
                    )));
                }
                alerts.push(DefenseAlert::warning(
                    "ffmpeg_audio_mime_mismatch",
                    "ffmpeg output mime does not match declared codec plan; bypassing audio rebuild",
                ));
                return Ok(HandlerResult {
                    mime: "audio/raw".to_string(),
                    output_bytes: input_bytes,
                    alerts,
                    stages,
                });
            }
            if kept_original {
                let Some(input_mime) = input_mime.as_deref() else {
                    return Ok(HandlerResult {
                        mime: plan.mime.to_string(),
                        output_bytes,
                        alerts,
                        stages,
                    });
                };
                let input_canonical = canonical_audio_mime(input_mime);
                if input_canonical != output_canonical {
                    if strict {
                        return Err(DefenderError::Audio(format!(
                            "keep-original mime mismatch: input={input_mime}, output={sniffed_mime}"
                        )));
                    }
                    alerts.push(DefenseAlert::warning(
                        "audio_keep_original_mime_mismatch",
                        "keep-original output mime does not match input mime; bypassing audio rebuild",
                    ));
                    return Ok(HandlerResult {
                        mime: "audio/raw".to_string(),
                        output_bytes: input_bytes,
                        alerts,
                        stages,
                    });
                }
            }
        } else if strict {
            return Err(DefenderError::Audio(
                "ffmpeg output mime is unknown for audio payload".to_string(),
            ));
        } else {
            alerts.push(DefenseAlert::warning(
                "ffmpeg_unknown_mime_audio",
                "ffmpeg output mime is unknown; bypassing audio rebuild",
            ));
            return Ok(HandlerResult {
                mime: "audio/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::Rebuild,
            status: PipelineStageStatus::Success,
            detail: if plan.codec_arg == "copy" {
                "achieved_reconstruction=structural".to_string()
            } else {
                "achieved_reconstruction=semantic".to_string()
            },
        });
        Ok(HandlerResult {
            mime: plan.mime.to_string(),
            output_bytes,
            alerts,
            stages,
        })
    }

    fn run_audio_probe(&self, input_path: &std::path::Path) -> Result<(), DefenderError> {
        let output = crate::process::run_bounded(
            Command::new(&self.policy.ffmpeg_bin)
                .args([
                    "-v",
                    "error",
                    "-nostdin",
                    "-protocol_whitelist",
                    "file,pipe",
                ])
                .args(["-threads", "2", "-i"])
                .arg(input_path)
                .args(["-map", "0:a:0", "-vn", "-sn", "-dn", "-f", "null", "-"]),
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        )
        .map_err(|error| DefenderError::Audio(format!("audio probe execution failed: {error}")))?;
        if !output.status.success() {
            return Err(DefenderError::Audio(format!(
                "audio probe decode failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    fn run_ffprobe_metrics(
        &self,
        input_path: &std::path::Path,
    ) -> Result<AudioProbeMetrics, DefenderError> {
        let output = crate::process::run_bounded(
            Command::new(&self.policy.ffprobe_bin)
                .args(["-protocol_whitelist", "file,pipe", "-threads", "2"])
                .arg("-v")
                .arg("error")
                .arg("-select_streams")
                .arg("a:0")
                .arg("-show_entries")
                .arg("stream=channels,bit_rate:format=duration,bit_rate")
                .arg("-of")
                .arg("default=noprint_wrappers=1:nokey=0")
                .arg(input_path),
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        )
        .map_err(|value| DefenderError::Audio(format!("ffprobe execution failed: {value}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DefenderError::Audio(format!(
                "ffprobe exited with error: {stderr}"
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_audio_probe_metrics(stdout.as_ref())
    }
}

fn native_decode_probe(input_bytes: &[u8]) -> Result<(), DefenderError> {
    let source = std::io::Cursor::new(input_bytes.to_vec());
    let stream = MediaSourceStream::new(Box::new(source), Default::default());
    let hint = Hint::new();
    let format_options = FormatOptions::default();
    let metadata_options = MetadataOptions::default();

    let probed = get_probe().format(&hint, stream, &format_options, &metadata_options);
    let probed = match probed {
        Ok(value) => value,
        Err(value) => {
            return Err(DefenderError::Audio(format!(
                "native probe failed: {value}"
            )));
        }
    };

    let mut format = probed.format;
    let track = format.default_track();
    let track = match track {
        Some(value) => value,
        None => {
            return Err(DefenderError::Audio(
                "no default audio track found".to_string(),
            ));
        }
    };
    let track_id = track.id;
    let decoder_options = DecoderOptions::default();
    let decoder = get_codecs().make(&track.codec_params, &decoder_options);
    let mut decoder = match decoder {
        Ok(value) => value,
        Err(value) => {
            return Err(DefenderError::Audio(format!(
                "native decoder init failed: {value}"
            )));
        }
    };

    let mut decoded_any = false;
    for _ in 0..64 {
        let packet = format.next_packet();
        let packet = match packet {
            Ok(value) => value,
            Err(SymphoniaError::IoError(_)) => break,
            Err(SymphoniaError::ResetRequired) => break,
            Err(value) => {
                return Err(DefenderError::Audio(format!(
                    "native packet read failed: {value}"
                )));
            }
        };
        if packet.track_id() != track_id {
            continue;
        }

        let decoded = decoder.decode(&packet);
        match decoded {
            Ok(_) => {
                decoded_any = true;
                break;
            }
            Err(SymphoniaError::DecodeError(_)) => continue,
            Err(SymphoniaError::IoError(_)) => break,
            Err(value) => {
                return Err(DefenderError::Audio(format!(
                    "native decode failed: {value}"
                )));
            }
        }
    }

    if decoded_any {
        return Ok(());
    }
    Err(DefenderError::Audio(
        "native decode produced no audio frames".to_string(),
    ))
}

fn resolve_transcode_plan(
    output_codec: AudioOutputCodec,
    input_mime: Option<&str>,
) -> (AudioTranscodePlan, bool) {
    match output_codec {
        AudioOutputCodec::KeepOriginalWhenPossible => match input_mime {
            Some("audio/mpeg") => (
                AudioTranscodePlan {
                    codec_arg: "copy",
                    mime: "audio/mpeg",
                    suffix: ".mp3",
                },
                true,
            ),
            Some("audio/aac") => (
                AudioTranscodePlan {
                    codec_arg: "copy",
                    mime: "audio/aac",
                    suffix: ".aac",
                },
                true,
            ),
            Some("audio/flac") => (
                AudioTranscodePlan {
                    codec_arg: "copy",
                    mime: "audio/flac",
                    suffix: ".flac",
                },
                true,
            ),
            Some("audio/wav") => (
                AudioTranscodePlan {
                    codec_arg: "copy",
                    mime: "audio/wav",
                    suffix: ".wav",
                },
                true,
            ),
            Some("audio/ogg") | Some("audio/opus") => (
                AudioTranscodePlan {
                    codec_arg: "copy",
                    mime: "audio/opus",
                    suffix: ".opus",
                },
                true,
            ),
            _ => (
                AudioTranscodePlan {
                    codec_arg: "libmp3lame",
                    mime: "audio/mpeg",
                    suffix: ".mp3",
                },
                false,
            ),
        },
        AudioOutputCodec::Mp3 => (
            AudioTranscodePlan {
                codec_arg: "libmp3lame",
                mime: "audio/mpeg",
                suffix: ".mp3",
            },
            false,
        ),
        AudioOutputCodec::Aac => (
            AudioTranscodePlan {
                codec_arg: "aac",
                mime: "audio/aac",
                suffix: ".aac",
            },
            false,
        ),
        AudioOutputCodec::Opus => (
            AudioTranscodePlan {
                codec_arg: "libopus",
                mime: "audio/opus",
                suffix: ".opus",
            },
            false,
        ),
        AudioOutputCodec::Flac => (
            AudioTranscodePlan {
                codec_arg: "flac",
                mime: "audio/flac",
                suffix: ".flac",
            },
            false,
        ),
        AudioOutputCodec::Wav => (
            AudioTranscodePlan {
                codec_arg: "pcm_s16le",
                mime: "audio/wav",
                suffix: ".wav",
            },
            false,
        ),
    }
}

fn is_audio_mime(mime: &str) -> bool {
    if mime == "audio/mpeg" {
        return true;
    }
    if mime == "audio/aac" {
        return true;
    }
    if mime == "audio/opus" {
        return true;
    }
    if mime == "audio/flac" {
        return true;
    }
    if mime == "audio/wav" {
        return true;
    }
    if mime == "audio/x-wav" {
        return true;
    }
    if mime == "audio/ogg" {
        return true;
    }
    false
}

fn canonical_audio_mime(mime: &str) -> &'static str {
    match mime {
        "audio/ogg" | "audio/opus" => "audio/opus",
        "audio/x-wav" | "audio/wav" => "audio/wav",
        "audio/mpeg" => "audio/mpeg",
        "audio/aac" => "audio/aac",
        "audio/flac" => "audio/flac",
        _ => "audio/unknown",
    }
}

fn has_executable_magic(bytes: &[u8]) -> bool {
    if bytes.len() >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A {
        return true;
    }
    if bytes.len() >= 4
        && bytes[0] == 0x7F
        && bytes[1] == 0x45
        && bytes[2] == 0x4C
        && bytes[3] == 0x46
    {
        return true;
    }
    if bytes.len() >= 4
        && bytes[0] == 0xFE
        && bytes[1] == 0xED
        && bytes[2] == 0xFA
        && bytes[3] == 0xCE
    {
        return true;
    }
    if bytes.len() >= 4
        && bytes[0] == 0xFE
        && bytes[1] == 0xED
        && bytes[2] == 0xFA
        && bytes[3] == 0xCF
    {
        return true;
    }
    if bytes.len() >= 4
        && bytes[0] == 0xCE
        && bytes[1] == 0xFA
        && bytes[2] == 0xED
        && bytes[3] == 0xFE
    {
        return true;
    }
    if bytes.len() >= 4
        && bytes[0] == 0xCF
        && bytes[1] == 0xFA
        && bytes[2] == 0xED
        && bytes[3] == 0xFE
    {
        return true;
    }
    false
}

fn parse_audio_probe_metrics(raw: &str) -> Result<AudioProbeMetrics, DefenderError> {
    let mut duration_secs = None;
    let mut bitrate_bps = None;
    let mut channels = None;
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut split = line.splitn(2, '=');
        let Some(key) = split.next() else {
            continue;
        };
        let Some(value) = split.next() else {
            continue;
        };
        if key == "duration" {
            if let Ok(parsed) = value.parse::<f64>() {
                duration_secs = Some(parsed);
            }
            continue;
        }
        if key == "bit_rate" {
            if let Ok(parsed) = value.parse::<u64>() {
                bitrate_bps = match bitrate_bps {
                    Some(existing) if existing >= parsed => Some(existing),
                    _ => Some(parsed),
                };
            }
            continue;
        }
        if key == "channels" {
            if let Ok(parsed) = value.parse::<u64>() {
                channels = Some(parsed);
            }
            continue;
        }
    }
    if duration_secs.is_none() && bitrate_bps.is_none() && channels.is_none() {
        return Err(DefenderError::Audio(
            "ffprobe returned no usable audio metrics".to_string(),
        ));
    }
    Ok(AudioProbeMetrics {
        duration_secs,
        bitrate_bps,
        channels,
    })
}

#[cfg(test)]
mod tests {
    use crate::policy::AudioOutputCodec;

    use super::{
        canonical_audio_mime, has_executable_magic, is_audio_mime, parse_audio_probe_metrics,
        resolve_transcode_plan,
    };

    #[test]
    fn keep_original_uses_copy_for_mp3() {
        let (plan, kept) = resolve_transcode_plan(
            AudioOutputCodec::KeepOriginalWhenPossible,
            Some("audio/mpeg"),
        );
        assert!(kept);
        assert_eq!(plan.codec_arg, "copy");
        assert_eq!(plan.suffix, ".mp3");
    }

    #[test]
    fn keep_original_falls_back_for_unknown() {
        let (plan, kept) = resolve_transcode_plan(
            AudioOutputCodec::KeepOriginalWhenPossible,
            Some("application/octet-stream"),
        );
        assert!(!kept);
        assert_eq!(plan.codec_arg, "libmp3lame");
        assert_eq!(plan.suffix, ".mp3");
    }

    #[test]
    fn canonicalizes_audio_mime_aliases() {
        assert_eq!(canonical_audio_mime("audio/ogg"), "audio/opus");
        assert_eq!(canonical_audio_mime("audio/opus"), "audio/opus");
        assert_eq!(canonical_audio_mime("audio/x-wav"), "audio/wav");
    }

    #[test]
    fn recognizes_allowed_audio_mimes() {
        assert!(is_audio_mime("audio/mpeg"));
        assert!(is_audio_mime("audio/x-wav"));
        assert!(!is_audio_mime("application/octet-stream"));
    }

    #[test]
    fn recognizes_executable_magic() {
        let bytes = vec![0x7F, 0x45, 0x4C, 0x46];
        assert!(has_executable_magic(&bytes));
    }

    #[test]
    fn parses_audio_probe_metrics() {
        let raw = "duration=33.2\nbit_rate=192000\nchannels=2\n";
        let metrics = parse_audio_probe_metrics(raw).expect("metrics must parse");
        assert_eq!(metrics.duration_secs, Some(33.2));
        assert_eq!(metrics.bitrate_bps, Some(192000));
        assert_eq!(metrics.channels, Some(2));
    }
}
