use std::io::Write;
use std::process::Command;
use std::time::Duration;

use crate::{
    DefenderError,
    policy::{ProbeFailureMode, VideoMode, VideoPolicy},
    types::{
        DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport, PipelineStageStatus,
    },
};

use super::HandlerResult;

#[derive(Debug, Clone)]
pub struct VideoHandler {
    policy: VideoPolicy,
}

#[derive(Debug, Clone, Copy)]
struct VideoProbeMetrics {
    duration_secs: Option<f64>,
    bitrate_bps: Option<u64>,
}

impl VideoHandler {
    pub fn new(policy: VideoPolicy) -> Self {
        Self { policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        _context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        // A required transcode cannot be satisfied by a native container rewrite.
        if self.policy.mode == VideoMode::RequireFfmpeg {
            return self.rebuild_with_ffmpeg(input_bytes, true);
        }
        // Try native MP4 container sanitization first (strips metadata
        // atoms, preserves codec bitstream). Works on mobile without ffmpeg.
        if let Some(mp4_result) = super::mp4_native::try_sanitize_mp4(&input_bytes) {
            match mp4_result {
                Ok(native) => {
                    log::info!(
                        "video native MP4 rebuild succeeded: stripped_count={} stripped_bytes={}",
                        native.stripped_count,
                        native.stripped_bytes
                    );
                    let mut alerts = Vec::new();
                    if native.stripped_count > 0 {
                        alerts.push(DefenseAlert::info(
                            "video_mp4_metadata_stripped",
                            format!(
                                "MP4 container CDR stripped {} metadata atom(s), {} bytes. \
                                 Codec bitstream preserved.",
                                native.stripped_count, native.stripped_bytes
                            ),
                        ));
                    }
                    return Ok(HandlerResult {
                        mime: "video/mp4".to_string(),
                        output_bytes: native.output_bytes,
                        alerts,
                        stages: vec![
                            PipelineStageReport {
                                stage: PipelineStage::VideoProbe,
                                status: PipelineStageStatus::Success,
                                detail: format!(
                                    "native MP4 CDR: stripped={}",
                                    native.stripped_count
                                ),
                            },
                            PipelineStageReport {
                                stage: PipelineStage::Rebuild,
                                status: PipelineStageStatus::Success,
                                detail: "achieved_reconstruction=structural".to_string(),
                            },
                        ],
                    });
                }
                Err(err) => {
                    log::warn!("video native MP4 rebuild failed: {err}");
                    return Err(err);
                }
            }
        }

        // Try native WebM/Matroska container sanitization (strips Tags,
        // Attachments, Chapters; preserves Clusters with codec bitstream).
        if let Some(webm_result) = super::webm_native::try_sanitize_webm(&input_bytes) {
            match webm_result {
                Ok(native) => {
                    log::info!(
                        "video native WebM rebuild succeeded: stripped_count={} stripped_bytes={}",
                        native.stripped_count,
                        native.stripped_bytes
                    );
                    let mut alerts = Vec::new();
                    if native.stripped_count > 0 {
                        alerts.push(DefenseAlert::info(
                            "video_webm_metadata_stripped",
                            format!(
                                "WebM container CDR stripped {} metadata element(s), {} bytes. \
                                 Codec bitstream preserved.",
                                native.stripped_count, native.stripped_bytes
                            ),
                        ));
                    }
                    return Ok(HandlerResult {
                        mime: "video/webm".to_string(),
                        output_bytes: native.output_bytes,
                        alerts,
                        stages: vec![
                            PipelineStageReport {
                                stage: PipelineStage::VideoProbe,
                                status: PipelineStageStatus::Success,
                                detail: format!(
                                    "native WebM CDR: stripped={}",
                                    native.stripped_count
                                ),
                            },
                            PipelineStageReport {
                                stage: PipelineStage::Rebuild,
                                status: PipelineStageStatus::Success,
                                detail: "achieved_reconstruction=structural".to_string(),
                            },
                        ],
                    });
                }
                Err(err) => {
                    log::warn!("video native WebM rebuild failed: {err}");
                    return Err(err);
                }
            }
        }

        // Non-MP4/non-WebM video (AVI, MOV with non-BMFF structure) falls
        // through to ffmpeg path.
        match self.policy.mode {
            VideoMode::RequireFfmpeg => self.rebuild_with_ffmpeg(input_bytes, true),
            VideoMode::BypassWhenUnavailable => self.rebuild_with_ffmpeg(input_bytes, false),
            VideoMode::BlockWhenUnavailable => self.block_if_ffmpeg_missing(input_bytes),
        }
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
            mime: "video/blocked".to_string(),
            output_bytes: Vec::new(),
            alerts: vec![DefenseAlert::blocking(
                "ffmpeg_missing",
                "ffmpeg is not installed and policy is BlockWhenUnavailable",
            )],
            stages: vec![PipelineStageReport {
                stage: PipelineStage::VideoProbe,
                status: PipelineStageStatus::Blocked,
                detail: "video probe blocked because ffmpeg is missing".to_string(),
            }],
        })
    }

    fn rebuild_with_ffmpeg(
        &self,
        input_bytes: Vec<u8>,
        strict: bool,
    ) -> Result<HandlerResult, DefenderError> {
        if input_bytes.is_empty() {
            return Err(DefenderError::Video(
                "video input is empty and cannot be rebuilt".to_string(),
            ));
        }
        let input = tempfile::NamedTempFile::new()?;
        let output = tempfile::Builder::new().suffix(".mp4").tempfile()?;

        input
            .as_file()
            .write_all(&input_bytes)
            .map_err(DefenderError::from)?;

        let video_probe = self.run_video_probe(input.path());
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
            .args(["-map", "0:v:0", "-map", "0:a:0?"])
            .args(["-map_metadata", "-1", "-map_chapters", "-1", "-sn", "-dn"])
            .args(["-threads", "2", "-filter_threads", "2"])
            .arg("-c:v")
            .arg("libx264")
            .arg("-c:a")
            .arg("aac")
            .arg("-movflags")
            .arg("+faststart")
            .arg(output.path());

        let mut alerts = Vec::new();
        let mut stages = Vec::new();
        let metrics = match ffprobe_metrics {
            Ok(value) => Some(value),
            Err(value) => {
                match self.policy.probe_failure_mode {
                    ProbeFailureMode::Block => return Err(value),
                    ProbeFailureMode::Warn => {
                        alerts.push(DefenseAlert::warning(
                            "video_ffprobe_failed",
                            "ffprobe metadata probe failed; continuing with ffmpeg transcode policy.",
                        ));
                    }
                }
                None
            }
        };
        if let Some(metrics) = metrics {
            if let Some(duration_secs) = metrics.duration_secs
                && duration_secs > self.policy.max_duration_secs as f64
            {
                return Err(DefenderError::Video(format!(
                    "video duration exceeds max_duration_secs: {duration_secs:.3} > {}",
                    self.policy.max_duration_secs
                )));
            }
            if let Some(bitrate_bps) = metrics.bitrate_bps {
                let max_bitrate_bps = self.policy.max_bitrate_kbps.saturating_mul(1000);
                if bitrate_bps > max_bitrate_bps {
                    return Err(DefenderError::Video(format!(
                        "video bitrate exceeds max_bitrate_kbps: {bitrate_bps} > {max_bitrate_bps}"
                    )));
                }
            }
        }
        let video_probe_ok = video_probe.is_ok();
        let ffprobe_ok = metrics.is_some();
        if video_probe_ok && ffprobe_ok {
            let Some(metrics) = metrics else {
                return Err(DefenderError::Video(
                    "video probe state is inconsistent".to_string(),
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
            stages.push(PipelineStageReport {
                stage: PipelineStage::VideoProbe,
                status: PipelineStageStatus::Success,
                detail: format!(
                    "video probe succeeded duration_secs={duration_label} bitrate_bps={bitrate_label}"
                ),
            });
        } else {
            if !video_probe_ok {
                match self.policy.probe_failure_mode {
                    ProbeFailureMode::Block => {
                        return Err(DefenderError::Video(
                            "native video probe failed under block mode".to_string(),
                        ));
                    }
                    ProbeFailureMode::Warn => {
                        alerts.push(DefenseAlert::warning(
                            "video_native_probe_failed",
                            "Native video probe failed; continuing with ffmpeg transcode policy.",
                        ));
                    }
                }
            }
            stages.push(PipelineStageReport {
                stage: PipelineStage::VideoProbe,
                status: PipelineStageStatus::Warning,
                detail: "video probe warning".to_string(),
            });
        }
        // Start the encoder only after every preflight policy check has passed.
        let command_result = match crate::process::run_bounded(
            &mut command,
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        ) {
            Ok(output) => output,
            Err(error) => {
                if strict {
                    return Err(DefenderError::Video(format!(
                        "ffmpeg video execution failed: {error}"
                    )));
                }
                alerts.push(DefenseAlert::warning(
                    "ffmpeg_execution_failed_video",
                    format!("ffmpeg video execution failed: {error}"),
                ));
                return Ok(HandlerResult {
                    mime: "video/raw".to_string(),
                    output_bytes: input_bytes,
                    alerts,
                    stages,
                });
            }
        };

        if !command_result.status.success() {
            if strict {
                let stderr = String::from_utf8_lossy(&command_result.stderr);
                return Err(DefenderError::Video(format!(
                    "ffmpeg failed in strict mode: {stderr}"
                )));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_failed",
                "ffmpeg failed; bypassing video rebuild",
            ));
            return Ok(HandlerResult {
                mime: "video/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }

        let output_bytes = std::fs::read(output.path())?;
        if output_bytes.is_empty() {
            if strict {
                return Err(DefenderError::Video(
                    "ffmpeg produced empty output in strict mode".to_string(),
                ));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_empty_output",
                "ffmpeg produced empty output; bypassing video rebuild",
            ));
            return Ok(HandlerResult {
                mime: "video/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        if !looks_like_mp4_container(&output_bytes) {
            if strict {
                return Err(DefenderError::Video(
                    "ffmpeg output does not look like a valid mp4 container".to_string(),
                ));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_invalid_container_video",
                "ffmpeg output failed mp4 container sanity check; bypassing video rebuild",
            ));
            return Ok(HandlerResult {
                mime: "video/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        if has_executable_magic(&output_bytes) {
            if strict {
                return Err(DefenderError::Video(
                    "ffmpeg output looks like executable payload".to_string(),
                ));
            }
            alerts.push(DefenseAlert::warning(
                "ffmpeg_executable_magic_video",
                "ffmpeg output has executable signature; bypassing video rebuild",
            ));
            return Ok(HandlerResult {
                mime: "video/raw".to_string(),
                output_bytes: input_bytes,
                alerts,
                stages,
            });
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::Rebuild,
            status: PipelineStageStatus::Success,
            detail: "achieved_reconstruction=semantic".to_string(),
        });
        Ok(HandlerResult {
            mime: "video/mp4".to_string(),
            output_bytes,
            alerts,
            stages,
        })
    }

    fn run_video_probe(&self, input_path: &std::path::Path) -> Result<(), DefenderError> {
        let output = crate::process::run_bounded(
            Command::new(&self.policy.ffmpeg_bin)
                .args(["-protocol_whitelist", "file,pipe", "-threads", "2"])
                .arg("-v")
                .arg("error")
                .arg("-nostdin")
                .arg("-i")
                .arg(input_path)
                .arg("-map")
                .arg("0:v:0")
                .arg("-frames:v")
                .arg("1")
                .arg("-f")
                .arg("null")
                .arg("-"),
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        );
        let output = match output {
            Ok(value) => value,
            Err(value) => {
                return Err(DefenderError::Video(format!(
                    "video probe failed to start: {value}"
                )));
            }
        };
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(DefenderError::Video(format!(
            "video probe decode failed: {stderr}"
        )))
    }

    fn run_ffprobe_metrics(
        &self,
        input_path: &std::path::Path,
    ) -> Result<VideoProbeMetrics, DefenderError> {
        let output = crate::process::run_bounded(
            Command::new(&self.policy.ffprobe_bin)
                .args(["-protocol_whitelist", "file,pipe", "-threads", "2"])
                .arg("-v")
                .arg("error")
                .arg("-select_streams")
                .arg("v:0")
                .arg("-show_entries")
                .arg("stream=bit_rate:format=duration,bit_rate")
                .arg("-of")
                .arg("default=noprint_wrappers=1:nokey=0")
                .arg(input_path),
            Duration::from_secs(self.policy.ffmpeg_timeout_secs),
        )
        .map_err(|value| DefenderError::Video(format!("ffprobe execution failed: {value}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DefenderError::Video(format!(
                "ffprobe exited with error: {stderr}"
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_video_probe_metrics(stdout.as_ref())
    }
}

fn looks_like_mp4_container(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let marker = &bytes[4..8];
    marker == b"ftyp"
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

fn parse_video_probe_metrics(raw: &str) -> Result<VideoProbeMetrics, DefenderError> {
    let mut duration_secs = None;
    let mut bitrate_bps = None;
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
    }
    if duration_secs.is_none() && bitrate_bps.is_none() {
        return Err(DefenderError::Video(
            "ffprobe returned no usable metrics".to_string(),
        ));
    }
    Ok(VideoProbeMetrics {
        duration_secs,
        bitrate_bps,
    })
}

#[cfg(test)]
mod tests {
    use super::{has_executable_magic, looks_like_mp4_container, parse_video_probe_metrics};

    #[test]
    fn recognizes_mp4_ftyp_signature() {
        let mut bytes = vec![0, 0, 0, 24];
        bytes.extend_from_slice(b"ftyp");
        bytes.extend_from_slice(b"isom");
        assert!(looks_like_mp4_container(&bytes));
    }

    #[test]
    fn rejects_non_mp4_signature() {
        let bytes = b"NOT_A_VALID_MP4_HEADER".to_vec();
        assert!(!looks_like_mp4_container(&bytes));
    }

    #[test]
    fn recognizes_executable_magic() {
        let bytes = vec![0x4D, 0x5A, 0x90, 0x00];
        assert!(has_executable_magic(&bytes));
    }

    #[test]
    fn parses_video_probe_metrics() {
        let raw = "duration=12.5\nbit_rate=800000\n";
        let metrics = parse_video_probe_metrics(raw).expect("metrics must parse");
        assert_eq!(metrics.duration_secs, Some(12.5));
        assert_eq!(metrics.bitrate_bps, Some(800000));
    }
}
