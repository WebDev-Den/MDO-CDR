use crate::types::SignatureRule;
use serde::Serialize;

/// Minimum transformation required before a result may be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ReconstructionLevel {
    Structural,
    Semantic,
}

#[derive(Debug, Clone)]
pub struct DefensePolicy {
    pub minimum_reconstruction_level: ReconstructionLevel,
    pub max_handler_duration_ms: u64,
    pub max_input_size_bytes: u64,
    pub max_output_size_bytes: u64,
    pub max_output_expansion_ratio: f64,
    pub enforce_output_kind_match: bool,
    pub block_on_unknown_output_mime: bool,
    pub enforce_output_mime_whitelist: bool,
    pub output_mime_whitelist: OutputMimeWhitelist,
    pub output_mime_denylist: Vec<String>,
    pub enforcement_mode: EnforcementMode,
    pub block_kind_mismatch: bool,
    pub unknown_kind_mode: UnknownKindMode,
    pub decoder_failure_mode: DecoderFailureMode,
    pub signature_scan_mode: SignatureScanMode,
    pub block_on_pre_scan_match: bool,
    pub blocked_extensions: Vec<String>,
    pub signature_rules: Vec<SignatureRule>,
    pub image: ImagePolicy,
    pub animated_image: AnimatedImagePolicy,
    pub gif: GifPolicy,
    pub video: VideoPolicy,
    pub audio: AudioPolicy,
    pub other: OtherPolicy,
}

impl Default for DefensePolicy {
    fn default() -> Self {
        Self {
            minimum_reconstruction_level: ReconstructionLevel::Structural,
            max_handler_duration_ms: 10_000, // 10 seconds
            max_input_size_bytes: 200 * 1024 * 1024,
            max_output_size_bytes: 250 * 1024 * 1024,
            max_output_expansion_ratio: 12.0,
            enforce_output_kind_match: true,
            block_on_unknown_output_mime: false,
            enforce_output_mime_whitelist: true,
            output_mime_whitelist: OutputMimeWhitelist::default(),
            output_mime_denylist: Vec::new(),
            enforcement_mode: EnforcementMode::Enforce,
            block_kind_mismatch: true,
            unknown_kind_mode: UnknownKindMode::Warn,
            decoder_failure_mode: DecoderFailureMode::QuarantineAsOther,
            signature_scan_mode: SignatureScanMode::InputAndOutput,
            block_on_pre_scan_match: true,
            blocked_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "js".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "msi".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "vbe".to_string(),
                "ps1".to_string(),
                "psc1".to_string(),
                "jar".to_string(),
                "apk".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "hta".to_string(),
                "cpl".to_string(),
                "wsf".to_string(),
                "wsh".to_string(),
                "reg".to_string(),
                "inf".to_string(),
                "lnk".to_string(),
                "py".to_string(),
                "rb".to_string(),
                "sh".to_string(),
                "php".to_string(),
                "class".to_string(),
                "dex".to_string(),
                "wasm".to_string(),
            ],
            signature_rules: Vec::new(),
            image: ImagePolicy::default(),
            animated_image: AnimatedImagePolicy::default(),
            gif: GifPolicy::default(),
            video: VideoPolicy::default(),
            audio: AudioPolicy::default(),
            other: OtherPolicy::default(),
        }
    }
}

impl DefensePolicy {
    /// Conservative profile for the dissertation demonstration: semantic
    /// reconstruction, known formats, and blocking when evidence is missing.
    pub fn dissertation_profile() -> Self {
        Self::strict_profile()
    }

    pub fn staging_profile() -> Self {
        Self::default()
    }

    pub fn strict_profile() -> Self {
        Self {
            minimum_reconstruction_level: ReconstructionLevel::Semantic,
            max_handler_duration_ms: 8_000,
            max_input_size_bytes: 100 * 1024 * 1024,
            max_output_size_bytes: 120 * 1024 * 1024,
            max_output_expansion_ratio: 8.0,
            enforce_output_kind_match: true,
            block_on_unknown_output_mime: true,
            enforce_output_mime_whitelist: true,
            output_mime_whitelist: OutputMimeWhitelist::strict(),
            output_mime_denylist: default_output_mime_denylist(),
            enforcement_mode: EnforcementMode::Enforce,
            block_kind_mismatch: true,
            unknown_kind_mode: UnknownKindMode::Block,
            decoder_failure_mode: DecoderFailureMode::Block,
            signature_scan_mode: SignatureScanMode::InputAndOutput,
            block_on_pre_scan_match: true,
            blocked_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "js".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "msi".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "vbe".to_string(),
                "ps1".to_string(),
                "psc1".to_string(),
                "jar".to_string(),
                "apk".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "hta".to_string(),
                "cpl".to_string(),
                "wsf".to_string(),
                "wsh".to_string(),
                "reg".to_string(),
                "inf".to_string(),
                "lnk".to_string(),
                "py".to_string(),
                "rb".to_string(),
                "sh".to_string(),
                "php".to_string(),
                "class".to_string(),
                "dex".to_string(),
                "wasm".to_string(),
            ],
            signature_rules: Vec::new(),
            image: ImagePolicy {
                probe_failure_mode: ProbeFailureMode::Block,
                ..ImagePolicy::default()
            },
            animated_image: AnimatedImagePolicy::strict(),
            gif: GifPolicy {
                probe_failure_mode: ProbeFailureMode::Block,
                ..GifPolicy::default()
            },
            video: VideoPolicy {
                mode: VideoMode::RequireFfmpeg,
                ffmpeg_bin: "ffmpeg".to_string(),
                ffprobe_bin: "ffprobe".to_string(),
                ffmpeg_timeout_secs: 20,
                max_duration_secs: 30 * 60,
                max_bitrate_kbps: 15_000,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            audio: AudioPolicy {
                mode: AudioMode::RequireFfmpeg,
                ffmpeg_bin: "ffmpeg".to_string(),
                ffprobe_bin: "ffprobe".to_string(),
                ffmpeg_timeout_secs: 15,
                max_duration_secs: 20 * 60,
                max_bitrate_kbps: 1_024,
                max_channels: 2,
                output_codec: AudioOutputCodec::Mp3,
                keep_original_mode: AudioKeepOriginalMode::Block,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            other: OtherPolicy {
                max_entropy: 7.7,
                structured_probe_mode: ProbeFailureMode::Block,
            },
        }
    }

    pub fn paranoid_profile() -> Self {
        Self {
            minimum_reconstruction_level: ReconstructionLevel::Semantic,
            max_handler_duration_ms: 5_000,
            max_input_size_bytes: 50 * 1024 * 1024,
            max_output_size_bytes: 60 * 1024 * 1024,
            max_output_expansion_ratio: 4.0,
            enforce_output_kind_match: true,
            block_on_unknown_output_mime: true,
            enforce_output_mime_whitelist: true,
            output_mime_whitelist: OutputMimeWhitelist::paranoid(),
            output_mime_denylist: default_output_mime_denylist(),
            enforcement_mode: EnforcementMode::Enforce,
            block_kind_mismatch: true,
            unknown_kind_mode: UnknownKindMode::Block,
            decoder_failure_mode: DecoderFailureMode::Block,
            signature_scan_mode: SignatureScanMode::InputAndOutput,
            block_on_pre_scan_match: true,
            blocked_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "js".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "msi".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "vbe".to_string(),
                "ps1".to_string(),
                "psc1".to_string(),
                "jar".to_string(),
                "apk".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "hta".to_string(),
                "cpl".to_string(),
                "wsf".to_string(),
                "wsh".to_string(),
                "reg".to_string(),
                "inf".to_string(),
                "lnk".to_string(),
                "py".to_string(),
                "rb".to_string(),
                "sh".to_string(),
                "php".to_string(),
                "class".to_string(),
                "dex".to_string(),
                "wasm".to_string(),
                // Paranoid-only: archive formats that can carry embedded
                // executables or exploit archive parsers.
                "zip".to_string(),
                "rar".to_string(),
                "7z".to_string(),
                "tar".to_string(),
                "gz".to_string(),
                "bz2".to_string(),
                "iso".to_string(),
                "cab".to_string(),
                "dmg".to_string(),
            ],
            signature_rules: Vec::new(),
            image: ImagePolicy {
                output_format: ImageOutputFormat::Png,
                max_pixels: 20_000_000,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            animated_image: AnimatedImagePolicy::paranoid(),
            gif: GifPolicy {
                max_frames: 200,
                max_pixels_per_frame: 8_000_000,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            video: VideoPolicy {
                mode: VideoMode::RequireFfmpeg,
                ffmpeg_bin: "ffmpeg".to_string(),
                ffprobe_bin: "ffprobe".to_string(),
                ffmpeg_timeout_secs: 12,
                max_duration_secs: 15 * 60,
                max_bitrate_kbps: 8_000,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            audio: AudioPolicy {
                mode: AudioMode::RequireFfmpeg,
                ffmpeg_bin: "ffmpeg".to_string(),
                ffprobe_bin: "ffprobe".to_string(),
                ffmpeg_timeout_secs: 10,
                max_duration_secs: 10 * 60,
                max_bitrate_kbps: 512,
                max_channels: 2,
                output_codec: AudioOutputCodec::Mp3,
                keep_original_mode: AudioKeepOriginalMode::Block,
                probe_failure_mode: ProbeFailureMode::Block,
            },
            other: OtherPolicy {
                max_entropy: 7.4,
                structured_probe_mode: ProbeFailureMode::Block,
            },
        }
    }

    pub fn public_profile() -> Self {
        Self::staging_profile()
    }

    pub fn enterprise_profile() -> Self {
        Self::strict_profile()
    }

    pub fn high_risk_profile() -> Self {
        Self::paranoid_profile()
    }

    pub fn with_dry_run(mut self) -> Self {
        self.enforcement_mode = EnforcementMode::DryRun;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnknownKindMode {
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DecoderFailureMode {
    Block,
    QuarantineAsOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignatureScanMode {
    OutputOnly,
    InputAndOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ProbeFailureMode {
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EnforcementMode {
    Enforce,
    DryRun,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputMimeWhitelist {
    pub image: Vec<String>,
    pub gif: Vec<String>,
    pub video: Vec<String>,
    pub audio: Vec<String>,
    pub other: Vec<String>,
}

impl Default for OutputMimeWhitelist {
    fn default() -> Self {
        Self {
            image: vec![
                "image/png".to_string(),
                "image/jpeg".to_string(),
                "image/webp".to_string(),
            ],
            gif: vec!["image/gif".to_string()],
            video: vec!["video/mp4".to_string(), "video/raw".to_string()],
            audio: vec![
                "audio/mpeg".to_string(),
                "audio/aac".to_string(),
                "audio/opus".to_string(),
                "audio/flac".to_string(),
                "audio/wav".to_string(),
                "audio/raw".to_string(),
            ],
            other: vec!["application/octet-stream".to_string()],
        }
    }
}

impl OutputMimeWhitelist {
    pub fn strict() -> Self {
        Self {
            image: vec!["image/png".to_string(), "image/jpeg".to_string()],
            gif: vec!["image/gif".to_string()],
            video: vec!["video/mp4".to_string()],
            audio: vec![
                "audio/mpeg".to_string(),
                "audio/aac".to_string(),
                "audio/opus".to_string(),
                "audio/flac".to_string(),
                "audio/wav".to_string(),
            ],
            other: vec!["application/octet-stream".to_string()],
        }
    }

    pub fn paranoid() -> Self {
        Self {
            image: vec!["image/png".to_string()],
            gif: vec!["image/gif".to_string()],
            video: vec!["video/mp4".to_string()],
            audio: vec!["audio/mpeg".to_string(), "audio/flac".to_string()],
            other: vec!["application/octet-stream".to_string()],
        }
    }
}

fn default_output_mime_denylist() -> Vec<String> {
    vec![
        "application/x-msdownload".to_string(),
        "application/x-dosexec".to_string(),
        "application/java-archive".to_string(),
        "application/x-sh".to_string(),
        "application/javascript".to_string(),
        "text/javascript".to_string(),
        "application/x-mach-binary".to_string(),
        "application/x-elf".to_string(),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ImageOutputFormat {
    Png,
    Jpeg,
    Webp,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImagePolicy {
    pub output_format: ImageOutputFormat,
    pub max_pixels: u64,
    pub probe_failure_mode: ProbeFailureMode,
}

impl Default for ImagePolicy {
    fn default() -> Self {
        Self {
            output_format: ImageOutputFormat::Png,
            max_pixels: 30_000_000,
            probe_failure_mode: ProbeFailureMode::Warn,
        }
    }
}

/// Bounds for animated-image container re-mux (APNG at the moment).
///
/// This is not a decoder — the handler walks PNG chunks, drops metadata
/// chunks, validates CRC, and re-emits a sanitized container. The limits
/// below stop chunk-bomb and frame-bomb inputs before they cost us any
/// real work.
#[derive(Debug, Clone, Serialize)]
pub struct AnimatedImagePolicy {
    /// Maximum number of PNG chunks we will walk before giving up. A
    /// well-formed APNG has a handful per frame; crafted inputs can use
    /// thousands of zero-length chunks to DoS the parser.
    pub max_chunks: u32,
    /// Maximum single chunk payload size (bytes). Metadata chunks like
    /// `iCCP` can legitimately be large; attackers can push it into the
    /// gigabyte range. 8 MiB is generous for real-world APNGs.
    pub max_chunk_size: u64,
    /// Maximum animation frames. 300 frames at 24fps = 12.5s loop.
    pub max_frames: u32,
    /// Maximum pixels in a single frame (`width * height`).
    pub max_pixels_per_frame: u64,
    /// Upper bound on `width` or `height` independently — rejects
    /// "1 × 4000000000" style degenerate inputs before multiplication.
    pub max_side: u32,
    /// Maximum aggregate pixel count across all frames. Protects against
    /// "many small frames" bombs that slip past per-frame limits.
    pub max_total_pixels: u64,
}

impl Default for AnimatedImagePolicy {
    fn default() -> Self {
        Self {
            max_chunks: 4_096,
            max_chunk_size: 8 * 1024 * 1024,
            max_frames: 300,
            max_pixels_per_frame: 8_000_000,
            max_side: 16_384,
            max_total_pixels: 200_000_000,
        }
    }
}

impl AnimatedImagePolicy {
    pub fn strict() -> Self {
        Self {
            max_chunks: 2_048,
            max_chunk_size: 4 * 1024 * 1024,
            max_frames: 200,
            max_pixels_per_frame: 4_000_000,
            max_side: 8_192,
            max_total_pixels: 100_000_000,
        }
    }

    pub fn paranoid() -> Self {
        Self {
            max_chunks: 1_024,
            max_chunk_size: 2 * 1024 * 1024,
            max_frames: 100,
            max_pixels_per_frame: 2_000_000,
            max_side: 4_096,
            max_total_pixels: 40_000_000,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GifPolicy {
    pub max_frames: usize,
    pub max_pixels_per_frame: u64,
    pub probe_failure_mode: ProbeFailureMode,
}

impl Default for GifPolicy {
    fn default() -> Self {
        Self {
            max_frames: 500,
            max_pixels_per_frame: 16_000_000,
            probe_failure_mode: ProbeFailureMode::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum VideoMode {
    RequireFfmpeg,
    BypassWhenUnavailable,
    BlockWhenUnavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct VideoPolicy {
    pub mode: VideoMode,
    pub ffmpeg_bin: String,
    pub ffprobe_bin: String,
    pub ffmpeg_timeout_secs: u64,
    pub max_duration_secs: u64,
    pub max_bitrate_kbps: u64,
    pub probe_failure_mode: ProbeFailureMode,
}

impl Default for VideoPolicy {
    fn default() -> Self {
        Self {
            // Fail-closed: if ffmpeg is not available, BLOCK the file rather
            // than silently passing it through unmodified. On mobile (where
            // ffmpeg is never available) this means video files are rejected
            // until the symphonia container-remux handler replaces this path.
            mode: VideoMode::BlockWhenUnavailable,
            ffmpeg_bin: "ffmpeg".to_string(),
            ffprobe_bin: "ffprobe".to_string(),
            ffmpeg_timeout_secs: 25,
            max_duration_secs: 60 * 60,
            max_bitrate_kbps: 20_000,
            probe_failure_mode: ProbeFailureMode::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AudioMode {
    RequireFfmpeg,
    BypassWhenUnavailable,
    BlockWhenUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AudioOutputCodec {
    KeepOriginalWhenPossible,
    Mp3,
    Aac,
    Opus,
    Flac,
    Wav,
}

#[derive(Debug, Clone, Serialize)]
pub struct AudioPolicy {
    pub mode: AudioMode,
    pub ffmpeg_bin: String,
    pub ffprobe_bin: String,
    pub ffmpeg_timeout_secs: u64,
    pub max_duration_secs: u64,
    pub max_bitrate_kbps: u64,
    pub max_channels: u64,
    pub output_codec: AudioOutputCodec,
    pub keep_original_mode: AudioKeepOriginalMode,
    pub probe_failure_mode: ProbeFailureMode,
}

impl Default for AudioPolicy {
    fn default() -> Self {
        Self {
            // Fail-closed: same rationale as VideoPolicy — never pass audio
            // through unprocessed. On mobile this blocks audio until the
            // symphonia container-remux handler lands.
            mode: AudioMode::BlockWhenUnavailable,
            ffmpeg_bin: "ffmpeg".to_string(),
            ffprobe_bin: "ffprobe".to_string(),
            ffmpeg_timeout_secs: 20,
            max_duration_secs: 60 * 60,
            max_bitrate_kbps: 1_536,
            max_channels: 6,
            output_codec: AudioOutputCodec::Mp3,
            keep_original_mode: AudioKeepOriginalMode::FallbackToMp3,
            probe_failure_mode: ProbeFailureMode::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AudioKeepOriginalMode {
    FallbackToMp3,
    Block,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtherPolicy {
    pub max_entropy: f64,
    pub structured_probe_mode: ProbeFailureMode,
}

impl Default for OtherPolicy {
    fn default() -> Self {
        Self {
            max_entropy: 7.98,
            structured_probe_mode: ProbeFailureMode::Warn,
        }
    }
}
