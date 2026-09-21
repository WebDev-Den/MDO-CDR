#![allow(clippy::question_mark)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Image,
    /// Animated PNG / animated WebP / other single-container animations that
    /// are NOT GIF. Detected by peeking the byte header for animation
    /// markers (acTL for APNG, VP8X animation flag for WebP) since the MIME
    /// guesser cannot distinguish animated from static variants.
    AnimatedImage,
    Gif,
    Video,
    Audio,
    Other,
}

impl FileKind {
    pub fn from_name_and_mime(file_name: Option<&str>, mime: Option<&str>) -> Self {
        let from_mime = Self::from_mime(mime);
        if let Some(value) = from_mime {
            return value;
        }
        let from_name = Self::from_name(file_name);
        if let Some(value) = from_name {
            return value;
        }
        Self::Other
    }

    /// Classify a file using a byte-header peek combined with the usual
    /// name + MIME heuristics.
    ///
    /// This upgrades an `Image` classification to `AnimatedImage` when the
    /// header reveals animation markers. Image-level MIME guessers report
    /// `image/png` for both static PNGs and APNGs, and `image/webp` for both
    /// static and animated WebPs, so the bytes themselves are the only
    /// reliable signal.
    pub fn classify(bytes: &[u8], file_name: Option<&str>, mime: Option<&str>) -> Self {
        // Double-extension defense: reject files where a dangerous extension
        // is hidden before a benign one, e.g. "invoice.exe.png". We check
        // the penultimate extension (if any) against a blocklist.
        if let Some(name) = file_name
            && has_suspicious_double_extension(name)
        {
            return Self::Other;
        }

        let base = Self::from_name_and_mime(file_name, mime);
        if matches!(base, Self::Image) && (is_apng(bytes) || is_animated_webp(bytes)) {
            return Self::AnimatedImage;
        }
        base
    }

    pub fn from_mime(mime: Option<&str>) -> Option<Self> {
        let Some(mime) = mime else {
            return None;
        };
        let value = mime.to_ascii_lowercase();
        if value.starts_with("image/gif") {
            return Some(Self::Gif);
        }
        // SVG is XML-based vector graphics, not a raster image. Routing it
        // to ImageHandler would fail (image crate can't decode SVG) and
        // could introduce XML-based attack vectors (XXE, script injection).
        if value.starts_with("image/svg") {
            return Some(Self::Other);
        }
        if value.starts_with("image/") {
            return Some(Self::Image);
        }
        if value.starts_with("video/") {
            return Some(Self::Video);
        }
        if value.starts_with("audio/") {
            return Some(Self::Audio);
        }
        if value.starts_with("application/") || value.starts_with("text/") {
            return Some(Self::Other);
        }
        None
    }

    pub fn from_name(file_name: Option<&str>) -> Option<Self> {
        let Some(file_name) = file_name else {
            return None;
        };
        let extension = std::path::Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        let Some(extension) = extension else {
            return None;
        };

        match extension.as_str() {
            "png" | "jpg" | "jpeg" | "bmp" | "tif" | "tiff" | "webp" => Some(Self::Image),
            "apng" => Some(Self::AnimatedImage),
            "gif" => Some(Self::Gif),
            "mp4" | "mov" | "avi" | "mkv" | "webm" => Some(Self::Video),
            "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" | "oga" | "opus" | "wma" | "amr"
            | "aiff" | "alac" => Some(Self::Audio),
            "pdf" | "txt" | "csv" | "json" | "xml" | "doc" | "docx" | "zip" | "7z" => {
                Some(Self::Other)
            }
            _ => None,
        }
    }
}

/// Returns true if the filename has a double extension where the penultimate
/// extension is a well-known dangerous type (exe, dll, bat, cmd, msi, scr,
/// vbs, ps1, jar, apk, com). Example: `report.exe.png` → true.
fn has_suspicious_double_extension(file_name: &str) -> bool {
    const DANGEROUS: &[&str] = &[
        "exe", "dll", "bat", "cmd", "msi", "scr", "vbs", "vbe", "ps1", "psc1", "jar", "apk", "com",
        "pif", "hta", "cpl", "wsf", "wsh",
    ];
    let parts: Vec<&str> = file_name.rsplit('.').collect();
    // parts[0] = final ext, parts[1] = penultimate ext, etc.
    if parts.len() < 3 {
        return false;
    }
    let penultimate = parts[1].to_ascii_lowercase();
    DANGEROUS.contains(&penultimate.as_str())
}

/// Detect APNG by locating an `acTL` chunk before the first `IDAT`/`IEND`.
///
/// Per the APNG specification, the animation-control chunk (`acTL`) MUST
/// appear after `IHDR` but before the first `IDAT`. We walk chunks from
/// offset 8 (after the 8-byte PNG signature) and return `true` if we find
/// `acTL` first, `false` if we hit `IDAT`/`IEND` or run out of bytes.
fn is_apng(bytes: &[u8]) -> bool {
    const PNG_SIGNATURE: &[u8; 8] = &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];
    if bytes.len() < 8 + 8 || &bytes[..8] != PNG_SIGNATURE {
        return false;
    }
    let mut offset = 8usize;
    // Defensive upper bound: walk at most 256 chunks before giving up.
    // A legitimate APNG places acTL very early (typically chunk 2-4),
    // but some generators add ancillary chunks before IDAT. 256 is generous
    // enough for any real-world file while stopping attackers from
    // forcing us to walk millions of descriptors.
    for _ in 0..256 {
        if offset + 8 > bytes.len() {
            return false;
        }
        let chunk_len = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        let chunk_type = &bytes[offset + 4..offset + 8];
        if chunk_type == b"acTL" {
            return true;
        }
        if chunk_type == b"IDAT" || chunk_type == b"IEND" {
            return false;
        }
        // Advance past: length(4) + type(4) + data + crc(4).
        // Use u64 arithmetic to avoid overflow on 32-bit targets where
        // usize is 32 bits but chunk_len can be up to ~4 GB.
        let next = (offset as u64) + (chunk_len as u64) + 12;
        if next > bytes.len() as u64 {
            return false;
        }
        offset = next as usize;
    }
    false
}

/// Detect animated WebP by inspecting the first VP8X chunk's animation flag.
///
/// WebP layout: `"RIFF" + u32 size + "WEBP" + chunks…`. Animated WebPs start
/// with a VP8X chunk whose first data byte is a bitfield; bit `0x02` is the
/// Animation flag. Static WebPs use `VP8 ` or `VP8L` instead of `VP8X`, so
/// we reject anything that isn't VP8X upfront.
fn is_animated_webp(bytes: &[u8]) -> bool {
    // Minimum bytes to reach VP8X flags: 12 (RIFF header) + 4 (chunk type)
    // + 4 (chunk size) + 1 (flags byte) = 21.
    if bytes.len() < 21 {
        return false;
    }
    if &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return false;
    }
    if &bytes[12..16] != b"VP8X" {
        return false;
    }
    // VP8X chunk data starts at offset 20. Verify the declared chunk size
    // is ≥ 10 bytes (the minimum VP8X payload).
    let vp8x_size = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    if vp8x_size < 10 {
        return false;
    }
    let flags_byte = bytes[20];
    (flags_byte & 0x02) != 0
}

/// Opaque cancellation token. The caller creates one, passes it into
/// `DefenseContext`, and can call `cancel()` from any thread. Handlers
/// check `is_cancelled()` at iteration boundaries (per-frame, per-page,
/// per-atom) and return early with `DefenderError::Cancelled`.
#[derive(Debug, Clone)]
pub struct CancellationToken {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DefenseContext {
    pub source: SourceRole,
    pub tenant_id: Option<String>,
    pub cancel: Option<CancellationToken>,
    /// When the handler started (set by FileDefender before dispatch).
    pub started_at: Option<std::time::Instant>,
    /// Wall-clock timeout in milliseconds. 0 = no timeout.
    pub timeout_ms: u64,
}

impl Default for DefenseContext {
    fn default() -> Self {
        Self {
            source: SourceRole::Outgoing,
            tenant_id: None,
            cancel: None,
            started_at: None,
            timeout_ms: 0,
        }
    }
}

impl DefenseContext {
    /// Check cancellation token and timeout. Returns `Err(Cancelled)` or
    /// `Err(Timeout)` if limits exceeded. Called by handlers at loop
    /// boundaries.
    /// Check cancellation and timeout. Call at handler loop boundaries.
    pub fn check_limits(&self) -> Result<(), crate::DefenderError> {
        if let Some(token) = &self.cancel
            && token.is_cancelled()
        {
            return Err(crate::DefenderError::Cancelled);
        }
        if self.timeout_ms > 0
            && let Some(started) = &self.started_at
            && started.elapsed().as_millis() as u64 > self.timeout_ms
        {
            return Err(crate::DefenderError::Timeout);
        }
        Ok(())
    }
}

/// Direction of the file relative to the process running the defense.
///
/// In an end-to-end encrypted chat the defense runs client-side on BOTH
/// sides: a sender CDRs a file before encrypting it (`Outgoing`), and a
/// receiver CDRs a file after decrypting it (`Incoming`). The names
/// `Client`/`Server` from earlier revisions did not reflect this E2E reality
/// and have been retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRole {
    /// File is about to leave this process (pre-send / pre-encrypt).
    Outgoing,
    /// File has just arrived at this process (post-receive / post-decrypt).
    Incoming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefenseVerdict {
    Clean,
    Suspicious,
    Blocked,
}

/// Severity of a single alert emitted by the defense pipeline.
///
/// The pipeline derives a 3-state verdict from alerts:
/// - any `Blocking` alert ⇒ `DefenseVerdict::Blocked`,
/// - otherwise any `Warning` alert ⇒ `DefenseVerdict::Suspicious`,
/// - otherwise (only `Info` alerts, or none) ⇒ `DefenseVerdict::Clean`.
///
/// `Info` is the audit-trail severity — it records normal transformations
/// (e.g. "EXIF stripped", "atom udta dropped") without affecting the verdict.
/// It exists so operators can see WHAT the defense did, not just WHETHER it
/// let the file through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    /// Record of a normal transformation — never affects the verdict.
    Info,
    /// Non-fatal anomaly — contributes to `Suspicious` verdict.
    Warning,
    /// Fatal policy violation — forces `Blocked` verdict.
    Blocking,
}

#[derive(Debug, Clone)]
pub struct DefenseAlert {
    pub code: String,
    pub message: String,
    pub severity: AlertSeverity,
}

impl DefenseAlert {
    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: AlertSeverity::Info,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: AlertSeverity::Warning,
        }
    }

    pub fn blocking(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            severity: AlertSeverity::Blocking,
        }
    }

    /// Whether this alert forces a `Blocked` verdict.
    pub fn is_blocking(&self) -> bool {
        matches!(self.severity, AlertSeverity::Blocking)
    }

    /// Whether this alert contributes to a `Suspicious` verdict.
    pub fn is_warning(&self) -> bool {
        matches!(self.severity, AlertSeverity::Warning)
    }

    /// Whether this alert is purely informational (no verdict impact).
    pub fn is_info(&self) -> bool {
        matches!(self.severity, AlertSeverity::Info)
    }
}

#[derive(Debug, Clone)]
pub struct DefendedArtifact {
    pub file_kind: FileKind,
    pub mime: String,
    pub original_size: u64,
    pub output_size: u64,
    pub sha256: String,
    pub output_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DefendResult {
    pub verdict: DefenseVerdict,
    pub alerts: Vec<DefenseAlert>,
    pub stages: Vec<PipelineStageReport>,
    pub artifact: DefendedArtifact,
    pub diagnostics: DefenseDiagnostics,
}

/// Per-call measurements emitted alongside the verdict.
///
/// These fields are not part of the verdict derivation — they exist so
/// operators can feed metrics into Prometheus / Sentry / local telemetry
/// without having to re-parse `alerts` or `stages`. Cheap to compute, always
/// populated.
///
/// The `stripped_*` counts are best-effort: handlers populate them when
/// they remove metadata or trailing bytes, but a handler that hasn't
/// been taught to report leaves them at zero.
#[derive(Debug, Clone, Default)]
pub struct DefenseDiagnostics {
    pub duration_ms: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub stripped_metadata_count: u32,
    pub stripped_bytes: u64,
    pub parser_used: String,
}

// `SignatureRule` and `SignatureLocation` live in the defender-signatures
// crate alongside the scanner implementation. They are re-exported here so
// existing callers using `crate::types::SignatureRule` keep working.
//
// A rule without an explicit location constraint is built with
// `SignatureLocation::Anywhere`. Use `SignatureRule::first_bytes(...)` or
// `SignatureRule::last_bytes(...)` for location-constrained rules.
pub use defender_signatures::{SignatureLocation, SignatureRule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    PreScan,
    ImageProbe,
    GifProbe,
    VideoProbe,
    AudioProbe,
    OtherProbe,
    Detect,
    Rebuild,
    SignatureScan,
    OutputValidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStageStatus {
    Success,
    Warning,
    Blocked,
}

#[derive(Debug, Clone)]
pub struct PipelineStageReport {
    pub stage: PipelineStage,
    pub status: PipelineStageStatus,
    pub detail: String,
}
