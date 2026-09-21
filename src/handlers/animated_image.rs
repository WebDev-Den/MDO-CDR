//! Animated-image handler (APNG container re-mux).
//!
//! The handler does NOT decode pixel data. It walks PNG chunks, validates
//! each chunk's CRC, verifies structural constraints (chunk count, chunk
//! size, frame count, dimensions), drops every metadata chunk, and emits
//! a sanitized PNG/APNG containing only the chunks needed for rendering.
//!
//! This mirrors the container-only strategy we use for video and audio:
//! parsing is pure structural analysis with bounded state, no codec
//! execution happens inside the defender. A downstream renderer will
//! catch any malformed pixel payload at display time.
//!
//! ## Chunks retained (critical)
//!
//! - `IHDR` — header (dimensions, colour type).
//! - `PLTE` — palette (required for indexed images).
//! - `tRNS` — transparency (required for some colour types).
//! - `IDAT` — primary image data (first frame fallback).
//! - `acTL` — animation control (required for APNG players).
//! - `fcTL` — per-frame control (required for APNG players).
//! - `fdAT` — per-frame data.
//! - `IEND` — terminator.
//!
//! ## Chunks stripped (metadata / attacker vectors)
//!
//! Everything else. Notably: `iCCP` (ICC profiles, historically abused),
//! `tEXt`/`iTXt`/`zTXt` (text metadata, compressed-text bomb vector),
//! `eXIf` (EXIF), `tIME`, `pHYs`, `bKGD`, `cHRM`, `gAMA`, `sBIT`, `sPLT`,
//! `sRGB`, `hIST`, and any unknown ancillary chunks.

use crate::{
    DefenderError,
    policy::AnimatedImagePolicy,
    types::{
        AlertSeverity, DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport,
        PipelineStageStatus,
    },
};

use super::HandlerResult;

const PNG_SIGNATURE: &[u8; 8] = &[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Chunks that are emitted in the sanitized output.
fn is_critical_chunk(chunk_type: &[u8; 4]) -> bool {
    matches!(
        chunk_type,
        b"IHDR" | b"PLTE" | b"tRNS" | b"IDAT" | b"acTL" | b"fcTL" | b"fdAT" | b"IEND"
    )
}

#[derive(Debug, Clone)]
pub struct AnimatedImageHandler {
    policy: AnimatedImagePolicy,
}

impl AnimatedImageHandler {
    pub fn new(policy: AnimatedImagePolicy) -> Self {
        Self { policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        log::debug!("animated_image::rebuild entry: size={}", input_bytes.len());

        if input_bytes.len() < 8 || &input_bytes[..8] != PNG_SIGNATURE {
            return Err(DefenderError::AnimatedImage(
                "input is not a PNG (signature mismatch)".to_string(),
            ));
        }

        // First critical sanity check before we touch anything else: the
        // IHDR chunk must be the very first chunk and it must carry sane
        // dimensions. We refuse to even walk the rest of the file if the
        // declared width/height already blow our bomb limits.
        let (ihdr_width, ihdr_height) = read_ihdr_dimensions(&input_bytes, &self.policy)?;
        log::debug!("animated_image::rebuild ihdr width={ihdr_width} height={ihdr_height}");

        let per_frame_pixels = (ihdr_width as u64).saturating_mul(ihdr_height as u64);
        if per_frame_pixels > self.policy.max_pixels_per_frame {
            log::warn!(
                "animated_image rejected: per-frame pixels {per_frame_pixels} exceeds limit {}",
                self.policy.max_pixels_per_frame
            );
            return Err(DefenderError::AnimatedImage(format!(
                "per-frame pixel count {per_frame_pixels} exceeds max_pixels_per_frame {}",
                self.policy.max_pixels_per_frame
            )));
        }

        // Walk every chunk, validate CRC, partition into keep/strip.
        let walked = walk_chunks(&input_bytes, &self.policy)?;
        context.check_limits()?;

        // Enforce frame-count and aggregate pixel limits based on acTL if
        // present. A file without acTL is a static PNG that happened to
        // reach this handler (peek-classifier will normally avoid that,
        // but we stay defensive).
        if let Some(frames) = walked.num_frames {
            if frames == 0 {
                return Err(DefenderError::AnimatedImage(
                    "acTL declares zero frames".to_string(),
                ));
            }
            if frames > self.policy.max_frames {
                log::warn!(
                    "animated_image rejected: frame count {frames} exceeds limit {}",
                    self.policy.max_frames
                );
                return Err(DefenderError::AnimatedImage(format!(
                    "frame count {frames} exceeds max_frames {}",
                    self.policy.max_frames
                )));
            }
            let total_pixels = per_frame_pixels.saturating_mul(frames as u64);
            if total_pixels > self.policy.max_total_pixels {
                log::warn!(
                    "animated_image rejected: total pixels {total_pixels} exceeds limit {}",
                    self.policy.max_total_pixels
                );
                return Err(DefenderError::AnimatedImage(format!(
                    "total pixel count {total_pixels} exceeds max_total_pixels {}",
                    self.policy.max_total_pixels
                )));
            }
        }

        // Emit critical chunks back into a fresh buffer. We copy whole
        // chunk frames (length + type + data + CRC) bit-for-bit since CRC
        // has already been verified; this guarantees the output remains a
        // valid PNG container without re-computing anything.
        let mut output = Vec::with_capacity(input_bytes.len());
        output.extend_from_slice(PNG_SIGNATURE);
        for chunk in &walked.chunks {
            if chunk.keep {
                // Checked arithmetic: offset + 12 (header+crc) + length.
                let end = match (chunk.offset as u64)
                    .checked_add(12)
                    .and_then(|v| v.checked_add(chunk.length as u64))
                {
                    Some(v) if v <= input_bytes.len() as u64 => v as usize,
                    _ => {
                        return Err(DefenderError::AnimatedImage(
                            "chunk bounds overflow during output assembly".to_string(),
                        ));
                    }
                };
                output.extend_from_slice(&input_bytes[chunk.offset..end]);
            }
        }

        let stripped_count = walked.chunks.iter().filter(|chunk| !chunk.keep).count() as u32;
        let stripped_bytes: u64 = walked
            .chunks
            .iter()
            .filter(|chunk| !chunk.keep)
            .map(|chunk| 12u64 + chunk.length as u64)
            .sum();

        let mut alerts = Vec::new();
        if stripped_count > 0 {
            alerts.push(DefenseAlert {
                code: "apng_metadata_stripped".to_string(),
                message: format!(
                    "Stripped {stripped_count} non-critical PNG chunk(s), {stripped_bytes} bytes.",
                ),
                severity: AlertSeverity::Info,
            });
        }

        let frames_label = walked
            .num_frames
            .map(|count| count.to_string())
            .unwrap_or_else(|| "static".to_string());
        log::info!(
            "animated_image::rebuild exit: frames={frames_label} stripped_chunks={stripped_count} stripped_bytes={stripped_bytes} output_size={}",
            output.len()
        );

        Ok(HandlerResult {
            mime: if walked.num_frames.is_some() {
                "image/apng".to_string()
            } else {
                "image/png".to_string()
            },
            output_bytes: output,
            alerts,
            stages: vec![PipelineStageReport {
                stage: PipelineStage::ImageProbe,
                status: PipelineStageStatus::Success,
                detail: format!(
                    "animated_image remux frames={frames_label} chunks_kept={} chunks_stripped={stripped_count}",
                    walked.chunks.iter().filter(|chunk| chunk.keep).count()
                ),
            }],
        })
    }
}

#[derive(Debug)]
struct ChunkRef {
    /// Offset of the chunk's length field in the input buffer.
    offset: usize,
    length: u32,
    /// Whether this chunk survives the rebuild.
    keep: bool,
}

#[derive(Debug)]
struct WalkOutcome {
    chunks: Vec<ChunkRef>,
    num_frames: Option<u32>,
}

fn walk_chunks(input: &[u8], policy: &AnimatedImagePolicy) -> Result<WalkOutcome, DefenderError> {
    let mut chunks = Vec::new();
    let mut num_frames: Option<u32> = None;
    let mut offset = 8usize;
    let mut saw_iend = false;

    for _ in 0..policy.max_chunks {
        if offset + 12 > input.len() {
            return Err(DefenderError::AnimatedImage(
                "truncated chunk header".to_string(),
            ));
        }
        let length = u32::from_be_bytes([
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ]);
        if length as u64 > policy.max_chunk_size {
            return Err(DefenderError::AnimatedImage(format!(
                "chunk payload {length} exceeds max_chunk_size {}",
                policy.max_chunk_size
            )));
        }
        let chunk_type_start = offset + 4;
        let chunk_type: [u8; 4] = [
            input[chunk_type_start],
            input[chunk_type_start + 1],
            input[chunk_type_start + 2],
            input[chunk_type_start + 3],
        ];
        let data_start = chunk_type_start + 4;
        let data_end = match data_start.checked_add(length as usize) {
            Some(value) => value,
            None => {
                return Err(DefenderError::AnimatedImage(
                    "chunk length arithmetic overflow".to_string(),
                ));
            }
        };
        if data_end > input.len() {
            return Err(DefenderError::AnimatedImage(
                "chunk data extends past end of file".to_string(),
            ));
        }
        let crc_end = match data_end.checked_add(4) {
            Some(value) => value,
            None => {
                return Err(DefenderError::AnimatedImage(
                    "chunk crc arithmetic overflow".to_string(),
                ));
            }
        };
        if crc_end > input.len() {
            return Err(DefenderError::AnimatedImage(
                "chunk CRC extends past end of file".to_string(),
            ));
        }

        // CRC is computed over type + data (not over length).
        let stated_crc = u32::from_be_bytes([
            input[data_end],
            input[data_end + 1],
            input[data_end + 2],
            input[data_end + 3],
        ]);
        let computed_crc = png_crc32(&input[chunk_type_start..data_end]);
        if stated_crc != computed_crc {
            return Err(DefenderError::AnimatedImage(format!(
                "CRC mismatch on chunk `{}`",
                String::from_utf8_lossy(&chunk_type)
            )));
        }

        // Validate structural invariants for critical chunks.
        validate_plte(&chunk_type, length)?;

        // Capture acTL frame count for downstream limit enforcement.
        if &chunk_type == b"acTL" && length >= 8 {
            let frames = u32::from_be_bytes([
                input[data_start],
                input[data_start + 1],
                input[data_start + 2],
                input[data_start + 3],
            ]);
            num_frames = Some(frames);
        }

        let keep = is_critical_chunk(&chunk_type);
        chunks.push(ChunkRef {
            offset,
            length,
            keep,
        });

        offset = crc_end;
        if &chunk_type == b"IEND" {
            saw_iend = true;
            break;
        }
    }

    if !saw_iend {
        return Err(DefenderError::AnimatedImage(
            "IEND terminator not found within max_chunks budget".to_string(),
        ));
    }

    Ok(WalkOutcome { chunks, num_frames })
}

fn read_ihdr_dimensions(
    input: &[u8],
    policy: &AnimatedImagePolicy,
) -> Result<(u32, u32), DefenderError> {
    // After the 8-byte signature, IHDR MUST be the first chunk:
    //   length(4) + "IHDR"(4) + data(13) + crc(4).
    if input.len() < 8 + 4 + 4 + 13 + 4 {
        return Err(DefenderError::AnimatedImage(
            "file too short to contain IHDR".to_string(),
        ));
    }
    let ihdr_length = u32::from_be_bytes([input[8], input[9], input[10], input[11]]);
    if ihdr_length != 13 {
        return Err(DefenderError::AnimatedImage(format!(
            "IHDR has unexpected length {ihdr_length}, expected 13"
        )));
    }
    if &input[12..16] != b"IHDR" {
        return Err(DefenderError::AnimatedImage(
            "first chunk is not IHDR".to_string(),
        ));
    }
    let width = u32::from_be_bytes([input[16], input[17], input[18], input[19]]);
    let height = u32::from_be_bytes([input[20], input[21], input[22], input[23]]);
    if width == 0 || height == 0 {
        return Err(DefenderError::AnimatedImage(
            "IHDR has zero width or height".to_string(),
        ));
    }
    if width > policy.max_side || height > policy.max_side {
        return Err(DefenderError::AnimatedImage(format!(
            "IHDR dimension exceeds max_side: width={width} height={height} max={}",
            policy.max_side
        )));
    }

    // Validate IHDR color type and bit depth per PNG specification (§11.2.2).
    // Reject values that are not part of the PNG spec — a downstream
    // decoder may crash or behave unpredictably on these.
    let bit_depth = input[24];
    let color_type = input[25];
    let valid = match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16), // Greyscale
        2 => matches!(bit_depth, 8 | 16),             // Truecolour
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),      // Indexed-colour
        4 => matches!(bit_depth, 8 | 16),             // Greyscale + alpha
        6 => matches!(bit_depth, 8 | 16),             // Truecolour + alpha
        _ => false,
    };
    if !valid {
        return Err(DefenderError::AnimatedImage(format!(
            "IHDR has invalid color_type={color_type} bit_depth={bit_depth} combination"
        )));
    }

    Ok((width, height))
}

/// Returns `true` if the chunk is a PLTE chunk whose length is structurally
/// valid (must be divisible by 3 — each palette entry is an R/G/B triplet).
fn validate_plte(chunk_type: &[u8; 4], length: u32) -> Result<(), DefenderError> {
    if chunk_type == b"PLTE" && !length.is_multiple_of(3) {
        return Err(DefenderError::AnimatedImage(format!(
            "PLTE chunk length {length} is not divisible by 3"
        )));
    }
    Ok(())
}

/// PNG / PKZIP CRC-32 — reflected polynomial 0xEDB88320, initial value
/// 0xFFFFFFFF, final XOR 0xFFFFFFFF.
fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask: u32 = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_png_with_chunks(extra: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        // Build a minimal PNG: signature + IHDR + extra chunks + IEND.
        let mut out = Vec::new();
        out.extend_from_slice(PNG_SIGNATURE);
        // IHDR: width=1 height=1 bit_depth=8 color=2 (RGB) comp=0 filter=0 interlace=0
        let ihdr_data: [u8; 13] = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
        write_chunk(&mut out, b"IHDR", &ihdr_data);
        for (kind, data) in extra {
            write_chunk(&mut out, kind, data);
        }
        write_chunk(&mut out, b"IEND", &[]);
        out
    }

    fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut crc_bytes = Vec::with_capacity(4 + data.len());
        crc_bytes.extend_from_slice(kind);
        crc_bytes.extend_from_slice(data);
        out.extend_from_slice(&png_crc32(&crc_bytes).to_be_bytes());
    }

    #[test]
    fn crc_matches_known_reference_zero_byte_input() {
        // CRC-32 of an empty slice is 0, pre-final-XOR it's 0xFFFFFFFF.
        assert_eq!(png_crc32(&[]), 0);
    }

    #[test]
    fn rebuild_strips_text_chunks() {
        let input = minimal_png_with_chunks(&[(b"tEXt", b"Comment\0evil")]);
        let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
        let result = handler
            .rebuild(input.clone(), DefenseContext::default())
            .expect("rebuild succeeds");
        // Output must not contain the stripped chunk data.
        let output_has_text = result.output_bytes.windows(4).any(|w| w == b"tEXt");
        assert!(!output_has_text);
        // Info alert must be present.
        assert!(
            result
                .alerts
                .iter()
                .any(|a| a.code == "apng_metadata_stripped")
        );
    }

    #[test]
    fn rebuild_keeps_idat_and_iend() {
        let input = minimal_png_with_chunks(&[(b"IDAT", b"dummy")]);
        let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
        let result = handler
            .rebuild(input, DefenseContext::default())
            .expect("rebuild succeeds");
        assert!(
            result.output_bytes.windows(4).any(|w| w == b"IDAT"),
            "IDAT must survive"
        );
        assert!(
            result.output_bytes.windows(4).any(|w| w == b"IEND"),
            "IEND must survive"
        );
    }

    #[test]
    fn rebuild_detects_corrupted_crc() {
        let mut input = minimal_png_with_chunks(&[(b"tEXt", b"hello")]);
        // Flip a byte inside the tEXt data — CRC should now mismatch.
        // Data bytes come after the 4-byte length and 4-byte type prefix
        // inside the chunk, so locate "hello" and alter it.
        let offset = input.windows(5).position(|w| w == b"hello").unwrap();
        input[offset] = b'H';
        let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
        let result = handler.rebuild(input, DefenseContext::default());
        assert!(matches!(result, Err(DefenderError::AnimatedImage(_))));
    }

    #[test]
    fn rebuild_rejects_bad_signature() {
        let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
        let result = handler.rebuild(vec![0u8; 32], DefenseContext::default());
        assert!(matches!(result, Err(DefenderError::AnimatedImage(_))));
    }

    #[test]
    fn rebuild_enforces_max_side() {
        let policy = AnimatedImagePolicy {
            max_side: 1,
            ..AnimatedImagePolicy::default()
        };
        // IHDR declares width=1 height=1 which equals max_side (accepted).
        let input = minimal_png_with_chunks(&[]);
        let handler = AnimatedImageHandler::new(policy);
        assert!(handler.rebuild(input, DefenseContext::default()).is_ok());
    }

    #[test]
    fn rebuild_detects_apng_via_actl() {
        // acTL data: num_frames=2, num_plays=0.
        let actl: [u8; 8] = [0, 0, 0, 2, 0, 0, 0, 0];
        let input = minimal_png_with_chunks(&[(b"acTL", &actl)]);
        let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
        let result = handler
            .rebuild(input, DefenseContext::default())
            .expect("rebuild succeeds");
        assert_eq!(result.mime, "image/apng");
    }

    #[test]
    fn rebuild_blocks_frame_count_bomb() {
        let policy = AnimatedImagePolicy {
            max_frames: 5,
            ..AnimatedImagePolicy::default()
        };
        // Declare 100 frames via acTL — exceeds max_frames=5.
        let actl: [u8; 8] = [0, 0, 0, 100, 0, 0, 0, 0];
        let input = minimal_png_with_chunks(&[(b"acTL", &actl)]);
        let handler = AnimatedImageHandler::new(policy);
        let result = handler.rebuild(input, DefenseContext::default());
        assert!(matches!(result, Err(DefenderError::AnimatedImage(_))));
    }
}
