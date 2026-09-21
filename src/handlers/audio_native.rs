//! Native (pure-Rust, no-ffmpeg) container sanitizers for common audio formats.
//!
//! Each function strips metadata from the container while preserving the
//! encoded audio stream bit-for-bit. No decoding or re-encoding happens —
//! this is structural CDR at the container level, identical in philosophy
//! to our APNG chunk-walker and video atom-walker.
//!
//! Supported:
//! - **MP3**: strips ID3v2 (header) and ID3v1 (footer) tags.
//! - **WAV**: RIFF chunk walker — keeps `fmt ` and `data`, drops everything
//!   else (LIST, INFO, bext, iXML, etc.).
//! - **FLAC**: metadata-block walker — keeps STREAMINFO, drops
//!   VORBIS_COMMENT, PICTURE, APPLICATION, and all other ancillary blocks.

use crate::DefenderError;

/// Result from a native audio sanitizer.
pub struct NativeAudioResult {
    pub output_bytes: Vec<u8>,
    pub mime: &'static str,
    pub stripped_count: u32,
    pub stripped_bytes: u64,
}

// ──────────────────────────────────────────────────────────────────────────
// MP3 — strip ID3v1 (tail) and ID3v2 (head), keep raw MPEG frames.
// ──────────────────────────────────────────────────────────────────────────

/// Try to sanitize an MP3 by stripping ID3 tags. Returns `None` if the
/// input doesn't look like an MP3 (no sync word found).
pub fn try_sanitize_mp3(input: &[u8]) -> Option<Result<NativeAudioResult, DefenderError>> {
    let mut start = 0usize;
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;

    // Skip ID3v2 header if present (starts with "ID3").
    if input.len() >= 10 && &input[0..3] == b"ID3" {
        // ID3v2 size is a 4-byte synchsafe integer at offset 6-9.
        let size = synchsafe_u32(&input[6..10]) as usize;
        let header_size = 10 + size;
        if header_size > input.len() {
            return Some(Err(DefenderError::Audio(
                "ID3v2 header declares size beyond file end".to_string(),
            )));
        }
        stripped_bytes += header_size as u64;
        stripped_count += 1;
        start = header_size;
    }

    let mut end = input.len();

    // Strip ID3v1 tag if present (last 128 bytes, starts with "TAG").
    if end >= start + 128 && &input[end - 128..end - 125] == b"TAG" {
        stripped_bytes += 128;
        stripped_count += 1;
        end -= 128;
    }

    // Strip ID3v1.1 extended tag if present (last 227 bytes before ID3v1,
    // starts with "TAG+").
    if end >= start + 227 && &input[end - 227..end - 223] == b"TAG+" {
        stripped_bytes += 227;
        stripped_count += 1;
        end -= 227;
    }

    let audio_data = &input[start..end];
    if audio_data.len() < 4 {
        return Some(Err(DefenderError::Audio(
            "MP3 has no audio frame data after tag stripping".to_string(),
        )));
    }

    // Verify first two bytes look like an MPEG sync word (0xFFE0 mask).
    // This catches files that are tagged as MP3 but contain no audio.
    let first_word = ((audio_data[0] as u16) << 8) | audio_data[1] as u16;
    if first_word & 0xFFE0 != 0xFFE0 {
        // No sync word — not an MP3 we can handle natively.
        return None;
    }

    Some(Ok(NativeAudioResult {
        output_bytes: audio_data.to_vec(),
        mime: "audio/mpeg",
        stripped_count,
        stripped_bytes,
    }))
}

/// Decode a 4-byte synchsafe integer (7 bits per byte, MSB first).
fn synchsafe_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 21)
        | ((bytes[1] as u32) << 14)
        | ((bytes[2] as u32) << 7)
        | (bytes[3] as u32)
}

// ──────────────────────────────────────────────────────────────────────────
// WAV (RIFF WAVE) — keep fmt + data chunks, strip everything else.
// ──────────────────────────────────────────────────────────────────────────

/// Try to sanitize a WAV file by walking RIFF chunks and keeping only `fmt `
/// and `data`. Returns `None` if input is not RIFF/WAVE.
pub fn try_sanitize_wav(input: &[u8]) -> Option<Result<NativeAudioResult, DefenderError>> {
    if input.len() < 12 {
        return None;
    }
    if &input[0..4] != b"RIFF" || &input[8..12] != b"WAVE" {
        return None;
    }

    let mut kept_chunks: Vec<([u8; 4], &[u8])> = Vec::new();
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;
    let mut total_kept_bytes = 0u64;
    let mut offset = 12usize;
    const MAX_WAV_TOTAL: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

    for _ in 0..1024 {
        if offset + 8 > input.len() {
            break;
        }
        let chunk_id: [u8; 4] = [
            input[offset],
            input[offset + 1],
            input[offset + 2],
            input[offset + 3],
        ];
        let chunk_size = u32::from_le_bytes([
            input[offset + 4],
            input[offset + 5],
            input[offset + 6],
            input[offset + 7],
        ]) as usize;
        let data_start = offset + 8;
        let data_end = match data_start.checked_add(chunk_size) {
            Some(value) => value,
            None => {
                return Some(Err(DefenderError::Audio(
                    "WAV chunk size arithmetic overflow".to_string(),
                )));
            }
        };
        if data_end > input.len() {
            return Some(Err(DefenderError::Audio(
                "WAV chunk extends past end of file".to_string(),
            )));
        }
        let data = &input[data_start..data_end];
        if &chunk_id == b"fmt " || &chunk_id == b"data" {
            total_kept_bytes += 8 + chunk_size as u64;
            if total_kept_bytes > MAX_WAV_TOTAL {
                return Some(Err(DefenderError::Audio(
                    "WAV exceeds maximum total size".to_string(),
                )));
            }
            kept_chunks.push((chunk_id, data));
        } else {
            stripped_count += 1;
            stripped_bytes += 8u64 + chunk_size as u64;
        }

        // RIFF chunks are word-aligned (padded to even size).
        let padded = if chunk_size.is_multiple_of(2) {
            chunk_size
        } else {
            chunk_size + 1
        };
        offset = match (offset + 8).checked_add(padded) {
            Some(value) => value,
            None => break,
        };
    }

    // Validate we got fmt and data.
    let has_fmt = kept_chunks.iter().any(|(id, _)| id == b"fmt ");
    let has_data = kept_chunks.iter().any(|(id, _)| id == b"data");
    if !has_fmt || !has_data {
        return Some(Err(DefenderError::Audio(
            "WAV missing required fmt or data chunk".to_string(),
        )));
    }

    // Rebuild: RIFF header + kept chunks.
    let payload_size: usize = kept_chunks
        .iter()
        .map(|(_, data)| 8 + data.len() + (data.len() % 2))
        .sum::<usize>()
        + 4; // "WAVE"

    let mut output = Vec::with_capacity(12 + payload_size);
    output.extend_from_slice(b"RIFF");
    output.extend_from_slice(&(payload_size as u32).to_le_bytes());
    output.extend_from_slice(b"WAVE");
    for (id, data) in &kept_chunks {
        output.extend_from_slice(id);
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());
        output.extend_from_slice(data);
        if data.len() % 2 != 0 {
            output.push(0); // padding byte
        }
    }

    Some(Ok(NativeAudioResult {
        output_bytes: output,
        mime: "audio/wav",
        stripped_count,
        stripped_bytes,
    }))
}

// ──────────────────────────────────────────────────────────────────────────
// FLAC — strip metadata blocks except STREAMINFO, keep audio frames.
// ──────────────────────────────────────────────────────────────────────────

/// Try to sanitize a FLAC file by stripping all metadata blocks except
/// STREAMINFO (block type 0, mandatory). Returns `None` if not FLAC.
pub fn try_sanitize_flac(input: &[u8]) -> Option<Result<NativeAudioResult, DefenderError>> {
    if input.len() < 8 || &input[0..4] != b"fLaC" {
        return None;
    }

    // FLAC structure: "fLaC" (4) + metadata blocks + audio frames.
    // Each metadata block header: 1 byte (is_last:1 + type:7) + 3 bytes (length).
    let mut offset = 4usize;
    let mut streaminfo: Option<&[u8]> = None;
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;
    let mut audio_start = 0usize;

    for _ in 0..256 {
        if offset + 4 > input.len() {
            return Some(Err(DefenderError::Audio(
                "FLAC metadata block header truncated".to_string(),
            )));
        }
        let header_byte = input[offset];
        let is_last = (header_byte & 0x80) != 0;
        let block_type = header_byte & 0x7F;
        let block_length = ((input[offset + 1] as usize) << 16)
            | ((input[offset + 2] as usize) << 8)
            | (input[offset + 3] as usize);
        let data_start = offset + 4;
        let data_end = match data_start.checked_add(block_length) {
            Some(value) if value <= input.len() => value,
            _ => {
                return Some(Err(DefenderError::Audio(
                    "FLAC metadata block extends past end of file".to_string(),
                )));
            }
        };

        match block_type {
            0 => {
                // STREAMINFO — must keep.
                streaminfo = Some(&input[data_start..data_end]);
            }
            _ => {
                // VORBIS_COMMENT (4), PICTURE (6), APPLICATION (2),
                // SEEKTABLE (3), CUESHEET (5), PADDING (1), etc. — strip all.
                stripped_count += 1;
                stripped_bytes += 4u64 + block_length as u64;
            }
        }

        offset = data_end;
        if is_last {
            audio_start = offset;
            break;
        }
    }

    let Some(si_data) = streaminfo else {
        return Some(Err(DefenderError::Audio(
            "FLAC has no STREAMINFO block".to_string(),
        )));
    };
    if audio_start == 0 || audio_start >= input.len() {
        return Some(Err(DefenderError::Audio(
            "FLAC has no audio frames after metadata".to_string(),
        )));
    }

    // Rebuild: "fLaC" + STREAMINFO (marked as last metadata block) + audio frames.
    let audio_frames = &input[audio_start..];
    let mut output = Vec::with_capacity(4 + 4 + si_data.len() + audio_frames.len());
    output.extend_from_slice(b"fLaC");
    // STREAMINFO header: is_last=1, type=0 → 0x80, then 3-byte length.
    output.push(0x80);
    let si_len = si_data.len();
    output.push(((si_len >> 16) & 0xFF) as u8);
    output.push(((si_len >> 8) & 0xFF) as u8);
    output.push((si_len & 0xFF) as u8);
    output.extend_from_slice(si_data);
    output.extend_from_slice(audio_frames);

    Some(Ok(NativeAudioResult {
        output_bytes: output,
        mime: "audio/flac",
        stripped_count,
        stripped_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MP3 ──

    #[test]
    fn mp3_strips_id3v2_header() {
        // Build: ID3v2 header (10 bytes + 4 bytes payload) + MP3 sync frame
        let mut input = Vec::new();
        input.extend_from_slice(b"ID3");
        input.extend_from_slice(&[4, 0, 0]); // version + flags
        input.extend_from_slice(&[0, 0, 0, 4]); // synchsafe size = 4
        input.extend_from_slice(&[0u8; 4]); // tag payload
        // MP3 sync word
        input.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        input.extend_from_slice(&[0u8; 100]); // frame data

        let result = try_sanitize_mp3(&input).unwrap().unwrap();
        assert_eq!(result.mime, "audio/mpeg");
        assert_eq!(result.stripped_count, 1);
        assert_eq!(result.stripped_bytes, 14); // 10 header + 4 payload
        assert_eq!(&result.output_bytes[0..2], &[0xFF, 0xFB]);
    }

    #[test]
    fn mp3_strips_id3v1_tail() {
        let mut input = vec![0xFF, 0xFB, 0x90, 0x00]; // sync
        input.extend_from_slice(&[0u8; 100]); // frame data
        // ID3v1 tag (128 bytes starting with "TAG")
        let mut tag = vec![0u8; 128];
        tag[0] = b'T';
        tag[1] = b'A';
        tag[2] = b'G';
        input.extend_from_slice(&tag);

        let result = try_sanitize_mp3(&input).unwrap().unwrap();
        assert_eq!(result.stripped_count, 1);
        assert_eq!(result.output_bytes.len(), 104); // 4 sync + 100 frame
    }

    #[test]
    fn mp3_rejects_non_mp3() {
        let input = b"this is not an mp3 file at all";
        assert!(try_sanitize_mp3(input).is_none());
    }

    // ── WAV ──

    #[test]
    fn wav_strips_list_chunk() {
        let mut input = Vec::new();
        // RIFF header
        input.extend_from_slice(b"RIFF");
        input.extend_from_slice(&[0u8; 4]); // size placeholder
        input.extend_from_slice(b"WAVE");
        // fmt chunk (16 bytes: PCM, mono, 44100, 16-bit)
        input.extend_from_slice(b"fmt ");
        input.extend_from_slice(&16u32.to_le_bytes());
        input.extend_from_slice(&1u16.to_le_bytes()); // PCM
        input.extend_from_slice(&1u16.to_le_bytes()); // mono
        input.extend_from_slice(&44100u32.to_le_bytes());
        input.extend_from_slice(&88200u32.to_le_bytes()); // byte rate
        input.extend_from_slice(&2u16.to_le_bytes()); // block align
        input.extend_from_slice(&16u16.to_le_bytes()); // bits/sample
        // LIST chunk (metadata — should be stripped)
        input.extend_from_slice(b"LIST");
        input.extend_from_slice(&8u32.to_le_bytes());
        input.extend_from_slice(b"INFOtest");
        // data chunk
        input.extend_from_slice(b"data");
        input.extend_from_slice(&4u32.to_le_bytes());
        input.extend_from_slice(&[0x80, 0x00, 0x80, 0x00]);
        // Fix RIFF size
        let riff_size = (input.len() - 8) as u32;
        input[4..8].copy_from_slice(&riff_size.to_le_bytes());

        let result = try_sanitize_wav(&input).unwrap().unwrap();
        assert_eq!(result.mime, "audio/wav");
        assert_eq!(result.stripped_count, 1); // LIST stripped
        assert!(result.stripped_bytes > 0);
        // Output should NOT contain "LIST"
        assert!(!result.output_bytes.windows(4).any(|w| w == b"LIST"));
        // Output should contain fmt and data
        assert!(result.output_bytes.windows(4).any(|w| w == b"fmt "));
        assert!(result.output_bytes.windows(4).any(|w| w == b"data"));
    }

    #[test]
    fn wav_rejects_non_riff() {
        assert!(try_sanitize_wav(b"not a wav file").is_none());
    }

    // ── FLAC ──

    #[test]
    fn flac_strips_vorbis_comment() {
        let mut input = Vec::new();
        input.extend_from_slice(b"fLaC");
        // STREAMINFO block (type 0, not last, length 34)
        input.push(0x00); // not last, type 0
        input.extend_from_slice(&[0, 0, 34]);
        input.extend_from_slice(&[0u8; 34]); // STREAMINFO data

        // VORBIS_COMMENT block (type 4, is_last, length 10)
        input.push(0x84); // is_last=1, type=4
        input.extend_from_slice(&[0, 0, 10]);
        input.extend_from_slice(&[0u8; 10]); // comment data

        // Audio frames
        input.extend_from_slice(&[0xFF, 0xF8, 0x00, 0x00]); // fake sync
        input.extend_from_slice(&[0u8; 50]);

        let result = try_sanitize_flac(&input).unwrap().unwrap();
        assert_eq!(result.mime, "audio/flac");
        assert_eq!(result.stripped_count, 1); // VORBIS_COMMENT stripped
        // Output starts with "fLaC" + STREAMINFO (is_last) + audio
        assert_eq!(&result.output_bytes[0..4], b"fLaC");
        assert_eq!(result.output_bytes[4], 0x80); // is_last=1, type=0
    }

    #[test]
    fn flac_rejects_non_flac() {
        assert!(try_sanitize_flac(b"not a flac file").is_none());
    }

    #[test]
    fn flac_rejects_missing_streaminfo() {
        let mut input = Vec::new();
        input.extend_from_slice(b"fLaC");
        // Only a VORBIS_COMMENT block (type 4), no STREAMINFO
        input.push(0x84); // is_last, type 4
        input.extend_from_slice(&[0, 0, 4]);
        input.extend_from_slice(&[0u8; 4]);
        // audio frames
        input.extend_from_slice(&[0u8; 20]);

        let result = try_sanitize_flac(&input).unwrap();
        assert!(result.is_err());
    }
}
