//! Native WebM/Matroska container sanitizer (EBML element walker).
//!
//! WebM uses EBML (Extensible Binary Meta Language) — variable-length IDs
//! and sizes. Metadata lives in `Tags` and `Attachments` elements inside
//! the top-level `Segment`. This handler walks Segment children, strips
//! Tags/Attachments/Chapters, and copies everything else verbatim.
//!
//! The encoded video/audio bitstream inside `Cluster` elements is preserved
//! bit-for-bit. No codec execution happens.

use crate::DefenderError;

pub struct WebmSanitizeResult {
    pub output_bytes: Vec<u8>,
    pub stripped_count: u32,
    pub stripped_bytes: u64,
}

// EBML element IDs (4-byte IDs stored as raw VINT bytes → u32).
const _ID_EBML: u32 = 0x1A45DFA3;
const ID_SEGMENT: u32 = 0x18538067;
const ID_TAGS: u32 = 0x1254C367;
const ID_ATTACHMENTS: u32 = 0x1941A469;
const ID_CHAPTERS: u32 = 0x1043A770;

/// Elements stripped from Segment children.
const STRIP_IDS: &[u32] = &[ID_TAGS, ID_ATTACHMENTS, ID_CHAPTERS];

const MAX_ELEMENTS: u32 = 65536;

/// Try to sanitize a WebM/Matroska file. Returns `None` if not EBML.
pub fn try_sanitize_webm(input: &[u8]) -> Option<Result<WebmSanitizeResult, DefenderError>> {
    if input.len() < 4 {
        return None;
    }
    // EBML header starts with ID 0x1A45DFA3.
    if input.len() >= 4
        && input[0] == 0x1A
        && input[1] == 0x45
        && input[2] == 0xDF
        && input[3] == 0xA3
    {
        Some(sanitize_webm(input))
    } else {
        None
    }
}

fn sanitize_webm(input: &[u8]) -> Result<WebmSanitizeResult, DefenderError> {
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0usize;
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;

    // Walk top-level elements: EBML header + Segment(s).
    for _ in 0..16 {
        if offset >= input.len() {
            break;
        }
        let (id, id_len) = read_vint_id(input, offset)?;
        let (size, size_len) = read_vint_size(input, offset + id_len)?;
        let header_len = id_len + size_len;
        let data_start = offset + header_len;

        if id == ID_SEGMENT {
            // Copy the Segment header, then walk children with filtering.
            output.extend_from_slice(&input[offset..data_start]);

            let segment_end = if size == u64::MAX {
                // Unknown size — extends to EOF.
                input.len()
            } else {
                let end = data_start + size as usize;
                if end > input.len() {
                    return Err(DefenderError::Video(
                        "WebM Segment extends past end of file".to_string(),
                    ));
                }
                end
            };

            let (clean_children, sc, sb) = filter_segment_children(input, data_start, segment_end)?;
            stripped_count += sc;
            stripped_bytes += sb;

            // If segment had known size, we need to update it.
            if size != u64::MAX {
                // Rewrite segment header with new size.
                let new_size = clean_children.len() as u64;
                let last = output.len();
                // Remove the header we just wrote.
                output.truncate(last - header_len);
                // Re-emit ID.
                output.extend_from_slice(&input[offset..offset + id_len]);
                // Re-emit size with enough bytes.
                write_vint_size(&mut output, new_size, size_len);
            }
            output.extend_from_slice(&clean_children);
            offset = segment_end;
        } else {
            // Non-Segment top-level element (EBML header, etc.) — copy verbatim.
            let elem_end = if size == u64::MAX {
                input.len()
            } else {
                data_start + size as usize
            };
            if elem_end > input.len() {
                return Err(DefenderError::Video(
                    "WebM top-level element extends past end of file".to_string(),
                ));
            }
            output.extend_from_slice(&input[offset..elem_end]);
            offset = elem_end;
        }
    }

    Ok(WebmSanitizeResult {
        output_bytes: output,
        stripped_count,
        stripped_bytes,
    })
}

/// Walk Segment children, strip Tags/Attachments/Chapters, keep everything else.
fn filter_segment_children(
    input: &[u8],
    start: usize,
    end: usize,
) -> Result<(Vec<u8>, u32, u64), DefenderError> {
    let mut output = Vec::with_capacity(end - start);
    let mut offset = start;
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;

    for _ in 0..MAX_ELEMENTS {
        if offset >= end {
            break;
        }
        if offset + 2 > input.len() {
            break;
        }

        let (id, id_len) = read_vint_id(input, offset)?;
        if offset + id_len >= input.len() {
            break;
        }
        let (size, size_len) = read_vint_size(input, offset + id_len)?;
        let header_len = id_len + size_len;
        let data_start = offset + header_len;

        let elem_end = if size == u64::MAX {
            // Unknown-size master element — valid for streaming Clusters.
            // Cap to segment boundary to prevent unbounded allocation.
            let remaining = end.saturating_sub(data_start);
            const MAX_UNKNOWN_ELEMENT: usize = 500 * 1024 * 1024; // 500 MB
            let capped = remaining.min(MAX_UNKNOWN_ELEMENT);
            data_start + capped
        } else {
            let e = data_start + size as usize;
            if e > end {
                return Err(DefenderError::Video(format!(
                    "WebM element 0x{id:X} at offset {offset} extends past Segment boundary"
                )));
            }
            e
        };

        if STRIP_IDS.contains(&id) {
            stripped_count += 1;
            stripped_bytes += (elem_end - offset) as u64;
        } else {
            output.extend_from_slice(&input[offset..elem_end]);
        }

        offset = elem_end;
    }

    Ok((output, stripped_count, stripped_bytes))
}

/// Read a VINT-encoded element ID (marker bits are part of the ID value).
fn read_vint_id(data: &[u8], offset: usize) -> Result<(u32, usize), DefenderError> {
    if offset >= data.len() {
        return Err(DefenderError::Video("EBML ID truncated".to_string()));
    }
    let first = data[offset];
    let len = vint_length(first)?;
    if offset + len > data.len() {
        return Err(DefenderError::Video("EBML ID extends past end".to_string()));
    }
    let mut value = 0u32;
    for i in 0..len {
        value = (value << 8) | data[offset + i] as u32;
    }
    Ok((value, len))
}

/// Read a VINT-encoded size (marker bits are stripped from the value).
/// Returns `u64::MAX` for "unknown size" (all data bits set to 1).
fn read_vint_size(data: &[u8], offset: usize) -> Result<(u64, usize), DefenderError> {
    if offset >= data.len() {
        return Err(DefenderError::Video("EBML size truncated".to_string()));
    }
    let first = data[offset];
    let len = vint_length(first)?;
    if offset + len > data.len() {
        return Err(DefenderError::Video(
            "EBML size extends past end".to_string(),
        ));
    }

    // Strip the marker bit from the first byte.
    let mask = 0xFFu8 >> len;
    let mut value = (first & mask) as u64;
    for i in 1..len {
        value = (value << 8) | data[offset + i] as u64;
    }

    // All data bits set = unknown size.
    let max_for_len = (1u64 << (7 * len)) - 1;
    if value == max_for_len {
        return Ok((u64::MAX, len));
    }

    Ok((value, len))
}

/// Write a VINT-encoded size into the output buffer using exactly `byte_len` bytes.
fn write_vint_size(output: &mut Vec<u8>, value: u64, byte_len: usize) {
    // byte_len must be 1..=8 for valid EBML VINT encoding.
    debug_assert!((1..=8).contains(&byte_len));
    let byte_len = byte_len.clamp(1, 8);
    // Set the marker bit at position (8*byte_len - byte_len).
    let marker = 1u64 << (8 * byte_len - byte_len);
    let encoded = marker | value;
    for i in (0..byte_len).rev() {
        output.push(((encoded >> (i * 8)) & 0xFF) as u8);
    }
}

/// Determine VINT byte length from the first byte.
fn vint_length(first_byte: u8) -> Result<usize, DefenderError> {
    if first_byte == 0 {
        return Err(DefenderError::Video(
            "EBML VINT starts with 0x00 (invalid)".to_string(),
        ));
    }
    Ok(first_byte.leading_zeros() as usize + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal EBML element: VINT id + VINT size + data.
    fn make_ebml_element(id_bytes: &[u8], data: &[u8]) -> Vec<u8> {
        let mut elem = Vec::new();
        elem.extend_from_slice(id_bytes);
        // Encode size as 1-byte VINT if small enough, else 2-byte.
        let size = data.len() as u64;
        if size < 0x7F {
            elem.push(0x80 | size as u8);
        } else if size < 0x3FFF {
            elem.push(0x40 | ((size >> 8) & 0x3F) as u8);
            elem.push((size & 0xFF) as u8);
        } else {
            panic!("test helper only supports small elements");
        }
        elem.extend_from_slice(data);
        elem
    }

    fn make_webm() -> Vec<u8> {
        let mut file = Vec::new();
        // EBML header.
        file.extend_from_slice(&make_ebml_element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &[0x42, 0x86, 0x81, 0x01], // DocType element (minimal)
        ));
        // Segment with children.
        let mut segment_data = Vec::new();
        // Info element (0x1549A966) — keep.
        segment_data.extend_from_slice(&make_ebml_element(
            &[0x15, 0x49, 0xA9, 0x66],
            b"duration-info",
        ));
        // Tracks element (0x1654AE6B) — keep.
        segment_data.extend_from_slice(&make_ebml_element(
            &[0x16, 0x54, 0xAE, 0x6B],
            b"track-config",
        ));
        // Tags element (0x1254C367) — STRIP.
        segment_data.extend_from_slice(&make_ebml_element(
            &[0x12, 0x54, 0xC3, 0x67],
            b"ARTIST=Evil",
        ));
        // Cluster element (0x1F43B675) — keep (media data).
        segment_data.extend_from_slice(&make_ebml_element(
            &[0x1F, 0x43, 0xB6, 0x75],
            b"video-audio-frames",
        ));
        // Attachments element (0x1941A469) — STRIP.
        segment_data.extend_from_slice(&make_ebml_element(
            &[0x19, 0x41, 0xA4, 0x69],
            b"attached-thumbnail.jpg",
        ));

        file.extend_from_slice(&make_ebml_element(&[0x18, 0x53, 0x80, 0x67], &segment_data));
        file
    }

    #[test]
    fn strips_tags_and_attachments() {
        let input = make_webm();
        let result = try_sanitize_webm(&input).unwrap().unwrap();
        assert_eq!(result.stripped_count, 2); // Tags + Attachments
        assert!(result.stripped_bytes > 0);
        // Should NOT contain "Evil" or "thumbnail".
        let s = String::from_utf8_lossy(&result.output_bytes);
        assert!(!s.contains("Evil"), "Tags should be stripped");
        assert!(!s.contains("thumbnail"), "Attachments should be stripped");
    }

    #[test]
    fn preserves_cluster_data() {
        let input = make_webm();
        let result = try_sanitize_webm(&input).unwrap().unwrap();
        let s = String::from_utf8_lossy(&result.output_bytes);
        assert!(
            s.contains("video-audio-frames"),
            "Cluster data must survive"
        );
        assert!(s.contains("track-config"), "Tracks must survive");
        assert!(s.contains("duration-info"), "Info must survive");
    }

    #[test]
    fn rejects_non_ebml() {
        assert!(try_sanitize_webm(b"not a webm file at all").is_none());
    }

    #[test]
    fn handles_empty_segment() {
        let mut file = Vec::new();
        file.extend_from_slice(&make_ebml_element(
            &[0x1A, 0x45, 0xDF, 0xA3],
            &[0x42, 0x86, 0x81, 0x01],
        ));
        // Segment with no children.
        file.extend_from_slice(&make_ebml_element(&[0x18, 0x53, 0x80, 0x67], &[]));
        let result = try_sanitize_webm(&file).unwrap().unwrap();
        assert_eq!(result.stripped_count, 0);
    }

    #[test]
    fn vint_length_correctness() {
        assert_eq!(vint_length(0x80).unwrap(), 1);
        assert_eq!(vint_length(0xFF).unwrap(), 1);
        assert_eq!(vint_length(0x40).unwrap(), 2);
        assert_eq!(vint_length(0x20).unwrap(), 3);
        assert_eq!(vint_length(0x10).unwrap(), 4);
        assert_eq!(vint_length(0x08).unwrap(), 5);
        assert_eq!(vint_length(0x04).unwrap(), 6);
        assert_eq!(vint_length(0x02).unwrap(), 7);
        assert_eq!(vint_length(0x01).unwrap(), 8);
        assert!(vint_length(0x00).is_err());
    }
}
