//! Native OGG container sanitizer for Opus and Vorbis audio.
//!
//! OGG is a page-based transport format. Metadata in OGG-Opus lives in an
//! `OpusTags` packet (page 1), and in OGG-Vorbis in a comment-header packet
//! (packet type 0x03). Both use VorbisComment encoding.
//!
//! Strategy: walk pages, identify the comment/tags page by its magic bytes,
//! **replace** it with a minimal empty comment (the spec requires this page
//! to exist), copy all other pages verbatim, recalculate CRC for the
//! modified page.

use crate::DefenderError;

pub struct OggSanitizeResult {
    pub output_bytes: Vec<u8>,
    pub codec: &'static str,
    pub stripped_bytes: u64,
}

const OGG_CAPTURE: &[u8; 4] = b"OggS";
const MAX_PAGES: u32 = 65536;

/// Try to sanitize an OGG file (Opus or Vorbis). Returns `None` if not OGG.
pub fn try_sanitize_ogg(input: &[u8]) -> Option<Result<OggSanitizeResult, DefenderError>> {
    if input.len() < 27 || &input[0..4] != OGG_CAPTURE {
        return None;
    }
    Some(sanitize_ogg(input))
}

fn sanitize_ogg(input: &[u8]) -> Result<OggSanitizeResult, DefenderError> {
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0usize;
    let mut codec: Option<&'static str> = None;
    let mut stripped_bytes = 0u64;
    let mut page_index = 0u32;
    // Track whether we're in the middle of stripping a multi-page comment.
    // OGG allows large packets (e.g., album art in comments) to span
    // multiple pages via continuation flag (header_type & 0x01).
    let mut stripping_continuation = false;

    while offset < input.len() && page_index < MAX_PAGES {
        if offset + 27 > input.len() {
            return Err(DefenderError::Audio(
                "OGG page header truncated".to_string(),
            ));
        }
        if &input[offset..offset + 4] != OGG_CAPTURE {
            return Err(DefenderError::Audio(format!(
                "OGG sync lost at offset {offset}"
            )));
        }

        let version = input[offset + 4];
        if version != 0 {
            return Err(DefenderError::Audio(format!(
                "unsupported OGG version {version}"
            )));
        }

        let header_type = input[offset + 5];
        let num_segments = input[offset + 26] as usize;
        let segment_table_end = offset + 27 + num_segments;
        if segment_table_end > input.len() {
            return Err(DefenderError::Audio(
                "OGG segment table truncated".to_string(),
            ));
        }

        let data_size: usize = input[offset + 27..segment_table_end]
            .iter()
            .map(|&v| v as usize)
            .sum();
        let data_start = segment_table_end;
        let data_end = match data_start.checked_add(data_size) {
            Some(v) if v <= input.len() => v,
            _ => {
                return Err(DefenderError::Audio(
                    "OGG page data extends past end of file".to_string(),
                ));
            }
        };
        let page_end = data_end;
        let page_data = &input[data_start..data_end];

        // Identify codec from BOS page.
        let is_bos = (header_type & 0x02) != 0;
        if is_bos && codec.is_none() {
            if page_data.len() >= 8 && &page_data[0..8] == b"OpusHead" {
                codec = Some("opus");
            } else if page_data.len() >= 7 && page_data[0] == 0x01 && &page_data[1..7] == b"vorbis"
            {
                codec = Some("vorbis");
            }
        }

        // Check if this is the comment/tags page that should be replaced.
        let is_comment_page = match codec {
            Some("opus") => page_data.len() >= 8 && &page_data[0..8] == b"OpusTags",
            Some("vorbis") => {
                page_data.len() >= 7 && page_data[0] == 0x03 && &page_data[1..7] == b"vorbis"
            }
            _ => false,
        };

        // Handle continuation pages from a multi-page comment we're stripping.
        let is_continuation = (header_type & 0x01) != 0;
        if stripping_continuation && is_continuation {
            // This page is a continuation of the comment packet we replaced.
            // Drop it entirely — the replacement comment fits in one page.
            stripped_bytes += page_data.len() as u64;
            offset = page_end;
            page_index += 1;
            continue;
        }
        stripping_continuation = false;

        if is_comment_page {
            // Build minimal replacement comment page.
            let minimal_data = match codec {
                Some("opus") => build_minimal_opus_tags(),
                Some("vorbis") => build_minimal_vorbis_comment(),
                _ => unreachable!(),
            };
            stripped_bytes += page_data.len() as u64;
            stripping_continuation = true; // flag for subsequent continuation pages

            // Build replacement page with same granule/serial/seq but new data.
            let replacement = build_ogg_page(
                &input[offset..segment_table_end], // original header (27+segments)
                &minimal_data,
            )?;
            output.extend_from_slice(&replacement);
        } else {
            // Copy page verbatim.
            output.extend_from_slice(&input[offset..page_end]);
        }

        offset = page_end;
        page_index += 1;
    }

    let detected_codec = codec.unwrap_or("unknown");
    Ok(OggSanitizeResult {
        output_bytes: output,
        codec: detected_codec,
        stripped_bytes,
    })
}

/// Build a minimal OpusTags packet: magic + empty vendor + 0 comments.
fn build_minimal_opus_tags() -> Vec<u8> {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(b"OpusTags");
    data.extend_from_slice(&0u32.to_le_bytes()); // vendor string length = 0
    data.extend_from_slice(&0u32.to_le_bytes()); // comment count = 0
    data
}

/// Build a minimal Vorbis comment header: type + magic + empty vendor + 0 comments + framing bit.
fn build_minimal_vorbis_comment() -> Vec<u8> {
    let mut data = Vec::with_capacity(16);
    data.push(0x03); // packet type
    data.extend_from_slice(b"vorbis");
    data.extend_from_slice(&0u32.to_le_bytes()); // vendor string length = 0
    data.extend_from_slice(&0u32.to_le_bytes()); // comment count = 0
    data.push(0x01); // framing bit
    data
}

/// Build an OGG page with new data, reusing the original page's header
/// fields (header_type, granule, serial, seq) but with new segment table
/// and CRC.
fn build_ogg_page(
    original_header: &[u8], // 27 + original_segments bytes
    new_data: &[u8],
) -> Result<Vec<u8>, DefenderError> {
    // New segment table: each segment is up to 255 bytes.
    let mut segment_table = Vec::new();
    let mut remaining = new_data.len();
    loop {
        if remaining >= 255 {
            segment_table.push(255u8);
            remaining -= 255;
        } else {
            segment_table.push(remaining as u8);
            break;
        }
    }

    if segment_table.len() > 255 {
        return Err(DefenderError::Audio(
            "OGG replacement page requires >255 segments (data too large for single page)"
                .to_string(),
        ));
    }
    let mut page = Vec::with_capacity(27 + segment_table.len() + new_data.len());
    // Copy first 26 bytes of header (capture, version, header_type,
    // granule, serial, page_seq) from original.
    page.extend_from_slice(&original_header[..26]);
    // Number of segments.
    page.push(segment_table.len() as u8);
    // Segment table.
    page.extend_from_slice(&segment_table);
    // Page data.
    page.extend_from_slice(new_data);

    // CRC: set CRC field to 0, compute over whole page, write CRC.
    page[22] = 0;
    page[23] = 0;
    page[24] = 0;
    page[25] = 0;
    let crc = ogg_crc32(&page);
    page[22..26].copy_from_slice(&crc.to_le_bytes());

    Ok(page)
}

/// OGG CRC-32: polynomial 0x04C11DB7, initial value 0, no final XOR,
/// **not bit-reflected** (differs from standard PKZIP CRC-32).
fn ogg_crc32(data: &[u8]) -> u32 {
    // Lookup table built from polynomial 0x04C11DB7 (non-reflected).
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i << 24;
            for _ in 0..8 {
                if crc & 0x8000_0000 != 0 {
                    crc = (crc << 1) ^ 0x04C1_1DB7;
                } else {
                    crc <<= 1;
                }
            }
            table[i as usize] = crc;
        }
        table
    });

    let mut crc = 0u32;
    for &byte in data {
        let index = ((crc >> 24) ^ (byte as u32)) & 0xFF;
        crc = (crc << 8) ^ TABLE[index as usize];
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal OGG page with given header_type, serial, seq, and data.
    fn make_ogg_page(header_type: u8, serial: u32, seq: u32, granule: i64, data: &[u8]) -> Vec<u8> {
        let mut segments = Vec::new();
        let mut remaining = data.len();
        loop {
            if remaining >= 255 {
                segments.push(255u8);
                remaining -= 255;
            } else {
                segments.push(remaining as u8);
                break;
            }
        }

        let mut page = Vec::new();
        page.extend_from_slice(b"OggS");
        page.push(0); // version
        page.push(header_type);
        page.extend_from_slice(&granule.to_le_bytes());
        page.extend_from_slice(&serial.to_le_bytes());
        page.extend_from_slice(&seq.to_le_bytes());
        page.extend_from_slice(&[0u8; 4]); // CRC placeholder
        page.push(segments.len() as u8);
        page.extend_from_slice(&segments);
        page.extend_from_slice(data);

        // Compute and write CRC.
        let crc = ogg_crc32(&page);
        page[22..26].copy_from_slice(&crc.to_le_bytes());
        page
    }

    fn make_opus_ogg() -> Vec<u8> {
        let mut file = Vec::new();
        // Page 0: BOS + OpusHead
        let mut opus_head = Vec::new();
        opus_head.extend_from_slice(b"OpusHead");
        opus_head.push(1); // version
        opus_head.push(1); // channels
        opus_head.extend_from_slice(&0u16.to_le_bytes()); // pre-skip
        opus_head.extend_from_slice(&48000u32.to_le_bytes()); // sample rate
        opus_head.extend_from_slice(&0i16.to_le_bytes()); // output gain
        opus_head.push(0); // channel mapping
        file.extend_from_slice(&make_ogg_page(0x02, 1, 0, 0, &opus_head));

        // Page 1: OpusTags with metadata
        let mut tags = Vec::new();
        tags.extend_from_slice(b"OpusTags");
        let vendor = b"test-vendor";
        tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
        tags.extend_from_slice(vendor);
        tags.extend_from_slice(&1u32.to_le_bytes()); // 1 comment
        let comment = b"ARTIST=Evil";
        tags.extend_from_slice(&(comment.len() as u32).to_le_bytes());
        tags.extend_from_slice(comment);
        file.extend_from_slice(&make_ogg_page(0x00, 1, 1, 0, &tags));

        // Page 2: audio data (EOS)
        file.extend_from_slice(&make_ogg_page(0x04, 1, 2, 48000, b"fake-opus-packets"));

        file
    }

    #[test]
    fn strips_opus_tags_metadata() {
        let input = make_opus_ogg();
        let result = try_sanitize_ogg(&input).unwrap().unwrap();
        assert_eq!(result.codec, "opus");
        assert!(result.stripped_bytes > 0);
        // Output should NOT contain "Evil" or "test-vendor".
        let output_str = String::from_utf8_lossy(&result.output_bytes);
        assert!(!output_str.contains("Evil"));
        assert!(!output_str.contains("test-vendor"));
        // Output should still contain OpusTags (minimal).
        assert!(result.output_bytes.windows(8).any(|w| w == b"OpusTags"));
        // Output should still contain OpusHead.
        assert!(result.output_bytes.windows(8).any(|w| w == b"OpusHead"));
    }

    #[test]
    fn preserves_audio_data_pages() {
        let input = make_opus_ogg();
        let result = try_sanitize_ogg(&input).unwrap().unwrap();
        // Audio data should survive.
        assert!(
            result
                .output_bytes
                .windows(17)
                .any(|w| w == b"fake-opus-packets")
        );
    }

    #[test]
    fn ogg_crc_known_value() {
        // "OggS" with version=0 and all-zero fields should produce a known CRC.
        // We verify the CRC function is internally consistent by round-tripping.
        let page = make_ogg_page(0x02, 42, 0, 0, b"test");
        // Verify CRC field is non-zero (computed).
        let crc_bytes = &page[22..26];
        let stored_crc =
            u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
        assert_ne!(stored_crc, 0);
        // Verify recomputing gives the same result.
        let mut check = page.clone();
        check[22] = 0;
        check[23] = 0;
        check[24] = 0;
        check[25] = 0;
        assert_eq!(ogg_crc32(&check), stored_crc);
    }

    #[test]
    fn rejects_non_ogg() {
        assert!(try_sanitize_ogg(b"not an ogg file").is_none());
    }

    #[test]
    fn rejects_truncated_page() {
        let input = make_opus_ogg();
        // Truncate mid-way through the second page (after the first page
        // completes but before the second page's data ends).
        let first_page_end = {
            let num_segments = input[26] as usize;
            let data_size: usize = input[27..27 + num_segments]
                .iter()
                .map(|&v| v as usize)
                .sum();
            27 + num_segments + data_size
        };
        let mut truncated = input[..first_page_end + 30].to_vec();
        // Ensure there's an OggS header for the second page but truncated data.
        if truncated.len() > first_page_end + 27 {
            truncated.truncate(first_page_end + 27);
        }
        let result = try_sanitize_ogg(&truncated);
        match result {
            Some(Err(_)) => {} // expected: recognized as OGG but truncated
            Some(Ok(_)) => panic!("should not succeed on truncated input"),
            None => {} // also acceptable if too short to recognize
        }
    }
}
