//! Native (pure-Rust, no-ffmpeg) container sanitizer for MP4/M4A/MOV files.
//!
//! ISO Base Media File Format (ISO BMFF / MPEG-4 Part 12) stores data in
//! nested boxes ("atoms"). Each atom has a 4-byte big-endian size followed
//! by a 4-byte type (FourCC). Metadata lives primarily in `udta` (user
//! data) and `meta` (metadata) atoms nested inside `moov`.
//!
//! This handler walks the atom tree, keeps structural atoms required for
//! playback (ftyp, moov, mdat, and their critical children), and strips
//! everything that carries metadata or is non-essential (udta, meta, free,
//! skip, wide, uuid, etc.).
//!
//! The encoded audio/video bitstream inside `mdat` is preserved bit-for-bit.
//! No codec execution happens.

use crate::DefenderError;

/// Result from MP4 native sanitization.
pub struct Mp4SanitizeResult {
    pub output_bytes: Vec<u8>,
    pub stripped_count: u32,
    pub stripped_bytes: u64,
}

/// Maximum atom nesting depth. Prevents stack overflow on recursive
/// descent through crafted inputs with thousands of nested containers.
const MAX_DEPTH: u32 = 32;

/// Maximum number of atoms we will walk at any single nesting level.
const MAX_ATOMS_PER_LEVEL: u32 = 4096;

/// Atoms that are ALWAYS stripped, at any nesting depth.
const STRIP_TYPES: &[&[u8; 4]] = &[
    b"udta", // User data — artist, title, GPS, album art, etc.
    b"meta", // Metadata container (iTunes ilst, ID3, etc.)
    b"free", // Free space padding.
    b"skip", // Alias for free.
    b"wide", // 64-bit size placeholder (legacy).
    b"uuid", // Extensible UUID-based atoms (often carries vendor metadata).
    b"pdin", // Progressive download info.
];

/// Container atoms whose children we recurse into (to find and strip
/// nested udta/meta). Children not in STRIP_TYPES are kept.
const CONTAINER_TYPES: &[&[u8; 4]] = &[
    b"moov", // Movie (top-level container for tracks).
    b"trak", // Track.
    b"mdia", // Media.
    b"minf", // Media information.
    b"stbl", // Sample table.
    b"edts", // Edit list.
    b"dinf", // Data information.
    b"sinf", // Protection scheme info.
    b"mvex", // Movie extends (fragmented MP4).
    b"moof", // Movie fragment.
    b"traf", // Track fragment.
];

/// Try to sanitize an MP4/M4A/MOV file. Returns `None` if the input
/// doesn't look like an ISO BMFF container.
pub fn try_sanitize_mp4(input: &[u8]) -> Option<Result<Mp4SanitizeResult, DefenderError>> {
    // Quick check: MP4 files start with a box whose type is typically
    // "ftyp" (at offset 4). Some files start with "moov" or "mdat"
    // (streaming-optimized), or "free"/"skip" before ftyp.
    if input.len() < 8 {
        return None;
    }
    let first_type = &input[4..8];
    let looks_like_mp4 = first_type == b"ftyp"
        || first_type == b"moov"
        || first_type == b"mdat"
        || first_type == b"free"
        || first_type == b"skip"
        || first_type == b"wide"
        || first_type == b"styp"; // segment type (fragmented MP4)
    if !looks_like_mp4 {
        return None;
    }

    Some(sanitize_and_fixup(input))
}

/// Top-level sanitization with stco/co64 offset fixup.
///
/// When we strip atoms that precede `mdat`, the absolute byte offsets
/// stored in `stco` (32-bit) and `co64` (64-bit) inside `moov→trak→
/// mdia→minf→stbl` become stale — they point N bytes too far because
/// we removed N bytes of metadata/free atoms. We compute the delta and
/// patch every offset entry in-place.
fn sanitize_and_fixup(input: &[u8]) -> Result<Mp4SanitizeResult, DefenderError> {
    // 1. Find original mdat offset.
    let orig_mdat_offset = find_atom_offset(input, b"mdat");

    // 2. Sanitize.
    let mut result = sanitize_level(input, 0)?;

    // 3. Find new mdat offset in output.
    let new_mdat_offset = find_atom_offset(&result.output_bytes, b"mdat");

    // 4. If moov comes before mdat and we changed sizes, patch offsets.
    if let (Some(orig), Some(new_off)) = (orig_mdat_offset, new_mdat_offset) {
        let delta = orig as i64 - new_off as i64;
        if delta != 0 {
            fixup_sample_offsets(&mut result.output_bytes, delta)?;
        }
    }

    Ok(result)
}

/// Find the byte offset of the first top-level atom with the given type.
fn find_atom_offset(data: &[u8], target: &[u8; 4]) -> Option<usize> {
    let mut offset = 0usize;
    for _ in 0..MAX_ATOMS_PER_LEVEL {
        if offset + 8 > data.len() {
            return None;
        }
        let size32 = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let atom_type = &data[offset + 4..offset + 8];
        if atom_type == target {
            return Some(offset);
        }
        let atom_size = if size32 == 1 {
            if offset + 16 > data.len() {
                return None;
            }
            u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]) as usize
        } else if size32 == 0 {
            return None; // extends to EOF, mdat can't be after this
        } else {
            size32 as usize
        };
        if atom_size < 8 {
            return None;
        }
        offset += atom_size;
        if offset > data.len() {
            return None;
        }
    }
    None
}

/// Walk the output buffer for `stco` and `co64` atoms and adjust every
/// offset entry by `delta` (positive = offsets shift right).
fn fixup_sample_offsets(output: &mut [u8], delta: i64) -> Result<(), DefenderError> {
    let mut positions = Vec::new();
    // Find all stco/co64 atoms in the buffer by scanning for their FourCC.
    // This is a flat scan — we look at every 4-byte-aligned position after
    // a plausible length field. Simpler than recursive tree walk and safe
    // because stco/co64 FourCCs are unique enough in practice.
    let mut i = 0;
    while i + 12 <= output.len() {
        let atom_type = &output[i + 4..i + 8];
        if atom_type == b"stco" || atom_type == b"co64" {
            let size = u32::from_be_bytes([output[i], output[i + 1], output[i + 2], output[i + 3]])
                as usize;
            if size >= 16 && i + size <= output.len() {
                positions.push((i, size, atom_type == b"co64"));
            }
        }
        // Advance by atom size if valid, else by 1.
        let size =
            u32::from_be_bytes([output[i], output[i + 1], output[i + 2], output[i + 3]]) as usize;
        if size >= 8 && i + size <= output.len() {
            i += size;
        } else {
            i += 1;
        }
    }

    for (atom_offset, atom_size, is_64bit) in positions {
        let data_start = atom_offset + 8; // skip atom header
        // version (1) + flags (3) + entry_count (4) = 8 bytes before entries
        if data_start + 8 > output.len() {
            continue;
        }
        let entry_count = u32::from_be_bytes([
            output[data_start + 4],
            output[data_start + 5],
            output[data_start + 6],
            output[data_start + 7],
        ]) as usize;
        let entries_start = data_start + 8;
        let entry_size = if is_64bit { 8 } else { 4 };
        let expected_size = 8 + 8 + entry_count * entry_size; // header + version+count + entries
        if expected_size > atom_size {
            continue;
        }

        for j in 0..entry_count {
            let pos = entries_start + j * entry_size;
            if pos + entry_size > output.len() {
                break;
            }
            if is_64bit {
                let old = u64::from_be_bytes([
                    output[pos],
                    output[pos + 1],
                    output[pos + 2],
                    output[pos + 3],
                    output[pos + 4],
                    output[pos + 5],
                    output[pos + 6],
                    output[pos + 7],
                ]);
                let new_val = (old as i64 - delta) as u64;
                output[pos..pos + 8].copy_from_slice(&new_val.to_be_bytes());
            } else {
                let old = u32::from_be_bytes([
                    output[pos],
                    output[pos + 1],
                    output[pos + 2],
                    output[pos + 3],
                ]);
                let new_val = (old as i64 - delta) as u32;
                output[pos..pos + 4].copy_from_slice(&new_val.to_be_bytes());
            }
        }
    }
    Ok(())
}

/// Walk atoms at a given nesting level, keeping critical atoms and
/// stripping metadata. Container atoms are recursed into.
fn sanitize_level(data: &[u8], depth: u32) -> Result<Mp4SanitizeResult, DefenderError> {
    if depth > MAX_DEPTH {
        return Err(DefenderError::Video(format!(
            "MP4 atom nesting depth exceeds {MAX_DEPTH}"
        )));
    }

    let mut output = Vec::with_capacity(data.len());
    let mut stripped_count = 0u32;
    let mut stripped_bytes = 0u64;
    let mut offset = 0usize;

    for _ in 0..MAX_ATOMS_PER_LEVEL {
        if offset >= data.len() {
            break;
        }
        if offset + 8 > data.len() {
            // Trailing bytes that don't form a complete atom header —
            // drop them silently (common in truncated files).
            stripped_bytes += (data.len() - offset) as u64;
            break;
        }

        let (atom_size, header_size) = read_atom_size(data, offset)?;
        let atom_type: [u8; 4] = [
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ];

        let atom_end = if atom_size == 0 {
            // Size 0 means "extends to end of enclosing data".
            data.len()
        } else {
            let end = offset + atom_size as usize;
            if end > data.len() {
                return Err(DefenderError::Video(format!(
                    "MP4 atom `{}` at offset {offset} declares size {atom_size} but only {} bytes remain",
                    String::from_utf8_lossy(&atom_type),
                    data.len() - offset
                )));
            }
            end
        };

        // Reject zero-size container atoms — they extend to EOF which makes
        // it impossible to reliably separate container children from siblings.
        let is_container = CONTAINER_TYPES.iter().any(|t| **t == atom_type);
        if atom_size == 0 && is_container {
            return Err(DefenderError::Video(format!(
                "MP4 container atom `{}` has size 0 (ambiguous boundaries)",
                String::from_utf8_lossy(&atom_type)
            )));
        }

        let should_strip = STRIP_TYPES.iter().any(|t| **t == atom_type);
        if should_strip {
            stripped_count += 1;
            stripped_bytes += (atom_end - offset) as u64;
            offset = atom_end;
            continue;
        }

        if is_container {
            // Recurse: re-build the container's children, stripping
            // metadata inside.
            let children_start = offset + header_size;
            let children_data = &data[children_start..atom_end];
            let child_result = sanitize_level(children_data, depth + 1)?;
            stripped_count += child_result.stripped_count;
            stripped_bytes += child_result.stripped_bytes;

            // Re-emit container with cleaned children.
            let new_atom_size = header_size + child_result.output_bytes.len();
            if header_size == 8 {
                output.extend_from_slice(&(new_atom_size as u32).to_be_bytes());
            } else {
                // Extended size (16-byte header): write 1 in first 4 bytes,
                // then type, then 8-byte extended size.
                output.extend_from_slice(&1u32.to_be_bytes());
            }
            output.extend_from_slice(&atom_type);
            if header_size == 16 {
                output.extend_from_slice(&(new_atom_size as u64).to_be_bytes());
            }
            output.extend_from_slice(&child_result.output_bytes);
        } else {
            // Leaf atom (mdat, ftyp, mvhd, stts, stsc, stsz, etc.) —
            // copy verbatim.
            output.extend_from_slice(&data[offset..atom_end]);
        }

        offset = atom_end;
    }

    Ok(Mp4SanitizeResult {
        output_bytes: output,
        stripped_count,
        stripped_bytes,
    })
}

/// Read atom size, handling both standard (4-byte) and extended (8-byte)
/// sizes. Returns `(total_atom_size, header_size)`.
fn read_atom_size(data: &[u8], offset: usize) -> Result<(u64, usize), DefenderError> {
    let size32 = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);

    if size32 == 1 {
        // Extended size: next 8 bytes after the type field.
        if offset + 16 > data.len() {
            return Err(DefenderError::Video(
                "MP4 atom has extended size marker but not enough bytes for 64-bit size"
                    .to_string(),
            ));
        }
        let size64 = u64::from_be_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        Ok((size64, 16))
    } else if size32 == 0 {
        // Atom extends to end of data.
        Ok((0, 8))
    } else {
        Ok((size32 as u64, 8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_atom(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let size = (8 + payload.len()) as u32;
        let mut atom = Vec::with_capacity(size as usize);
        atom.extend_from_slice(&size.to_be_bytes());
        atom.extend_from_slice(fourcc);
        atom.extend_from_slice(payload);
        atom
    }

    fn make_container(fourcc: &[u8; 4], children: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        for child in children {
            payload.extend_from_slice(child);
        }
        make_atom(fourcc, &payload)
    }

    #[test]
    fn strips_top_level_free_and_udta() {
        let mut input = Vec::new();
        input.extend_from_slice(&make_atom(b"ftyp", b"isom\x00\x00\x00\x00"));
        input.extend_from_slice(&make_atom(b"free", &[0u8; 100]));
        input.extend_from_slice(&make_atom(b"udta", b"artist=evil"));
        input.extend_from_slice(&make_atom(b"mdat", b"audio-data-here"));

        let result = try_sanitize_mp4(&input).unwrap().unwrap();
        assert_eq!(result.stripped_count, 2); // free + udta
        // Output should contain ftyp and mdat but not free/udta.
        assert!(result.output_bytes.windows(4).any(|w| w == b"ftyp"));
        assert!(result.output_bytes.windows(4).any(|w| w == b"mdat"));
        assert!(!result.output_bytes.windows(4).any(|w| w == b"free"));
        assert!(!result.output_bytes.windows(4).any(|w| w == b"udta"));
    }

    #[test]
    fn strips_udta_inside_moov() {
        let moov = make_container(
            b"moov",
            &[
                make_atom(b"mvhd", &[0u8; 28]),
                make_container(b"trak", &[make_atom(b"tkhd", &[0u8; 20])]),
                make_atom(b"udta", b"GPS=evil-location"),
            ],
        );
        let mut input = Vec::new();
        input.extend_from_slice(&make_atom(b"ftyp", b"isom\x00\x00\x00\x00"));
        input.extend_from_slice(&moov);
        input.extend_from_slice(&make_atom(b"mdat", b"stream-data"));

        let result = try_sanitize_mp4(&input).unwrap().unwrap();
        assert_eq!(result.stripped_count, 1); // udta inside moov
        // moov should exist but udta should not.
        assert!(result.output_bytes.windows(4).any(|w| w == b"moov"));
        assert!(result.output_bytes.windows(4).any(|w| w == b"trak"));
        assert!(!result.output_bytes.windows(4).any(|w| w == b"udta"));
    }

    #[test]
    fn preserves_mdat_bitperfect() {
        let mdat_data = b"codec-bitstream-must-survive-exactly";
        let mut input = Vec::new();
        input.extend_from_slice(&make_atom(b"ftyp", b"mp41"));
        input.extend_from_slice(&make_atom(b"mdat", mdat_data));

        let result = try_sanitize_mp4(&input).unwrap().unwrap();
        // Find mdat in output, verify payload.
        let mdat_pos = result
            .output_bytes
            .windows(4)
            .position(|w| w == b"mdat")
            .unwrap();
        let payload_start = mdat_pos + 4; // after "mdat" type
        let payload_end = payload_start + mdat_data.len();
        assert_eq!(&result.output_bytes[payload_start..payload_end], mdat_data);
    }

    #[test]
    fn rejects_non_mp4() {
        assert!(try_sanitize_mp4(b"not an mp4 file at all").is_none());
    }

    #[test]
    fn rejects_truncated_atom() {
        let mut input = make_atom(b"ftyp", b"isom");
        // Add a truncated atom: says 100 bytes but only 8 available.
        input.extend_from_slice(&100u32.to_be_bytes());
        input.extend_from_slice(b"mdat");

        let result = try_sanitize_mp4(&input).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn handles_zero_size_final_atom() {
        let mut input = Vec::new();
        input.extend_from_slice(&make_atom(b"ftyp", b"isom"));
        // Zero-size mdat — extends to EOF.
        input.extend_from_slice(&0u32.to_be_bytes());
        input.extend_from_slice(b"mdat");
        input.extend_from_slice(b"rest-of-file-is-mdat");

        let result = try_sanitize_mp4(&input).unwrap().unwrap();
        assert!(result.output_bytes.windows(4).any(|w| w == b"mdat"));
    }

    #[test]
    fn strips_meta_inside_nested_trak() {
        let trak = make_container(
            b"trak",
            &[
                make_atom(b"tkhd", &[0u8; 20]),
                make_container(
                    b"mdia",
                    &[
                        make_atom(b"mdhd", &[0u8; 20]),
                        make_atom(b"meta", b"should-be-stripped"),
                    ],
                ),
            ],
        );
        let moov = make_container(b"moov", &[make_atom(b"mvhd", &[0u8; 28]), trak]);
        let mut input = make_atom(b"ftyp", b"isom");
        input.extend_from_slice(&moov);

        let result = try_sanitize_mp4(&input).unwrap().unwrap();
        assert!(result.stripped_count >= 1);
        assert!(!result.output_bytes.windows(4).any(|w| w == b"meta"));
    }
}
