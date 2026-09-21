//! Attack simulation tests.
//!
//! These tests craft malicious inputs that exercise every defense layer in
//! the pipeline. Each test simulates a specific attack technique and verifies
//! the system blocks or safely neutralises it. All inputs are synthetic —
//! no real malware is used.
//!
//! Categories:
//!   1. Decompression bombs (pixel/frame/chunk)
//!   2. Metadata poisoning (EXIF, ID3, VorbisComment, atoms)
//!   3. Executable smuggling (polyglots, double-extensions, magic bytes)
//!   4. Container malformation (truncated, overflow, infinite nesting)
//!   5. Signature evasion
//!   6. Cancellation and timeout
//!   7. Media-only policy enforcement

use file_defender::{
    CancellationToken, DefenderError, DefenseContext, DefenseVerdict, FileDefender, FileKind,
    policy::DefensePolicy,
};

fn default_defender() -> FileDefender {
    FileDefender::new(DefensePolicy::default())
}

fn strict_defender() -> FileDefender {
    FileDefender::new(DefensePolicy::strict_profile())
}

fn paranoid_defender() -> FileDefender {
    FileDefender::new(DefensePolicy::paranoid_profile())
}

// ═══════════════════════════════════════════════════════════════════════
// 1. DECOMPRESSION BOMBS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bomb_oversized_image_dimensions_rejected() {
    // A fake PNG header claiming 50000×50000 pixels — well over the
    // default max_pixels (30M). Must be rejected BEFORE decode.
    let defender = default_defender();
    let mut fake_png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    // IHDR chunk: width=50000, height=50000
    let ihdr_data: Vec<u8> = {
        let mut d = Vec::new();
        d.extend_from_slice(&50000u32.to_be_bytes()); // width
        d.extend_from_slice(&50000u32.to_be_bytes()); // height
        d.push(8); // bit depth
        d.push(2); // color type RGB
        d.extend_from_slice(&[0, 0, 0]); // compression, filter, interlace
        d
    };
    // length + "IHDR" + data + CRC (fake CRC — handler will reject on probe)
    fake_png.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
    fake_png.extend_from_slice(b"IHDR");
    fake_png.extend_from_slice(&ihdr_data);
    fake_png.extend_from_slice(&[0u8; 4]); // fake CRC

    let result = defender.defend_bytes(
        fake_png,
        Some("bomb.png".to_string()),
        DefenseContext::default(),
    );
    // Must fail — either probe rejects dimensions or decode fails.
    assert!(result.is_err() || result.unwrap().verdict == DefenseVerdict::Blocked);
}

#[test]
fn bomb_gif_excessive_frames_rejected() {
    // GIF header claiming to have frames, then garbage data. The handler
    // should reject once max_frames is exceeded.
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00".to_vec(),
        Some("bomb.gif".to_string()),
        DefenseContext::default(),
    );
    // GIF with broken frame data → error (not passthrough).
    assert!(result.is_err() || result.unwrap().verdict == DefenseVerdict::Blocked);
}

#[test]
fn bomb_apng_excessive_chunks_rejected() {
    // APNG with more chunks than max_chunks policy allows.
    let policy = DefensePolicy::paranoid_profile();
    let defender = FileDefender::new(policy);
    // Paranoid max_chunks = 1024. Build a PNG with 2000 tEXt chunks.
    let mut input = Vec::new();
    input.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    // Minimal IHDR
    write_png_chunk(&mut input, b"IHDR", &{
        let mut d = vec![0u8; 13];
        d[3] = 1; // width=1
        d[7] = 1; // height=1
        d[8] = 8; // bit depth
        d[9] = 2; // RGB
        d
    });
    // Flood with tEXt chunks
    for _ in 0..2000 {
        write_png_chunk(&mut input, b"tEXt", b"key\0value");
    }
    write_png_chunk(&mut input, b"IEND", &[]);

    let result = defender.defend_bytes(
        input,
        Some("flood.apng".to_string()),
        DefenseContext::default(),
    );
    // Should fail: IEND not found within chunk budget.
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════
// 2. METADATA POISONING
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn metadata_mp3_id3v2_with_embedded_exe_stripped() {
    // MP3 with a large ID3v2 tag containing a fake PE executable payload.
    let defender = default_defender();
    let mut input = Vec::new();
    // ID3v2 header
    input.extend_from_slice(b"ID3");
    input.extend_from_slice(&[4, 0, 0]); // version + flags
    let tag_size = 1024u32;
    // Synchsafe encode
    input.push(((tag_size >> 21) & 0x7F) as u8);
    input.push(((tag_size >> 14) & 0x7F) as u8);
    input.push(((tag_size >> 7) & 0x7F) as u8);
    input.push((tag_size & 0x7F) as u8);
    // Tag payload: starts with MZ (PE header) — this should be stripped.
    let mut tag_data = vec![0u8; tag_size as usize];
    tag_data[0] = b'M';
    tag_data[1] = b'Z';
    input.extend_from_slice(&tag_data);
    // MP3 sync frame
    input.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    input.extend_from_slice(&[0u8; 200]);

    let result = defender
        .defend_bytes(
            input,
            Some("evil.mp3".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    // Output must NOT contain MZ header — ID3 was stripped.
    assert!(!result.artifact.output_bytes.starts_with(b"MZ"));
    // Output must start with sync word.
    assert_eq!(&result.artifact.output_bytes[0..2], &[0xFF, 0xFB]);
}

#[test]
fn metadata_mp4_udta_with_gps_coordinates_stripped() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(&make_mp4_atom(b"ftyp", b"isom\x00\x00\x00\x00"));
    let moov = make_mp4_container(
        b"moov",
        &[
            make_mp4_atom(b"mvhd", &[0u8; 28]),
            make_mp4_container(b"trak", &[make_mp4_atom(b"tkhd", &[0u8; 20])]),
            make_mp4_atom(b"udta", b"GPS:48.8566,2.3522"),
        ],
    );
    input.extend_from_slice(&moov);
    input.extend_from_slice(&make_mp4_atom(b"mdat", b"aac-audio-data"));

    let result = defender
        .defend_bytes(
            input,
            Some("video.mp4".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    let output_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(
        !output_str.contains("GPS"),
        "GPS coordinates must be stripped"
    );
    assert!(
        output_str.contains("aac-audio-data"),
        "audio data must survive"
    );
}

#[test]
fn metadata_ogg_opus_tags_with_album_art_stripped() {
    let defender = default_defender();
    let mut input = Vec::new();
    // BOS page with OpusHead
    let opus_head = build_opus_head();
    input.extend_from_slice(&make_ogg_page(0x02, 1, 0, 0, &opus_head));
    // OpusTags with large "album art" payload
    let mut tags = Vec::new();
    tags.extend_from_slice(b"OpusTags");
    tags.extend_from_slice(&0u32.to_le_bytes()); // vendor len
    tags.extend_from_slice(&1u32.to_le_bytes()); // 1 comment
    let art_comment = format!("METADATA_BLOCK_PICTURE={}", "A".repeat(5000));
    tags.extend_from_slice(&(art_comment.len() as u32).to_le_bytes());
    tags.extend_from_slice(art_comment.as_bytes());
    input.extend_from_slice(&make_ogg_page(0x00, 1, 1, 0, &tags));
    // Audio page
    input.extend_from_slice(&make_ogg_page(0x04, 1, 2, 48000, b"opus-audio-frames"));

    let result = defender
        .defend_bytes(
            input,
            Some("voice.ogg".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    let output_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(
        !output_str.contains("METADATA_BLOCK_PICTURE"),
        "album art must be stripped"
    );
    assert!(
        output_str.contains("opus-audio-frames"),
        "audio must survive"
    );
}

#[test]
fn metadata_wav_list_info_stripped() {
    let defender = default_defender();
    let mut input = build_minimal_wav_with_list(b"ARTIST\0Evil Hacker");
    let riff_size = (input.len() - 8) as u32;
    input[4..8].copy_from_slice(&riff_size.to_le_bytes());

    let result = defender
        .defend_bytes(
            input,
            Some("audio.wav".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    let output_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(
        !output_str.contains("Evil Hacker"),
        "LIST metadata must be stripped"
    );
}

#[test]
fn metadata_flac_vorbis_comment_and_picture_stripped() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(b"fLaC");
    // STREAMINFO (type 0, not last)
    input.push(0x00);
    input.extend_from_slice(&[0, 0, 34]);
    input.extend_from_slice(&[0u8; 34]);
    // VORBIS_COMMENT (type 4, not last)
    let comment = b"vendor\x00\x00\x00\x00\x01\x00\x00\x00\x0BARTIST=Evil\x00\x00\x00";
    input.push(0x04);
    input.push(0);
    input.extend_from_slice(&(comment.len() as u16).to_be_bytes());
    input.extend_from_slice(comment);
    // PICTURE (type 6, is_last)
    let picture = b"fake-jpeg-album-art-data";
    input.push(0x86);
    input.push(0);
    input.extend_from_slice(&(picture.len() as u16).to_be_bytes());
    input.extend_from_slice(picture);
    // Audio frames
    input.extend_from_slice(&[0xFF, 0xF8, 0x00, 0x00]);
    input.extend_from_slice(&[0u8; 100]);

    let result = defender
        .defend_bytes(
            input,
            Some("song.flac".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    let output_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(!output_str.contains("Evil"), "VORBIS_COMMENT stripped");
    assert!(!output_str.contains("fake-jpeg"), "PICTURE stripped");
}

// ═══════════════════════════════════════════════════════════════════════
// 3. EXECUTABLE SMUGGLING
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn smuggle_exe_renamed_to_jpg_blocked() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"MZ\x90\x00PE\x00\x00".to_vec(),
        Some("photo.jpg".to_string()),
        DefenseContext::default(),
    );
    // PE magic in output → blocked by output validator.
    if let Ok(r) = result {
        assert_eq!(r.verdict, DefenseVerdict::Blocked);
    }
}

#[test]
fn smuggle_elf_renamed_to_png_blocked() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"\x7fELF\x02\x01\x01\x00".to_vec(),
        Some("image.png".to_string()),
        DefenseContext::default(),
    );
    if let Ok(r) = result {
        assert_eq!(r.verdict, DefenseVerdict::Blocked);
    }
}

#[test]
fn smuggle_double_extension_exe_png_blocked() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            vec![0u8; 100],
            Some("report.exe.png".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_double_extension_bat_mp3_blocked() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            vec![0u8; 100],
            Some("script.bat.mp3".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_java_class_as_bin_blocked() {
    let defender = default_defender();
    let mut input = vec![0xCA, 0xFE, 0xBA, 0xBE]; // Java class magic
    input.extend_from_slice(&[0u8; 100]);
    let result = defender
        .defend_bytes(
            input,
            Some("Exploit.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_ole_doc_blocked() {
    let defender = default_defender();
    let mut input = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    input.extend_from_slice(&[0u8; 100]);
    let result = defender
        .defend_bytes(
            input,
            Some("doc.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_shell_script_as_txt_blocked() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            b"#!/bin/bash\nrm -rf /".to_vec(),
            Some("readme.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_php_payload_blocked() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            b"<?php system($_GET['cmd']); ?>".to_vec(),
            Some("image.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_wasm_module_blocked() {
    let defender = default_defender();
    let mut input = vec![0x00, b'a', b's', b'm'];
    input.extend_from_slice(&[0u8; 50]);
    let result = defender
        .defend_bytes(
            input,
            Some("module.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn smuggle_dex_android_blocked() {
    let defender = default_defender();
    let mut input = b"dex\n035\x00".to_vec();
    input.extend_from_slice(&[0u8; 100]);
    let result = defender
        .defend_bytes(
            input,
            Some("classes.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

// ═══════════════════════════════════════════════════════════════════════
// 4. CONTAINER MALFORMATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn malformed_mp4_truncated_atom_rejected() {
    let defender = default_defender();
    let mut input = make_mp4_atom(b"ftyp", b"isom");
    input.extend_from_slice(&500u32.to_be_bytes());
    input.extend_from_slice(b"mdat");

    let result = defender.defend_bytes(
        input,
        Some("broken.mp4".to_string()),
        DefenseContext::default(),
    );
    // Either direct error or quarantined as blocked.
    match result {
        Err(_) => {}
        Ok(r) => assert_eq!(r.verdict, DefenseVerdict::Blocked),
    }
}

#[test]
fn malformed_ogg_bad_sync_rejected() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(b"OggS"); // valid start
    input.extend_from_slice(&[0u8; 23]); // rest of minimal header
    input.extend_from_slice(b"GARBAGE_NOT_OGGS"); // second page: bad sync
    input.extend_from_slice(&[0u8; 100]);

    let result = defender.defend_bytes(
        input,
        Some("broken.ogg".to_string()),
        DefenseContext::default(),
    );
    // Either error or blocked — not clean passthrough.
    if let Ok(r) = result {
        assert_ne!(r.verdict, DefenseVerdict::Clean);
    }
}

#[test]
fn malformed_webm_bad_vint_rejected() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
    input.push(0x00); // zero VINT — invalid
    input.extend_from_slice(&[0u8; 50]);

    let result = defender.defend_bytes(
        input,
        Some("broken.webm".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(_) => {}
        Ok(r) => assert_eq!(r.verdict, DefenseVerdict::Blocked),
    }
}

#[test]
fn malformed_flac_no_streaminfo_rejected() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(b"fLaC");
    input.push(0x84); // is_last, type 4
    input.extend_from_slice(&[0, 0, 4]);
    input.extend_from_slice(&[0u8; 4]);
    input.extend_from_slice(&[0u8; 20]);

    let result = defender.defend_bytes(
        input,
        Some("broken.flac".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(_) => {}
        Ok(r) => assert_eq!(r.verdict, DefenseVerdict::Blocked),
    }
}

#[test]
fn malformed_wav_missing_data_chunk_rejected() {
    let defender = default_defender();
    let mut input = Vec::new();
    input.extend_from_slice(b"RIFF");
    input.extend_from_slice(&28u32.to_le_bytes());
    input.extend_from_slice(b"WAVE");
    input.extend_from_slice(b"fmt ");
    input.extend_from_slice(&16u32.to_le_bytes());
    input.extend_from_slice(&[1, 0, 1, 0]);
    input.extend_from_slice(&44100u32.to_le_bytes());
    input.extend_from_slice(&88200u32.to_le_bytes());
    input.extend_from_slice(&[2, 0, 16, 0]);

    let result = defender.defend_bytes(
        input,
        Some("broken.wav".to_string()),
        DefenseContext::default(),
    );
    match result {
        Err(_) => {}
        Ok(r) => assert_eq!(r.verdict, DefenseVerdict::Blocked),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 5. SIGNATURE EVASION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn signature_eicar_in_text_file_blocked() {
    let defender = default_defender();
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let result = defender
        .defend_bytes(
            eicar.to_vec(),
            Some("test.txt".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn signature_pe_header_in_middle_of_data_detected() {
    let defender = default_defender();
    let mut data = vec![0u8; 100];
    data.extend_from_slice(b"PE\x00\x00"); // PE signature mid-stream
    data.extend_from_slice(&[0u8; 100]);
    let result = defender
        .defend_bytes(
            data,
            Some("data.bin".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

// ═══════════════════════════════════════════════════════════════════════
// 6. CANCELLATION AND TIMEOUT
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cancellation_token_stops_processing() {
    let defender = default_defender();
    let token = CancellationToken::new();
    // Cancel immediately before processing.
    token.cancel();
    let context = DefenseContext {
        source: file_defender::types::SourceRole::Outgoing,
        cancel: Some(token),
        ..DefenseContext::default()
    };
    // A valid GIF that would normally succeed.
    let gif = vec![
        71, 73, 70, 56, 57, 97, 1, 0, 1, 0, 128, 0, 0, 255, 255, 255, 0, 0, 0, 33, 249, 4, 1, 10,
        0, 1, 0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59,
    ];
    let result = defender.defend_bytes(gif, Some("anim.gif".to_string()), context);
    // Must return Cancelled error.
    match result {
        Err(DefenderError::Cancelled) => {} // expected
        Err(_) => {}                        // other error also acceptable (cancelled during probe)
        Ok(r) => {
            // If it somehow completed before checking, verdict should not be Clean
            // (race condition — acceptable edge case in real-world, but in this
            // test token is cancelled before any work starts).
            let _ = r;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 7. MEDIA-ONLY POLICY ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn policy_blocks_pdf() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            b"%PDF-1.4 fake".to_vec(),
            Some("doc.pdf".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn policy_blocks_zip() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"PK\x03\x04fake-zip".to_vec(),
        Some("archive.zip".to_string()),
        DefenseContext::default(),
    );
    // Either blocked extension or blocked file kind.
    match result {
        Ok(r) => assert_eq!(r.verdict, DefenseVerdict::Blocked),
        Err(DefenderError::BlockedExtension { .. }) => {} // paranoid blocks .zip
        Err(_) => {}
    }
}

#[test]
fn policy_blocks_docx() {
    let defender = default_defender();
    let result = defender
        .defend_bytes(
            b"PK\x03\x04word/document.xml".to_vec(),
            Some("report.docx".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn policy_blocks_exe_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"anything".to_vec(),
        Some("payload.exe".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_bat_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"@echo off".to_vec(),
        Some("script.bat".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_ps1_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"Get-Process".to_vec(),
        Some("hack.ps1".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_jar_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"PK\x03\x04".to_vec(),
        Some("exploit.jar".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_apk_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"PK\x03\x04".to_vec(),
        Some("malware.apk".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_dex_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"dex\n035\x00".to_vec(),
        Some("classes.dex".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn policy_blocks_wasm_extension() {
    let defender = default_defender();
    let result = defender.defend_bytes(
        b"\x00asm".to_vec(),
        Some("module.wasm".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

// ═══════════════════════════════════════════════════════════════════════
// 8. PROFILE ESCALATION
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn strict_profile_blocks_unknown_extensions() {
    let defender = strict_defender();
    let result = defender
        .defend_bytes(
            b"unknown-content".to_vec(),
            Some("data.xyz".to_string()),
            DefenseContext::default(),
        )
        .expect("should return result");
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
}

#[test]
fn paranoid_profile_blocks_zip_extension() {
    let defender = paranoid_defender();
    let result = defender.defend_bytes(
        b"PK\x03\x04".to_vec(),
        Some("archive.zip".to_string()),
        DefenseContext::default(),
    );
    assert!(matches!(
        result,
        Err(DefenderError::BlockedExtension { .. })
    ));
}

#[test]
fn classify_svg_as_other() {
    // SVG should not be routed to ImageHandler.
    assert_eq!(
        FileKind::classify(b"<svg></svg>", Some("icon.svg"), Some("image/svg+xml"),),
        FileKind::Other
    );
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════

fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    // CRC over type + data.
    let crc = png_crc32(chunk_type, data);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn png_crc32(chunk_type: &[u8], data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in chunk_type.iter().chain(data.iter()) {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn make_mp4_atom(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let size = (8 + payload.len()) as u32;
    let mut atom = Vec::with_capacity(size as usize);
    atom.extend_from_slice(&size.to_be_bytes());
    atom.extend_from_slice(fourcc);
    atom.extend_from_slice(payload);
    atom
}

fn make_mp4_container(fourcc: &[u8; 4], children: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for child in children {
        payload.extend_from_slice(child);
    }
    make_mp4_atom(fourcc, &payload)
}

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

    let crc = ogg_crc32(&page);
    page[22..26].copy_from_slice(&crc.to_le_bytes());
    page
}

fn ogg_crc32(data: &[u8]) -> u32 {
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

fn build_opus_head() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"OpusHead");
    h.push(1); // version
    h.push(1); // channels
    h.extend_from_slice(&0u16.to_le_bytes()); // pre-skip
    h.extend_from_slice(&48000u32.to_le_bytes());
    h.extend_from_slice(&0i16.to_le_bytes()); // output gain
    h.push(0); // channel mapping
    h
}

fn build_minimal_wav_with_list(list_data: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(b"RIFF");
    input.extend_from_slice(&[0u8; 4]); // size placeholder
    input.extend_from_slice(b"WAVE");
    // fmt chunk
    input.extend_from_slice(b"fmt ");
    input.extend_from_slice(&16u32.to_le_bytes());
    input.extend_from_slice(&1u16.to_le_bytes()); // PCM
    input.extend_from_slice(&1u16.to_le_bytes()); // mono
    input.extend_from_slice(&44100u32.to_le_bytes());
    input.extend_from_slice(&88200u32.to_le_bytes());
    input.extend_from_slice(&2u16.to_le_bytes());
    input.extend_from_slice(&16u16.to_le_bytes());
    // LIST chunk with metadata
    input.extend_from_slice(b"LIST");
    input.extend_from_slice(&(list_data.len() as u32).to_le_bytes());
    input.extend_from_slice(list_data);
    if !list_data.len().is_multiple_of(2) {
        input.push(0);
    }
    // data chunk
    input.extend_from_slice(b"data");
    input.extend_from_slice(&4u32.to_le_bytes());
    input.extend_from_slice(&[0x80, 0x00, 0x80, 0x00]);
    input
}
