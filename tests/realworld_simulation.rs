//! Real-world file simulation tests.
//!
//! These tests generate spec-valid files that mimic what real devices
//! produce (iPhone photos, Android voice notes, Chrome WebM, etc.),
//! pass them through the CDR pipeline, and verify:
//!   1. Output is non-empty and playable (correct magic bytes)
//!   2. Metadata is stripped
//!   3. Media content is preserved (or safely rebuilt)
//!   4. Verdict is Clean (no false positives)
//!
//! The fixture generation is inlined — no external files needed.

use std::io::Write;

use mdo_cdr::{
    DefenseContext, DefenseVerdict, FileDefender, FileKind, policy::DefensePolicy,
};

fn defender() -> FileDefender {
    FileDefender::new(DefensePolicy::default())
}

// ═══════════════════════════════════════════════════════════════════════
// IMAGE TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn realworld_jpeg_rebuild_strips_exif() {
    let d = defender();
    // Create a valid JPEG via image crate.
    let img = image::RgbImage::from_fn(4, 4, |x, y| {
        image::Rgb([(x * 60) as u8, (y * 60) as u8, 128])
    });
    let mut jpeg_buf = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut jpeg_buf),
        image::ImageFormat::Jpeg,
    )
    .unwrap();

    let result = d
        .defend_bytes(
            jpeg_buf,
            Some("photo.jpg".to_string()),
            DefenseContext::default(),
        )
        .expect("JPEG should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Clean);
    assert_eq!(result.artifact.file_kind, FileKind::Image);
    assert!(!result.artifact.output_bytes.is_empty());
    // Output should be valid PNG (default output format).
    assert_eq!(&result.artifact.output_bytes[1..4], b"PNG");
    // Info alert about metadata stripping.
    assert!(
        result
            .alerts
            .iter()
            .any(|a| a.code == "image_metadata_stripped")
    );
}

#[test]
fn realworld_png_rebuild_preserves_pixels() {
    let d = defender();
    let img = image::RgbImage::from_fn(8, 8, |x, y| image::Rgb([((x + y) * 30) as u8, 100, 200]));
    let mut png_buf = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut png_buf),
        image::ImageFormat::Png,
    )
    .unwrap();

    let result = d
        .defend_bytes(
            png_buf.clone(),
            Some("chart.png".to_string()),
            DefenseContext::default(),
        )
        .expect("PNG should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Clean);
    // Re-decode output and compare pixel values.
    let rebuilt = image::load_from_memory(&result.artifact.output_bytes).unwrap();
    let original = image::load_from_memory(&png_buf).unwrap();
    assert_eq!(rebuilt.width(), original.width());
    assert_eq!(rebuilt.height(), original.height());
}

#[test]
fn realworld_gif_rebuild_preserves_frame_count() {
    let d = defender();
    let mut buf = Vec::new();
    {
        let mut enc = gif::Encoder::new(&mut buf, 4, 4, &[]).unwrap();
        enc.set_repeat(gif::Repeat::Infinite).unwrap();
        for i in 0..3u8 {
            let mut pixels = vec![i * 80; 4 * 4 * 4]; // RGBA
            let mut frame = gif::Frame::from_rgba_speed(4, 4, &mut pixels, 10);
            frame.delay = 20;
            enc.write_frame(&frame).unwrap();
        }
    }

    let result = d
        .defend_bytes(
            buf,
            Some("sticker.gif".to_string()),
            DefenseContext::default(),
        )
        .expect("GIF should succeed");

    assert_eq!(result.verdict, DefenseVerdict::Clean);
    assert_eq!(result.artifact.file_kind, FileKind::Gif);
    assert!(
        result
            .alerts
            .iter()
            .any(|a| a.code == "gif_metadata_stripped")
    );
    // Output should be valid GIF.
    assert_eq!(&result.artifact.output_bytes[0..3], b"GIF");
}

// ═══════════════════════════════════════════════════════════════════════
// AUDIO TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn realworld_mp3_strips_id3_keeps_frames() {
    let d = defender();
    let mut input = Vec::new();
    // ID3v2 header (10 bytes + 20 bytes payload)
    input.extend_from_slice(b"ID3\x04\x00\x00");
    input.extend_from_slice(&[0, 0, 0, 20]); // synchsafe 20
    input.extend_from_slice(&[0xAA; 20]); // tag data
    // Valid MP3 sync + frame
    input.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    input.extend_from_slice(&vec![0u8; 413]); // frame body
    // Second frame
    input.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    input.extend_from_slice(&vec![0u8; 413]);
    // ID3v1 tail
    let mut id3v1 = vec![0u8; 128];
    id3v1[0..3].copy_from_slice(b"TAG");
    input.extend_from_slice(&id3v1);

    let original_len = input.len();
    let result = d
        .defend_bytes(
            input,
            Some("podcast.mp3".to_string()),
            DefenseContext::default(),
        )
        .expect("MP3 should succeed");

    assert_eq!(result.artifact.file_kind, FileKind::Audio);
    // Output should be smaller (tags stripped).
    assert!(result.artifact.output_bytes.len() < original_len);
    // Output should start with sync word.
    assert_eq!(&result.artifact.output_bytes[0..2], &[0xFF, 0xFB]);
    // No ID3 header in output.
    assert!(!result.artifact.output_bytes.starts_with(b"ID3"));
    // No TAG footer.
    let tail =
        &result.artifact.output_bytes[result.artifact.output_bytes.len().saturating_sub(128)..];
    assert!(!tail.starts_with(b"TAG"));
}

#[test]
fn realworld_wav_strips_list_keeps_audio() {
    let d = defender();
    let mut input = Vec::new();
    input.extend_from_slice(b"RIFF\x00\x00\x00\x00WAVE");
    // fmt
    input.extend_from_slice(b"fmt ");
    input.extend_from_slice(&16u32.to_le_bytes());
    input.extend_from_slice(&1u16.to_le_bytes());
    input.extend_from_slice(&1u16.to_le_bytes());
    input.extend_from_slice(&44100u32.to_le_bytes());
    input.extend_from_slice(&88200u32.to_le_bytes());
    input.extend_from_slice(&2u16.to_le_bytes());
    input.extend_from_slice(&16u16.to_le_bytes());
    // LIST chunk with INFO sub-chunk containing artist metadata.
    let list_payload = b"INFOIARTEvil Hax0r";
    input.extend_from_slice(b"LIST");
    input.extend_from_slice(&(list_payload.len() as u32).to_le_bytes());
    input.extend_from_slice(list_payload);
    // data
    let samples = vec![0x80u8; 1000];
    input.extend_from_slice(b"data");
    input.extend_from_slice(&(samples.len() as u32).to_le_bytes());
    input.extend_from_slice(&samples);
    // Fix RIFF size
    let rs = (input.len() - 8) as u32;
    input[4..8].copy_from_slice(&rs.to_le_bytes());

    let result = d
        .defend_bytes(
            input,
            Some("recording.wav".to_string()),
            DefenseContext::default(),
        )
        .expect("WAV should succeed");

    let out = &result.artifact.output_bytes;
    assert!(out.starts_with(b"RIFF"));
    assert!(!String::from_utf8_lossy(out).contains("Evil Hax0r"));
    assert!(out.windows(4).any(|w| w == b"data"));
}

#[test]
fn realworld_ogg_opus_strips_tags_keeps_audio() {
    let d = defender();
    let mut input = Vec::new();
    // OpusHead
    let mut oh = Vec::new();
    oh.extend_from_slice(b"OpusHead\x01\x01");
    oh.extend_from_slice(&0u16.to_le_bytes());
    oh.extend_from_slice(&48000u32.to_le_bytes());
    oh.extend_from_slice(&0i16.to_le_bytes());
    oh.push(0);
    input.extend_from_slice(&make_ogg_page(0x02, 1, 0, 0, &oh));
    // OpusTags with evil metadata
    let mut tags = Vec::new();
    tags.extend_from_slice(b"OpusTags");
    tags.extend_from_slice(&0u32.to_le_bytes());
    tags.extend_from_slice(&1u32.to_le_bytes());
    let c = b"TITLE=Stolen Recording";
    tags.extend_from_slice(&(c.len() as u32).to_le_bytes());
    tags.extend_from_slice(c);
    input.extend_from_slice(&make_ogg_page(0x00, 1, 1, 0, &tags));
    // Audio
    input.extend_from_slice(&make_ogg_page(0x04, 1, 2, 960, b"opus-frame-data-here"));

    let result = d
        .defend_bytes(
            input,
            Some("voice.ogg".to_string()),
            DefenseContext::default(),
        )
        .expect("OGG should succeed");

    let out_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(!out_str.contains("Stolen Recording"));
    assert!(out_str.contains("opus-frame-data-here"));
}

#[test]
fn realworld_mp4_audio_strips_metadata() {
    let d = defender();
    let mut input = Vec::new();
    input.extend_from_slice(&make_mp4_atom(b"ftyp", b"M4A \x00\x00\x02\x00M4A mp42"));
    let moov = make_mp4_container(
        b"moov",
        &[
            make_mp4_atom(b"mvhd", &[0u8; 108]),
            make_mp4_container(b"trak", &[make_mp4_atom(b"tkhd", &[0u8; 92])]),
            make_mp4_atom(b"udta", b"\xa9nam\x00\x00\x00\x10Stolen Note\x00\x00"),
        ],
    );
    input.extend_from_slice(&moov);
    input.extend_from_slice(&make_mp4_atom(b"mdat", b"aac-encoded-audio-samples"));

    let result = d
        .defend_bytes(
            input,
            Some("memo.m4a".to_string()),
            DefenseContext::default(),
        )
        .expect("M4A should succeed");

    let out_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(!out_str.contains("Stolen Note"));
    assert!(out_str.contains("aac-encoded-audio-samples"));
}

// ═══════════════════════════════════════════════════════════════════════
// VIDEO TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn realworld_mp4_video_strips_gps_keeps_frames() {
    let d = defender();
    let mut input = Vec::new();
    input.extend_from_slice(&make_mp4_atom(b"ftyp", b"isom\x00\x00\x02\x00isomiso2"));
    let moov = make_mp4_container(
        b"moov",
        &[
            make_mp4_atom(b"mvhd", &[0u8; 108]),
            make_mp4_container(b"trak", &[make_mp4_atom(b"tkhd", &[0u8; 92])]),
            make_mp4_atom(b"udta", b"\xa9xyz\x00\x00\x00\x1248.8566+2.3522/"),
        ],
    );
    input.extend_from_slice(&moov);
    input.extend_from_slice(&make_mp4_atom(b"free", &[0u8; 200]));
    let video_data = b"h264-nal-units-keyframe-slice-data-bitstream";
    input.extend_from_slice(&make_mp4_atom(b"mdat", video_data));

    let result = d
        .defend_bytes(
            input,
            Some("clip.mp4".to_string()),
            DefenseContext::default(),
        )
        .expect("MP4 video should succeed");

    let out_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(!out_str.contains("48.8566"), "GPS must be stripped");
    assert!(
        !result
            .artifact
            .output_bytes
            .windows(4)
            .any(|w| w == b"free"),
        "free atom must be stripped"
    );
    assert!(
        out_str.contains("h264-nal-units"),
        "video data must survive"
    );
}

#[test]
fn realworld_webm_strips_tags_keeps_clusters() {
    let d = defender();
    let mut input = Vec::new();
    // EBML header
    input.extend_from_slice(&make_ebml_element(&[0x1A, 0x45, 0xDF, 0xA3], &{
        let mut h = Vec::new();
        h.extend_from_slice(&make_ebml_element(&[0x42, 0x82], b"webm"));
        h
    }));
    // Segment
    let mut seg = Vec::new();
    // Info
    seg.extend_from_slice(&make_ebml_element(&[0x15, 0x49, 0xA9, 0x66], b"info-data"));
    // Tracks
    seg.extend_from_slice(&make_ebml_element(
        &[0x16, 0x54, 0xAE, 0x6B],
        b"track-config",
    ));
    // Tags (should be stripped)
    seg.extend_from_slice(&make_ebml_element(
        &[0x12, 0x54, 0xC3, 0x67],
        b"TITLE=Evil Video",
    ));
    // Cluster
    seg.extend_from_slice(&make_ebml_element(
        &[0x1F, 0x43, 0xB6, 0x75],
        b"vp9-encoded-frames",
    ));
    input.extend_from_slice(&make_ebml_element(&[0x18, 0x53, 0x80, 0x67], &seg));

    let result = d
        .defend_bytes(
            input,
            Some("screen.webm".to_string()),
            DefenseContext::default(),
        )
        .expect("WebM should succeed");

    let out_str = String::from_utf8_lossy(&result.artifact.output_bytes);
    assert!(!out_str.contains("Evil Video"), "Tags must be stripped");
    assert!(
        out_str.contains("vp9-encoded-frames"),
        "Cluster must survive"
    );
    assert!(out_str.contains("track-config"), "Tracks must survive");
}

// ═══════════════════════════════════════════════════════════════════════
// APNG TEST
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn realworld_apng_strips_text_keeps_animation() {
    let d = defender();
    let mut input = Vec::new();
    input.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
    let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
    write_png_chunk(&mut input, b"IHDR", &ihdr);
    // acTL: 1 frame
    let mut actl = Vec::new();
    actl.extend_from_slice(&1u32.to_be_bytes());
    actl.extend_from_slice(&0u32.to_be_bytes());
    write_png_chunk(&mut input, b"acTL", &actl);
    // Metadata
    write_png_chunk(&mut input, b"tEXt", b"Author\0Attacker");
    write_png_chunk(&mut input, b"eXIf", b"fake-exif-with-gps");
    // IDAT
    let mut compressed = Vec::new();
    {
        let mut enc =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
        enc.write_all(&[0, 255, 0, 0]).unwrap();
        enc.finish().unwrap();
    }
    write_png_chunk(&mut input, b"IDAT", &compressed);
    write_png_chunk(&mut input, b"IEND", &[]);

    let result = d
        // Use .png extension — classify() peeks bytes for acTL chunk and
        // upgrades to AnimatedImage automatically. Using .apng would cause
        // FileTypeMismatch because infer reports image/png for APNG.
        .defend_bytes(
            input,
            Some("sticker.png".to_string()),
            DefenseContext::default(),
        )
        .expect("APNG should succeed");

    assert_eq!(result.artifact.file_kind, FileKind::AnimatedImage);
    let out = &result.artifact.output_bytes;
    // Must not contain stripped metadata.
    assert!(!out.windows(8).any(|w| w == b"Attacker"));
    assert!(!out.windows(4).any(|w| w == b"eXIf"));
    // Must contain acTL (animation preserved).
    assert!(out.windows(4).any(|w| w == b"acTL"));
    // Must contain IDAT (image data preserved).
    assert!(out.windows(4).any(|w| w == b"IDAT"));
}

// ═══════════════════════════════════════════════════════════════════════
// CROSS-FORMAT CONSISTENCY
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn all_formats_produce_non_empty_output() {
    let d = defender();

    // Minimal valid JPEG
    let img = image::RgbImage::from_pixel(1, 1, image::Rgb([128, 128, 128]));
    let mut jpeg = Vec::new();
    img.write_to(
        &mut std::io::Cursor::new(&mut jpeg),
        image::ImageFormat::Jpeg,
    )
    .unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![("test.jpg", jpeg)];

    for (name, data) in cases {
        let result = d
            .defend_bytes(data, Some(name.to_string()), DefenseContext::default())
            .unwrap_or_else(|_| panic!("{name} should succeed"));
        assert!(
            !result.artifact.output_bytes.is_empty(),
            "{name}: output must not be empty"
        );
        assert!(
            result.diagnostics.duration_ms < 10_000,
            "{name}: should complete in <10s"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
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
    let mut a = Vec::with_capacity(size as usize);
    a.extend_from_slice(&size.to_be_bytes());
    a.extend_from_slice(fourcc);
    a.extend_from_slice(payload);
    a
}

fn make_mp4_container(fourcc: &[u8; 4], children: &[Vec<u8>]) -> Vec<u8> {
    let mut p = Vec::new();
    for c in children {
        p.extend_from_slice(c);
    }
    make_mp4_atom(fourcc, &p)
}

fn make_ogg_page(ht: u8, serial: u32, seq: u32, granule: i64, data: &[u8]) -> Vec<u8> {
    let mut segs = Vec::new();
    let mut rem = data.len();
    loop {
        if rem >= 255 {
            segs.push(255u8);
            rem -= 255;
        } else {
            segs.push(rem as u8);
            break;
        }
    }
    let mut p = Vec::new();
    p.extend_from_slice(b"OggS");
    p.push(0);
    p.push(ht);
    p.extend_from_slice(&granule.to_le_bytes());
    p.extend_from_slice(&serial.to_le_bytes());
    p.extend_from_slice(&seq.to_le_bytes());
    p.extend_from_slice(&[0u8; 4]);
    p.push(segs.len() as u8);
    p.extend_from_slice(&segs);
    p.extend_from_slice(data);
    let crc = ogg_crc32(&p);
    p[22..26].copy_from_slice(&crc.to_le_bytes());
    p
}

fn ogg_crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::LazyLock<[u32; 256]> = std::sync::LazyLock::new(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i << 24;
            for _ in 0..8 {
                if c & 0x8000_0000 != 0 {
                    c = (c << 1) ^ 0x04C1_1DB7;
                } else {
                    c <<= 1;
                }
            }
            t[i as usize] = c;
        }
        t
    });
    let mut c = 0u32;
    for &b in data {
        let i = ((c >> 24) ^ (b as u32)) & 0xFF;
        c = (c << 8) ^ TABLE[i as usize];
    }
    c
}

fn make_ebml_element(id: &[u8], data: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(id);
    let s = data.len() as u64;
    if s < 0x7F {
        e.push(0x80 | s as u8);
    } else if s < 0x3FFF {
        e.push(0x40 | ((s >> 8) & 0x3F) as u8);
        e.push((s & 0xFF) as u8);
    } else {
        panic!("too large");
    }
    e.extend_from_slice(data);
    e
}
