//! Generated media and synthetic container simulation tests.
//!
//! Valid generated PNG/JPEG/GIF/WAV inputs exercise release and preservation.
//! Deliberately incomplete MP3/FLAC/Opus/MP4/WebM/APNG containers exercise
//! native metadata filtering separately from the pipeline release decision.
//! Header signatures alone do not demonstrate playable or valid media.
//! All fixtures are generated in the test; these are not external research data.

use std::io::Write;

use mdo_cdr::{DefenseContext, DefenseVerdict, FileDefender, FileKind, policy::DefensePolicy};

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

    // Add a real EXIF APP1 segment: little-endian TIFF with one ASCII
    // ImageDescription entry. The marker is harmless generated metadata.
    let description = b"generated-dissertation-metadata\0";
    let mut exif = b"Exif\0\0II\x2a\x00\x08\x00\x00\x00".to_vec();
    exif.extend_from_slice(&1u16.to_le_bytes()); // IFD entry count
    exif.extend_from_slice(&0x010eu16.to_le_bytes()); // ImageDescription
    exif.extend_from_slice(&2u16.to_le_bytes()); // ASCII
    exif.extend_from_slice(&(description.len() as u32).to_le_bytes());
    exif.extend_from_slice(&26u32.to_le_bytes()); // Value offset from TIFF header
    exif.extend_from_slice(&0u32.to_le_bytes()); // No next IFD
    exif.extend_from_slice(description);
    let mut app1 = vec![0xff, 0xe1];
    app1.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
    app1.extend_from_slice(&exif);
    assert_eq!(&jpeg_buf[..2], &[0xff, 0xd8]);
    jpeg_buf.splice(2..2, app1);
    assert!(jpeg_buf.windows(6).any(|bytes| bytes == b"Exif\0\0"));
    assert!(
        jpeg_buf
            .windows(description.len())
            .any(|bytes| bytes == description)
    );
    let original_pixels = image::load_from_memory(&jpeg_buf)
        .expect("generated JPEG with EXIF must decode")
        .to_rgba8();

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
    assert!(
        !result
            .artifact
            .output_bytes
            .windows(6)
            .any(|bytes| bytes == b"Exif\0\0")
    );
    assert!(
        !result
            .artifact
            .output_bytes
            .windows(description.len())
            .any(|bytes| bytes == description),
        "the injected EXIF description must not survive reconstruction"
    );
    let rebuilt_pixels = image::load_from_memory(&result.artifact.output_bytes)
        .expect("rebuilt PNG must decode")
        .to_rgba8();
    assert_eq!(
        rebuilt_pixels, original_pixels,
        "JPEG reconstruction to PNG must preserve the decoded pixel values"
    );
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
    assert_eq!(
        rebuilt.to_rgba8(),
        original.to_rgba8(),
        "PNG reconstruction must preserve every decoded RGBA pixel"
    );
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
fn synthetic_ogg_metadata_stripped_but_fake_packets_withheld() {
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

    // A container rewrite does not establish that the synthetic codec payload is decodable.
    let native = mdo_cdr::handlers::ogg_native::try_sanitize_ogg(&input)
        .unwrap()
        .unwrap();

    let result = d
        .defend_bytes(
            input,
            Some("voice.ogg".to_string()),
            DefenseContext::default(),
        )
        .expect("pipeline reports rejected Ogg");
    assert_failed_read_withheld(&result, native.output_bytes.len() as u64);

    let out_str = String::from_utf8_lossy(&native.output_bytes);
    assert!(!out_str.contains("Stolen Recording"));
    assert!(out_str.contains("opus-frame-data-here"));
}

#[test]
fn synthetic_mp4_audio_metadata_stripped_but_fake_stream_withheld() {
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

    // A container rewrite does not establish that the synthetic codec payload is decodable.
    let native = mdo_cdr::handlers::mp4_native::try_sanitize_mp4(&input)
        .unwrap()
        .unwrap();

    let result = d
        .defend_bytes(
            input,
            Some("memo.m4a".to_string()),
            DefenseContext::default(),
        )
        .expect("pipeline reports rejected M4A");
    assert_failed_read_withheld(&result, native.output_bytes.len() as u64);

    let out_str = String::from_utf8_lossy(&native.output_bytes);
    assert!(!out_str.contains("Stolen Note"));
    assert!(out_str.contains("aac-encoded-audio-samples"));
}

// ═══════════════════════════════════════════════════════════════════════
// VIDEO TESTS
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn synthetic_mp4_video_gps_stripped_but_fake_stream_withheld() {
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

    // A container rewrite does not establish that the synthetic codec payload is decodable.
    let native = mdo_cdr::handlers::mp4_native::try_sanitize_mp4(&input)
        .unwrap()
        .unwrap();

    let result = d
        .defend_bytes(
            input,
            Some("clip.mp4".to_string()),
            DefenseContext::default(),
        )
        .expect("pipeline reports rejected MP4");
    assert_failed_read_withheld(&result, native.output_bytes.len() as u64);

    let out_str = String::from_utf8_lossy(&native.output_bytes);
    assert!(!out_str.contains("48.8566"), "GPS must be stripped");
    assert!(
        !native.output_bytes.windows(4).any(|w| w == b"free"),
        "free atom must be stripped"
    );
    assert!(
        out_str.contains("h264-nal-units"),
        "video data must survive"
    );
}

#[test]
fn synthetic_webm_tags_stripped_but_fake_clusters_withheld() {
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

    // A container rewrite does not establish that the synthetic codec payload is decodable.
    let native = mdo_cdr::handlers::webm_native::try_sanitize_webm(&input)
        .unwrap()
        .unwrap();

    let result = d
        .defend_bytes(
            input,
            Some("screen.webm".to_string()),
            DefenseContext::default(),
        )
        .expect("pipeline reports rejected WebM");
    assert_failed_read_withheld(&result, native.output_bytes.len() as u64);

    let out_str = String::from_utf8_lossy(&native.output_bytes);
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
fn synthetic_apng_metadata_stripped_but_missing_frame_control_withheld() {
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

    // A container rewrite does not establish that the synthetic codec payload is decodable.
    let native = mdo_cdr::handlers::animated_image::AnimatedImageHandler::new(
        mdo_cdr::policy::AnimatedImagePolicy::default(),
    )
    .rebuild(input.clone(), DefenseContext::default())
    .unwrap();

    let result = d
        // Use .png extension — classify() peeks bytes for acTL chunk and
        // upgrades to AnimatedImage automatically. Using .apng would cause
        // FileTypeMismatch because infer reports image/png for APNG.
        .defend_bytes(
            input,
            Some("sticker.png".to_string()),
            DefenseContext::default(),
        )
        .expect("pipeline reports rejected APNG");
    assert_failed_read_withheld(&result, native.output_bytes.len() as u64);

    assert_eq!(result.artifact.file_kind, FileKind::AnimatedImage);
    let out = &native.output_bytes;
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

fn assert_failed_read_withheld(result: &mdo_cdr::DefendResult, candidate_size: u64) {
    assert_eq!(result.verdict, DefenseVerdict::Blocked);
    assert!(
        result.artifact.output_bytes.is_empty(),
        "an unverified candidate cannot be released"
    );
    assert_eq!(
        result.artifact.output_size, candidate_size,
        "the examined candidate size remains available for audit"
    );
    assert!(
        result
            .alerts
            .iter()
            .any(|alert| alert.code == "output_read_failed"),
        "the separate output reader must reject the synthetic payload: {:?}",
        result.alerts
    );
}
