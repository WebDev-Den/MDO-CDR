//! Generates minimal but spec-valid test fixture files for real-world testing.
//!
//! Run with: cargo test --test generate_fixtures -- --ignored
//! Files are written to tests/fixtures/.

use std::io::Write;
use std::path::Path;

const FIXTURES_DIR: &str = "tests/fixtures";

fn fixtures_path(name: &str) -> std::path::PathBuf {
    Path::new(FIXTURES_DIR).join(name)
}

#[test]
#[ignore] // Run manually to generate fixtures.
fn generate_all_fixtures() {
    std::fs::create_dir_all(FIXTURES_DIR).unwrap();

    generate_minimal_png();
    generate_minimal_jpeg();
    generate_minimal_gif();
    generate_minimal_mp3_with_id3();
    generate_minimal_wav_with_metadata();
    generate_minimal_flac_with_comment();
    generate_minimal_ogg_opus();
    generate_minimal_mp4();
    generate_minimal_webm();
    generate_minimal_apng();

    println!("All fixtures generated in {FIXTURES_DIR}/");
}

fn generate_minimal_png() {
    // 1×1 red pixel PNG with tEXt metadata chunk.
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR: 1×1, 8-bit RGB
    let ihdr = [0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
    write_png_chunk(&mut out, b"IHDR", &ihdr);

    // tEXt: metadata that should be stripped
    write_png_chunk(&mut out, b"tEXt", b"Author\0TestGenerator");
    write_png_chunk(
        &mut out,
        b"tEXt",
        b"Comment\0This should be stripped by CDR",
    );

    // IDAT: minimal filtered scanline (filter=0, R=255, G=0, B=0)
    let raw_scanline = [0x00, 0xFF, 0x00, 0x00]; // filter byte + RGB
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
        encoder.write_all(&raw_scanline).unwrap();
        encoder.finish().unwrap();
    }
    write_png_chunk(&mut out, b"IDAT", &compressed);
    write_png_chunk(&mut out, b"IEND", &[]);

    std::fs::write(fixtures_path("minimal_with_metadata.png"), &out).unwrap();
    println!(
        "  generated minimal_with_metadata.png ({} bytes)",
        out.len()
    );
}

fn generate_minimal_jpeg() {
    // Use image crate to create a 2×2 JPEG.
    let img = image::RgbImage::from_fn(2, 2, |x, y| {
        if (x + y) % 2 == 0 {
            image::Rgb([255, 0, 0])
        } else {
            image::Rgb([0, 0, 255])
        }
    });
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    img.write_to(&mut cursor, image::ImageFormat::Jpeg).unwrap();

    // Inject a fake EXIF APP1 marker after SOI.
    let mut with_exif = Vec::new();
    with_exif.extend_from_slice(&buf[..2]); // SOI (FF D8)
    // APP1 marker with "Exif\0\0" + fake TIFF header
    let exif_data = b"Exif\0\0MM\0*\0\0\0\x08GPS-COORDINATES-48.8566-2.3522";
    let app1_len = (exif_data.len() + 2) as u16;
    with_exif.push(0xFF);
    with_exif.push(0xE1); // APP1
    with_exif.extend_from_slice(&app1_len.to_be_bytes());
    with_exif.extend_from_slice(exif_data);
    with_exif.extend_from_slice(&buf[2..]); // rest of JPEG

    std::fs::write(fixtures_path("minimal_with_exif.jpg"), &with_exif).unwrap();
    println!(
        "  generated minimal_with_exif.jpg ({} bytes)",
        with_exif.len()
    );
}

fn generate_minimal_gif() {
    // 2×2 animated GIF with 2 frames and a comment extension.
    let mut buf = Vec::new();
    {
        let mut encoder = gif::Encoder::new(&mut buf, 2, 2, &[]).unwrap();
        encoder.set_repeat(gif::Repeat::Finite(1)).unwrap();

        // Frame 1: red
        let mut pixels = vec![
            255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255,
        ];
        let mut frame = gif::Frame::from_rgba_speed(2, 2, &mut pixels, 10);
        frame.delay = 50; // 0.5s
        encoder.write_frame(&frame).unwrap();

        // Frame 2: blue
        let mut pixels = vec![
            0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255, 0, 0, 255, 255,
        ];
        let mut frame = gif::Frame::from_rgba_speed(2, 2, &mut pixels, 10);
        frame.delay = 50;
        encoder.write_frame(&frame).unwrap();
    }

    std::fs::write(fixtures_path("animated_with_comment.gif"), &buf).unwrap();
    println!(
        "  generated animated_with_comment.gif ({} bytes)",
        buf.len()
    );
}

fn generate_minimal_mp3_with_id3() {
    let mut out = Vec::new();

    // ID3v2 header
    out.extend_from_slice(b"ID3");
    out.extend_from_slice(&[3, 0, 0]); // v2.3, no flags
    let tag_payload = b"TIT2\x00\x00\x00\x0B\x00\x00\x00Test Title";
    let size = tag_payload.len() as u32;
    out.push(((size >> 21) & 0x7F) as u8);
    out.push(((size >> 14) & 0x7F) as u8);
    out.push(((size >> 7) & 0x7F) as u8);
    out.push((size & 0x7F) as u8);
    out.extend_from_slice(tag_payload);

    // Minimal MP3 frame (MPEG1 Layer3, 128kbps, 44100Hz, stereo)
    // Sync word + valid header
    out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    // Frame data (417 bytes for 128kbps @ 44100Hz frame)
    out.extend_from_slice(&vec![0u8; 413]);

    // ID3v1 tail
    let mut id3v1 = vec![0u8; 128];
    id3v1[0] = b'T';
    id3v1[1] = b'A';
    id3v1[2] = b'G';
    // Title: "Evil Song"
    id3v1[3..12].copy_from_slice(b"Evil Song");
    out.extend_from_slice(&id3v1);

    std::fs::write(fixtures_path("tagged.mp3"), &out).unwrap();
    println!("  generated tagged.mp3 ({} bytes)", out.len());
}

fn generate_minimal_wav_with_metadata() {
    let mut out = Vec::new();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&[0u8; 4]); // size placeholder
    out.extend_from_slice(b"WAVE");

    // fmt chunk: PCM 16-bit mono 44100Hz
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&44100u32.to_le_bytes());
    out.extend_from_slice(&88200u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());

    // LIST/INFO with metadata
    let info_payload = b"INFOIARTEvil Artist\0\0";
    out.extend_from_slice(b"LIST");
    out.extend_from_slice(&(info_payload.len() as u32).to_le_bytes());
    out.extend_from_slice(info_payload);

    // data chunk: 100 samples of silence
    let samples = vec![0u8; 200];
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(samples.len() as u32).to_le_bytes());
    out.extend_from_slice(&samples);

    // Fix RIFF size
    let riff_size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&riff_size.to_le_bytes());

    std::fs::write(fixtures_path("metadata.wav"), &out).unwrap();
    println!("  generated metadata.wav ({} bytes)", out.len());
}

fn generate_minimal_flac_with_comment() {
    let mut out = Vec::new();
    out.extend_from_slice(b"fLaC");

    // STREAMINFO block (type 0, not last, 34 bytes)
    out.push(0x00);
    out.extend_from_slice(&[0, 0, 34]);
    let mut si = [0u8; 34];
    // min/max block size = 4096
    si[0] = 0x10;
    si[1] = 0x00;
    si[2] = 0x10;
    si[3] = 0x00;
    // sample rate 44100 = 0xAC44, channels=1 (0), bps=16 (15)
    // Byte 10: sample_rate[15:8] = 0xAC
    si[10] = 0xAC;
    // Byte 11: sample_rate[7:4]=0x4 | channels[2:0]=0 | bps[4]=0 → 0x44
    si[11] = 0x44;
    // Byte 12: bps[3:0]=0xF | total_samples[35:32]=0 → 0xF0
    si[12] = 0xF0;
    out.extend_from_slice(&si);

    // VORBIS_COMMENT (type 4, not last)
    let mut vc = Vec::new();
    let vendor = b"TestEncoder";
    vc.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    vc.extend_from_slice(vendor);
    vc.extend_from_slice(&1u32.to_le_bytes()); // 1 comment
    let comment = b"ARTIST=Evil Artist";
    vc.extend_from_slice(&(comment.len() as u32).to_le_bytes());
    vc.extend_from_slice(comment);
    out.push(0x04);
    out.push(0);
    out.extend_from_slice(&(vc.len() as u16).to_be_bytes());
    out.extend_from_slice(&vc);

    // PICTURE (type 6, is_last)
    let pic = b"fake-album-art-jpeg-data-here";
    out.push(0x86); // is_last + type 6
    out.push(0);
    out.extend_from_slice(&(pic.len() as u16).to_be_bytes());
    out.extend_from_slice(pic);

    // Fake audio frames (FLAC frame sync 0xFFF8)
    out.extend_from_slice(&[0xFF, 0xF8, 0x69, 0x18]);
    out.extend_from_slice(&[0u8; 200]);

    std::fs::write(fixtures_path("metadata.flac"), &out).unwrap();
    println!("  generated metadata.flac ({} bytes)", out.len());
}

fn generate_minimal_ogg_opus() {
    let mut out = Vec::new();

    // Page 0: BOS + OpusHead
    let mut opus_head = Vec::new();
    opus_head.extend_from_slice(b"OpusHead");
    opus_head.push(1); // version
    opus_head.push(1); // channels
    opus_head.extend_from_slice(&3840u16.to_le_bytes()); // pre-skip
    opus_head.extend_from_slice(&48000u32.to_le_bytes());
    opus_head.extend_from_slice(&0i16.to_le_bytes()); // output gain
    opus_head.push(0); // channel mapping family
    out.extend_from_slice(&make_ogg_page(0x02, 1, 0, 0, &opus_head));

    // Page 1: OpusTags with metadata
    let mut tags = Vec::new();
    tags.extend_from_slice(b"OpusTags");
    let vendor = b"libopus 1.3.1";
    tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    tags.extend_from_slice(vendor);
    tags.extend_from_slice(&2u32.to_le_bytes()); // 2 comments
    let c1 = b"ENCODER=Evil Encoder";
    tags.extend_from_slice(&(c1.len() as u32).to_le_bytes());
    tags.extend_from_slice(c1);
    let c2 = b"TITLE=Malicious Voice Note";
    tags.extend_from_slice(&(c2.len() as u32).to_le_bytes());
    tags.extend_from_slice(c2);
    out.extend_from_slice(&make_ogg_page(0x00, 1, 1, 0, &tags));

    // Pages 2-4: fake Opus audio data
    for i in 0..3 {
        let mut audio_data = vec![0xFC; 20]; // TOC byte + padding (silence-like)
        audio_data.extend_from_slice(&[0u8; 80]);
        let granule = (i + 1) * 960;
        out.extend_from_slice(&make_ogg_page(
            if i == 2 { 0x04 } else { 0x00 },
            1,
            (i + 2) as u32,
            granule,
            &audio_data,
        ));
    }

    std::fs::write(fixtures_path("voice_note.ogg"), &out).unwrap();
    println!("  generated voice_note.ogg ({} bytes)", out.len());
}

fn generate_minimal_mp4() {
    let mut out = Vec::new();

    // ftyp
    out.extend_from_slice(&make_mp4_atom(b"ftyp", b"isom\x00\x00\x02\x00isomiso2mp41"));

    // moov with metadata
    let mvhd = vec![0u8; 108]; // version 0 mvhd
    let tkhd = vec![0u8; 92]; // version 0 tkhd
    let mdhd = vec![0u8; 32]; // version 0 mdhd

    let stbl = make_mp4_container(
        b"stbl",
        &[
            make_mp4_atom(b"stsd", &[0u8; 16]),
            make_mp4_atom(b"stts", &[0, 0, 0, 0, 0, 0, 0, 0]), // version + 0 entries
            make_mp4_atom(b"stsc", &[0, 0, 0, 0, 0, 0, 0, 0]),
            make_mp4_atom(b"stsz", &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            make_mp4_atom(b"stco", &[0, 0, 0, 0, 0, 0, 0, 0]), // version + 0 entries
        ],
    );
    let minf = make_mp4_container(b"minf", &[stbl]);
    let mdia = make_mp4_container(
        b"mdia",
        &[
            make_mp4_atom(b"mdhd", &mdhd),
            make_mp4_atom(b"hdlr", &[0u8; 33]),
            minf,
        ],
    );
    let trak = make_mp4_container(b"trak", &[make_mp4_atom(b"tkhd", &tkhd), mdia]);
    // udta with GPS location and title (should be stripped)
    let udta = make_mp4_atom(b"udta", b"\xa9nam\x00\x00\x00\x10data\x00\x00\x00\x01Evil Video\x00\xa9xyz\x00\x00\x00\x1048.8566+2.3522/");

    let moov = make_mp4_container(b"moov", &[make_mp4_atom(b"mvhd", &mvhd), trak, udta]);
    out.extend_from_slice(&moov);

    // mdat with fake H.264 NAL units
    let mut mdat_payload = Vec::new();
    // SPS NAL
    mdat_payload.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E, 0xAB, 0x40, 0x50]);
    // PPS NAL
    mdat_payload.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xCE, 0x38, 0x80]);
    // IDR slice NAL (fake)
    mdat_payload.extend_from_slice(&[0, 0, 0, 1, 0x65]);
    mdat_payload.extend_from_slice(&vec![0xAA; 500]);
    out.extend_from_slice(&make_mp4_atom(b"mdat", &mdat_payload));

    // free atom (padding — should be stripped)
    out.extend_from_slice(&make_mp4_atom(b"free", &[0u8; 64]));

    std::fs::write(fixtures_path("video_with_metadata.mp4"), &out).unwrap();
    println!("  generated video_with_metadata.mp4 ({} bytes)", out.len());
}

fn generate_minimal_webm() {
    let mut out = Vec::new();

    // EBML header
    out.extend_from_slice(&make_ebml_element(&[0x1A, 0x45, 0xDF, 0xA3], &{
        let mut h = Vec::new();
        // DocType = "webm"
        h.extend_from_slice(&make_ebml_element(&[0x42, 0x82], b"webm"));
        // DocTypeVersion = 2
        h.extend_from_slice(&make_ebml_element(&[0x42, 0x87], &[0x02]));
        h
    }));

    // Segment
    let mut segment_data = Vec::new();

    // Info (duration, title)
    segment_data.extend_from_slice(&make_ebml_element(&[0x15, 0x49, 0xA9, 0x66], &{
        let mut info = Vec::new();
        // TimecodeScale = 1000000 (default)
        info.extend_from_slice(&make_ebml_element(&[0x2A, 0xD7, 0xB1], &[0x0F, 0x42, 0x40]));
        // Duration (float, ~5 seconds)
        info.extend_from_slice(&make_ebml_element(&[0x44, 0x89], &5000.0f64.to_be_bytes()));
        info
    }));

    // Tracks
    segment_data.extend_from_slice(&make_ebml_element(&[0x16, 0x54, 0xAE, 0x6B], &{
        let mut tracks = Vec::new();
        // TrackEntry
        tracks.extend_from_slice(&make_ebml_element(&[0xAE], &{
            let mut entry = Vec::new();
            // TrackNumber = 1
            entry.extend_from_slice(&make_ebml_element(&[0xD7], &[0x01]));
            // TrackUID
            entry.extend_from_slice(&make_ebml_element(&[0x73, 0xC5], &[0x01]));
            // TrackType = video (1)
            entry.extend_from_slice(&make_ebml_element(&[0x83], &[0x01]));
            // CodecID = V_VP9
            entry.extend_from_slice(&make_ebml_element(&[0x86], b"V_VP9"));
            entry
        }));
        tracks
    }));

    // Tags (metadata — should be stripped by CDR)
    segment_data.extend_from_slice(&make_ebml_element(&[0x12, 0x54, 0xC3, 0x67], &{
        let mut tags = Vec::new();
        // Tag
        tags.extend_from_slice(&make_ebml_element(&[0x73, 0x73], &{
            let mut tag = Vec::new();
            // SimpleTag
            tag.extend_from_slice(&make_ebml_element(&[0x67, 0xC8], &{
                let mut st = Vec::new();
                // TagName
                st.extend_from_slice(&make_ebml_element(&[0x45, 0xA3], b"ARTIST"));
                // TagString
                st.extend_from_slice(&make_ebml_element(&[0x44, 0x87], b"Evil Artist"));
                st
            }));
            tag
        }));
        tags
    }));

    // Cluster with fake VP9 frames
    segment_data.extend_from_slice(&make_ebml_element(&[0x1F, 0x43, 0xB6, 0x75], &{
        let mut cluster = Vec::new();
        // Timecode = 0
        cluster.extend_from_slice(&make_ebml_element(&[0xE7], &[0x00]));
        // SimpleBlock
        let mut block = Vec::new();
        block.push(0x81); // track 1, VINT
        block.extend_from_slice(&0i16.to_be_bytes()); // timecode
        block.push(0x80); // flags (keyframe)
        block.extend_from_slice(&[0xAA; 200]); // fake VP9 data
        cluster.extend_from_slice(&make_ebml_element(&[0xA3], &block));
        cluster
    }));

    out.extend_from_slice(&make_ebml_element(&[0x18, 0x53, 0x80, 0x67], &segment_data));

    std::fs::write(fixtures_path("video_with_tags.webm"), &out).unwrap();
    println!("  generated video_with_tags.webm ({} bytes)", out.len());
}

fn generate_minimal_apng() {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);

    // IHDR: 2×2, 8-bit RGB
    let ihdr = [0, 0, 0, 2, 0, 0, 0, 2, 8, 2, 0, 0, 0];
    write_png_chunk(&mut out, b"IHDR", &ihdr);

    // acTL: 2 frames, infinite loop
    let mut actl = Vec::new();
    actl.extend_from_slice(&2u32.to_be_bytes()); // num_frames
    actl.extend_from_slice(&0u32.to_be_bytes()); // num_plays (0 = infinite)
    write_png_chunk(&mut out, b"acTL", &actl);

    // Metadata that should be stripped
    write_png_chunk(&mut out, b"tEXt", b"Author\0Evil Author");
    write_png_chunk(
        &mut out,
        b"iTXt",
        b"Comment\0\0\0\0\0This is malicious metadata",
    );

    // fcTL for frame 0
    let fctl0 = build_fctl(0, (2, 2), (0, 0), (50, 100), (0, 0));
    write_png_chunk(&mut out, b"fcTL", &fctl0);

    // IDAT: frame 0 (2×2 red pixels)
    let scanlines = [0, 255, 0, 0, 255, 0, 0, 0, 255, 0, 0, 255, 0, 0];
    let mut compressed = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
        encoder.write_all(&scanlines).unwrap();
        encoder.finish().unwrap();
    }
    write_png_chunk(&mut out, b"IDAT", &compressed);

    // fcTL for frame 1
    let fctl1 = build_fctl(1, (2, 2), (0, 0), (50, 100), (0, 0));
    write_png_chunk(&mut out, b"fcTL", &fctl1);

    // fdAT: frame 1 (2×2 blue pixels)
    let scanlines2 = [0, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255, 0, 0, 255];
    let mut compressed2 = Vec::new();
    {
        let mut encoder =
            flate2::write::ZlibEncoder::new(&mut compressed2, flate2::Compression::default());
        encoder.write_all(&scanlines2).unwrap();
        encoder.finish().unwrap();
    }
    let mut fdat = Vec::new();
    fdat.extend_from_slice(&2u32.to_be_bytes()); // sequence_number
    fdat.extend_from_slice(&compressed2);
    write_png_chunk(&mut out, b"fdAT", &fdat);

    write_png_chunk(&mut out, b"IEND", &[]);

    std::fs::write(fixtures_path("animated_with_metadata.apng"), &out).unwrap();
    println!(
        "  generated animated_with_metadata.apng ({} bytes)",
        out.len()
    );
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

fn build_fctl(
    seq: u32,
    size: (u32, u32),
    offset: (u32, u32),
    delay: (u16, u16),
    ops: (u8, u8),
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&size.0.to_be_bytes());
    f.extend_from_slice(&size.1.to_be_bytes());
    f.extend_from_slice(&offset.0.to_be_bytes());
    f.extend_from_slice(&offset.1.to_be_bytes());
    f.extend_from_slice(&delay.0.to_be_bytes());
    f.extend_from_slice(&delay.1.to_be_bytes());
    f.push(ops.0);
    f.push(ops.1);
    f
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
    page.push(0);
    page.push(header_type);
    page.extend_from_slice(&granule.to_le_bytes());
    page.extend_from_slice(&serial.to_le_bytes());
    page.extend_from_slice(&seq.to_le_bytes());
    page.extend_from_slice(&[0u8; 4]);
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

fn make_ebml_element(id_bytes: &[u8], data: &[u8]) -> Vec<u8> {
    let mut elem = Vec::new();
    elem.extend_from_slice(id_bytes);
    let size = data.len() as u64;
    if size < 0x7F {
        elem.push(0x80 | size as u8);
    } else if size < 0x3FFF {
        elem.push(0x40 | ((size >> 8) & 0x3F) as u8);
        elem.push((size & 0xFF) as u8);
    } else {
        panic!("test helper only supports small EBML elements");
    }
    elem.extend_from_slice(data);
    elem
}
