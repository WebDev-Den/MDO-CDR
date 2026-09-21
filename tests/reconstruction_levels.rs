use mdo_cdr::{
    DefenseContext, PipelineStage,
    handlers::{audio::AudioHandler, video::VideoHandler},
    policy::{AudioMode, AudioOutputCodec, AudioPolicy, ProbeFailureMode, VideoMode, VideoPolicy},
};

fn wav_sample() -> Vec<u8> {
    let samples: Vec<i16> = (0..1600)
        .map(|index| {
            ((index as f64 * 440.0 * std::f64::consts::TAU / 8000.0).sin() * 1000.0) as i16
        })
        .collect();
    let data_size = (samples.len() * 2) as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&(36 + data_size).to_le_bytes());
    bytes.extend_from_slice(b"WAVEfmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&8000_u32.to_le_bytes());
    bytes.extend_from_slice(&16000_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&16_u16.to_le_bytes());
    bytes.extend_from_slice(b"data");
    bytes.extend_from_slice(&data_size.to_le_bytes());
    for sample in samples {
        bytes.extend_from_slice(&sample.to_le_bytes());
    }
    bytes
}

// Two 16x16 black H.264 frames in an MP4 container, generated as a benign
// fixture with FFmpeg. Embedded so the missing-runtime tests need no decoder.
fn mp4_sample() -> Vec<u8> {
    hex::decode(concat!(
        "000000206674797069736f6d0000020069736f6d69736f32617663316d7034310000000866726565000002d96d6461740000",
        "02ae0605ffffaadc45e9bde6d948b7962cd820d923eeef78323634202d20636f726520313635207233323233203034383063",
        "6230202d20482e3236342f4d5045472d342041564320636f646563202d20436f70796c65667420323030332d32303235202d",
        "20687474703a2f2f7777772e766964656f6c616e2e6f72672f783236342e68746d6c202d206f7074696f6e733a2063616261",
        "633d31207265663d33206465626c6f636b3d313a303a3020616e616c7973653d3078333a3078313133206d653d6865782073",
        "75626d653d37207073793d31207073795f72643d312e30303a302e3030206d697865645f7265663d31206d655f72616e6765",
        "3d3136206368726f6d615f6d653d31207472656c6c69733d31203878386463743d312063716d3d3020646561647a6f6e653d",
        "32312c313120666173745f70736b69703d31206368726f6d615f71705f6f66667365743d2d3220746872656164733d31206c",
        "6f6f6b61686561645f746872656164733d3120736c696365645f746872656164733d30206e723d3020646563696d6174653d",
        "3120696e7465726c616365643d3020626c757261795f636f6d7061743d3020636f6e73747261696e65645f696e7472613d30",
        "20626672616d65733d3320625f707972616d69643d3220625f61646170743d3120625f626961733d30206469726563743d31",
        "20776569676874623d31206f70656e5f676f703d3020776569676874703d32206b6579696e743d323530206b6579696e745f",
        "6d696e3d3235207363656e656375743d343020696e7472615f726566726573683d302072635f6c6f6f6b61686561643d3430",
        "2072633d637266206d62747265653d31206372663d32332e302071636f6d703d302e36302071706d696e3d302071706d6178",
        "3d3639207170737465703d342069705f726174696f3d312e34302061713d313a312e303000800000000f658884002ffffef6",
        "aefccb2b747f8100000008419a216c42bffec0000003306d6f6f760000006c6d766864000000000000000000000000000003",
        "e800000050000100000100000000000000000000000001000000000000000000000000000000010000000000000000000000",
        "00000040000000000000000000000000000000000000000000000000000000000000020000025b7472616b0000005c746b68",
        "6400000003000000000000000000000001000000000000005000000000000000000000000000000000000100000000000000",
        "000000000000000001000000000000000000000000000040000000001000000010000000000024656474730000001c656c73",
        "740000000000000001000000500000000000010000000001d36d646961000000206d64686400000000000000000000000000",
        "0032000000040055c400000000002d68646c72000000000000000076696465000000000000000000000000566964656f4861",
        "6e646c6572000000017e6d696e6600000014766d68640000000100000000000000000000002464696e660000001c64726566",
        "00000000000000010000000c75726c20000000010000013e7374626c000000be737473640000000000000001000000ae6176",
        "6331000000000000000100000000000000000000000000000000001000100048000000480000000000000001144c61766336",
        "332e312e313032206c69627832363400000000000000000000000018ffff00000034617663430164000affe100176764000a",
        "acd95ec044000003000400000300c83c48965801000668ebe3cb22c0fdf8f800000000107061737000000001000000010000",
        "00146274727400000000000119a4000000000000001873747473000000000000000100000002000002000000001473747373",
        "0000000000000001000000010000001c7374736300000000000000010000000100000002000000010000001c7374737a0000",
        "00000000000000000002000002c50000000c000000147374636f000000000000000100000030000000617564746100000059",
        "6d657461000000000000002168646c7200000000000000006d6469726170706c0000000000000000000000002c696c737400",
        "000024a9746f6f0000001c6461746100000001000000004c61766636332e312e313032",
    )).expect("embedded MP4 fixture is valid hex")
}

#[test]
fn required_audio_transcode_never_falls_back_to_native_wav() {
    let input = wav_sample();
    let native = AudioHandler::new(AudioPolicy::default())
        .rebuild(input.clone(), DefenseContext::default())
        .expect("valid WAV has a native structural route");
    assert!(!native.output_bytes.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let missing = dir
        .path()
        .join("missing-ffmpeg")
        .to_string_lossy()
        .into_owned();
    let policy = AudioPolicy {
        mode: AudioMode::RequireFfmpeg,
        ffmpeg_bin: missing.clone(),
        ffprobe_bin: missing,
        ..AudioPolicy::default()
    };
    assert!(
        AudioHandler::new(policy)
            .rebuild(input, DefenseContext::default())
            .is_err()
    );
}

#[test]
fn required_video_transcode_never_falls_back_to_native_mp4() {
    let input = mp4_sample();
    let native = VideoHandler::new(VideoPolicy::default())
        .rebuild(input.clone(), DefenseContext::default())
        .expect("valid MP4 has a native structural route");
    assert!(!native.output_bytes.is_empty());
    let dir = tempfile::tempdir().unwrap();
    let missing = dir
        .path()
        .join("missing-ffmpeg")
        .to_string_lossy()
        .into_owned();
    let policy = VideoPolicy {
        mode: VideoMode::RequireFfmpeg,
        ffmpeg_bin: missing.clone(),
        ffprobe_bin: missing,
        ..VideoPolicy::default()
    };
    assert!(
        VideoHandler::new(policy)
            .rebuild(input, DefenseContext::default())
            .is_err()
    );
}

#[test]
#[ignore = "requires MDO_TEST_FFMPEG and MDO_TEST_FFPROBE runtime paths"]
fn semantic_audio_and_video_transcode_with_external_runtime() {
    let ffmpeg = std::env::var("MDO_TEST_FFMPEG").expect("provide FFmpeg runtime");
    let ffprobe = std::env::var("MDO_TEST_FFPROBE").expect("provide FFprobe runtime");
    let audio = AudioHandler::new(AudioPolicy {
        mode: AudioMode::RequireFfmpeg,
        ffmpeg_bin: ffmpeg.clone(),
        ffprobe_bin: ffprobe.clone(),
        // Even this request cannot enable stream copy in the required route.
        output_codec: AudioOutputCodec::KeepOriginalWhenPossible,
        probe_failure_mode: ProbeFailureMode::Block,
        ..AudioPolicy::default()
    })
    .rebuild(wav_sample(), DefenseContext::default())
    .expect("WAV transcodes");
    assert_eq!(audio.mime, "audio/mpeg");
    assert!(!audio.output_bytes.is_empty());
    assert!(
        audio
            .stages
            .iter()
            .any(|stage| stage.stage == PipelineStage::Rebuild
                && stage.detail == "achieved_reconstruction=semantic")
    );
    let video = VideoHandler::new(VideoPolicy {
        mode: VideoMode::RequireFfmpeg,
        ffmpeg_bin: ffmpeg,
        ffprobe_bin: ffprobe,
        probe_failure_mode: ProbeFailureMode::Block,
        ..VideoPolicy::default()
    })
    .rebuild(mp4_sample(), DefenseContext::default())
    .expect("MP4 transcodes with an explicit output container");
    assert_eq!(video.mime, "video/mp4");
    assert!(!video.output_bytes.is_empty());
    assert!(
        video
            .stages
            .iter()
            .any(|stage| stage.stage == PipelineStage::Rebuild
                && stage.detail == "achieved_reconstruction=semantic")
    );
}
