//! End-to-end media checks enabled by CI when FFmpeg and FFprobe are installed.
use std::path::Path;
use std::process::{Command, Output};

fn successful(command: &mut Command) -> Output {
    let output = command.output().expect("start external media process");
    assert!(
        output.status.success(),
        "{command:?} failed with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

#[test]
#[ignore = "requires MDO_TEST_FFMPEG and MDO_TEST_FFPROBE; exercised by the media CI job"]
fn cli_audio_video_roundtrip_with_external_runtime() {
    let ffmpeg = std::env::var_os("MDO_TEST_FFMPEG").expect("set MDO_TEST_FFMPEG");
    let ffprobe = std::env::var_os("MDO_TEST_FFPROBE").expect("set MDO_TEST_FFPROBE");
    let temp = tempfile::tempdir().unwrap();

    // Fixed one-second fixtures keep generation, reconstruction, and full decoding
    // small. The dedicated CI job also has an outer execution timeout.
    for (filename, filter, encoding, stream_kind) in [
        (
            "mono audio.wav",
            "sine=frequency=440:sample_rate=44100:duration=1",
            vec!["-ac", "1", "-c:a", "pcm_s16le"],
            "audio",
        ),
        (
            "short video.mp4",
            "testsrc2=size=96x64:rate=12:duration=1",
            vec!["-an", "-c:v", "mpeg4", "-pix_fmt", "yuv420p"],
            "video",
        ),
    ] {
        let input = temp.path().join(filename);
        successful(
            Command::new(&ffmpeg)
                .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i", filter])
                .args(encoding)
                .arg(&input),
        );
        let original = std::fs::read(&input).unwrap();
        let destination = temp.path().join(format!("{stream_kind} results"));
        let invocation = successful(
            Command::new(env!("CARGO_BIN_EXE_mdocdr"))
                .arg("--input")
                .arg(&input)
                .arg("--output-dir")
                .arg(&destination)
                .args(["--profile", "dissertation", "--ffmpeg"])
                .arg(&ffmpeg)
                .arg("--ffprobe")
                .arg(&ffprobe)
                .arg("--json"),
        );
        let report: serde_json::Value = serde_json::from_slice(&invocation.stdout).unwrap();
        assert_eq!(report["released"], true, "{report}");
        let output = Path::new(report["output_path"].as_str().unwrap());
        let report_path = Path::new(report["report_path"].as_str().unwrap());
        assert!(output.is_file(), "missing released {stream_kind} file");
        assert!(report_path.is_file(), "missing persisted JSON report");
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
        assert_eq!(persisted, report, "stdout and persisted reports disagree");
        assert_eq!(
            std::fs::read(&input).unwrap(),
            original,
            "input was modified"
        );
        let destination = destination.canonicalize().unwrap();
        assert_eq!(
            output.canonicalize().unwrap().parent(),
            Some(destination.as_path())
        );
        assert_eq!(
            report_path.canonicalize().unwrap().parent(),
            Some(destination.as_path())
        );
        assert_eq!(std::fs::read_dir(&destination).unwrap().count(), 2);

        // Decode the entire released file outside the application. A playable
        // header alone must not satisfy this delivery contract.
        successful(
            Command::new(&ffmpeg)
                .args(["-nostdin", "-v", "error", "-xerror", "-i"])
                .arg(output)
                .args(["-map", "0", "-f", "null", "-"]),
        );
        let probe = successful(
            Command::new(&ffprobe)
                .args([
                    "-v",
                    "error",
                    "-count_frames",
                    "-show_entries",
                    "stream=codec_type,width,height,nb_read_frames,channels:format=duration",
                    "-of",
                    "json",
                ])
                .arg(output),
        );
        let probe: serde_json::Value = serde_json::from_slice(&probe.stdout).unwrap();
        let streams = probe["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 1, "unexpected streams: {probe}");
        let stream = &streams[0];
        assert_eq!(stream["codec_type"], stream_kind);
        let duration: f64 = probe["format"]["duration"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((duration - 1.0).abs() <= 0.15, "changed duration: {probe}");
        if stream_kind == "video" {
            assert_eq!(stream["width"], 96);
            assert_eq!(stream["height"], 64);
            assert_eq!(stream["nb_read_frames"], "12", "lost video frames: {probe}");
        } else {
            assert_eq!(stream["channels"], 1, "changed audio channels: {probe}");
        }
    }
}
