use std::process::Command;

#[test]
fn cli_releases_only_a_readable_result_and_never_overwrites_source() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("зображення з пробілом.png");
    image::DynamicImage::new_rgb8(16, 16).save(&input).unwrap();
    let original = std::fs::read(&input).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mdocdr"))
        .arg("--input")
        .arg(&input)
        .arg("--output-dir")
        .arg(temp.path().join("results"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["released"], true);
    let new_file = report["output_path"].as_str().unwrap();
    let result = image::open(new_file).unwrap();
    assert_eq!((result.width(), result.height()), (16, 16));
    assert_eq!(std::fs::read(&input).unwrap(), original);
    assert!(std::path::Path::new(report["report_path"].as_str().unwrap()).is_file());
}

#[test]
fn cli_wrong_declared_type_emits_report_without_media_file() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("sample.png");
    image::DynamicImage::new_rgb8(8, 8).save(&input).unwrap();
    let dest = temp.path().join("results");
    let output = Command::new(env!("CARGO_BIN_EXE_mdocdr"))
        .arg("--input")
        .arg(&input)
        .arg("--output-dir")
        .arg(&dest)
        .args(["--mime", "video/mp4", "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["released"], false);
    assert!(report["output_path"].is_null());
    let paths: Vec<_> = std::fs::read_dir(dest)
        .unwrap()
        .map(|p| p.unwrap().path())
        .collect();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].extension().unwrap(), "json");
}

#[test]
fn cli_rejects_duplicate_or_unknown_options() {
    for args in [
        vec!["--input", "a", "--input", "b", "--json"],
        vec!["--not-an-option", "--json"],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_mdocdr"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["released"], false);
    }
}
