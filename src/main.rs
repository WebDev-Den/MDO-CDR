use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use mdo_cdr::{DefenseContext, DefenseVerdict, FileDefender, policy::DefensePolicy};
use serde_json::{Value, json};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json_mode = args.iter().any(|s| s == "--json");
    match run(&args) {
        Ok((result, code)) => {
            if json_mode || args.iter().any(|s| s == "--self-test") {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else if let Some(message) = result.get("message").and_then(Value::as_str) {
                println!("{message}");
            } else {
                println!(
                    "MDO-CDR: {}",
                    result["status"].as_str().unwrap_or("unknown")
                );
                if let Some(path) = result["output_path"].as_str() {
                    println!("Результат: {path}");
                }
                if let Some(path) = result["report_path"].as_str() {
                    println!("Звіт: {path}");
                }
                for alert in result["alerts"].as_array().into_iter().flatten() {
                    println!("{}: {}", alert["code"], alert["message"]);
                }
            }
            std::process::exit(code);
        }
        Err(error) => {
            if json_mode {
                println!(
                    "{}",
                    json!({"program":"MDO-CDR", "status":"error", "released":false, "error":error})
                );
            } else {
                eprintln!("MDO-CDR: {error}");
            }
            std::process::exit(1);
        }
    }
}

fn value(args: &[String], key: &str) -> Result<Option<String>, String> {
    let positions: Vec<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(i, s)| (s == key).then_some(i))
        .collect();
    if positions.len() > 1 {
        return Err(format!("Повторний параметр {key}"));
    }
    match positions.first() {
        Some(i) => args
            .get(i + 1)
            .filter(|s| !s.starts_with("--"))
            .cloned()
            .map(Some)
            .ok_or_else(|| format!("Потрібне значення після {key}")),
        None => Ok(None),
    }
}

fn run(args: &[String]) -> Result<(Value, i32), String> {
    if args.is_empty() || args.iter().any(|s| s == "--help") {
        return Ok((
            json!({"message": "MDO-CDR — контрольована перебудова мультимедійних файлів\n\nmdocdr --input FILE --output-dir FOLDER [--mime MIME] [--profile dissertation|standard|strict|paranoid] [--ffmpeg FILE] [--ffprobe FILE] [--json]\nmdocdr --self-test\nmdocdr --version\n\nТиповий профіль: dissertation. Вихід надається лише після успішної перевірки.\nКоди завершення: 0 — надано; 2 — не надано; 1 — помилка виклику/запису."}),
            0,
        ));
    }
    if args.iter().any(|s| s == "--version") {
        return Ok((
            json!({"message":concat!("MDO-CDR ",env!("CARGO_PKG_VERSION")), "version":env!("CARGO_PKG_VERSION")}),
            0,
        ));
    }
    if args.iter().any(|s| s == "--self-test") {
        return self_test();
    }
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => i += 1,
            "--input" | "--output-dir" | "--mime" | "--profile" | "--ffmpeg" | "--ffprobe" => {
                value(args, &args[i])?;
                i += 2;
            }
            other => return Err(format!("Невідомий параметр: {other}")),
        }
    }
    let input = PathBuf::from(value(args, "--input")?.ok_or("Потрібен --input FILE")?);
    let output_dir =
        PathBuf::from(value(args, "--output-dir")?.ok_or("Потрібен --output-dir FOLDER")?);
    let profile = value(args, "--profile")?.unwrap_or_else(|| "dissertation".into());
    let mut policy = match profile.as_str() {
        "dissertation" => DefensePolicy::dissertation_profile(),
        "standard" => DefensePolicy::default(),
        "strict" => DefensePolicy::strict_profile(),
        "paranoid" => DefensePolicy::paranoid_profile(),
        _ => return Err("Невідомий профіль".into()),
    };
    if let Some(bin) = value(args, "--ffmpeg")?.or_else(|| std::env::var("MDO_CDR_FFMPEG").ok()) {
        policy.audio.ffmpeg_bin = bin.clone();
        policy.video.ffmpeg_bin = bin;
    }
    if let Some(bin) = value(args, "--ffprobe")?.or_else(|| std::env::var("MDO_CDR_FFPROBE").ok()) {
        policy.audio.ffprobe_bin = bin.clone();
        policy.video.ffprobe_bin = bin;
    }
    let file = std::fs::File::open(&input).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Вхід має бути звичайним файлом".into());
    }
    let mut bytes = Vec::new();
    file.take(policy.max_input_size_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > policy.max_input_size_bytes {
        return Err("Файл перевищує обмеження профілю".into());
    }
    let name = input
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Некоректне ім'я файла")?
        .to_string();
    let context = DefenseContext {
        declared_mime: value(args, "--mime")?,
        ..DefenseContext::default()
    };
    let defender = FileDefender::new(policy);
    let result = defender.defend_bytes(bytes, Some(name.clone()), context);
    std::fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let output_dir = output_dir.canonicalize().map_err(|e| e.to_string())?;
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("media");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let prefix = format!("{stem}.cdr-{stamp}");
    let mut report = match result {
        Ok(result) => {
            let released = result.can_release();
            let output_path = if released {
                let path =
                    output_dir.join(format!("{prefix}.{}", extension(&result.artifact.mime)?));
                write_new(&path, &result.artifact.output_bytes)?;
                Some(path.to_string_lossy().to_string())
            } else {
                None
            };
            json!({
                "program":"MDO-CDR", "version":env!("CARGO_PKG_VERSION"), "profile":profile,
                "input_name":name, "status":format!("{:?}",result.verdict), "released":released,
                "output_path":output_path, "mime":result.artifact.mime,
                "input_bytes":result.artifact.original_size, "candidate_bytes":result.artifact.output_size,
                "candidate_sha256":result.artifact.sha256,
                "duration_ms":result.diagnostics.duration_ms,
                "alerts":result.alerts.iter().map(|a|json!({"code":a.code,"message":a.message,"severity":format!("{:?}",a.severity)})).collect::<Vec<_>>(),
                "stages":result.stages.iter().map(|s|json!({"stage":format!("{:?}",s.stage),"status":format!("{:?}",s.status),"detail":s.detail})).collect::<Vec<_>>()
            })
        }
        Err(error) => {
            json!({"program":"MDO-CDR", "version":env!("CARGO_PKG_VERSION"), "profile":profile,
            "input_name":name, "status":"Blocked", "released":false, "error":error.to_string(), "output_path":null})
        }
    };
    let report_path = output_dir.join(format!("{prefix}.json"));
    report["report_path"] = json!(report_path.to_string_lossy());
    write_new(
        &report_path,
        &serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )?;
    let code = if report["released"] == true { 0 } else { 2 };
    Ok((report, code))
}

fn extension(mime: &str) -> Result<&'static str, String> {
    match mime {
        "image/png" => Ok("png"),
        "image/jpeg" => Ok("jpg"),
        "image/webp" => Ok("webp"),
        "image/gif" => Ok("gif"),
        "video/mp4" | "application/mp4" => Ok("mp4"),
        "video/webm" => Ok("webm"),
        "audio/mpeg" | "audio/mp3" => Ok("mp3"),
        "audio/wav" | "audio/x-wav" | "audio/wave" => Ok("wav"),
        "audio/flac" | "audio/x-flac" => Ok("flac"),
        "audio/ogg" | "audio/opus" => Ok("ogg"),
        "audio/mp4" | "audio/x-m4a" => Ok("m4a"),
        "audio/aac" => Ok("aac"),
        _ => Err(format!("Немає вихідного розширення для {mime}")),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("Вихідна папка відсутня")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(path).map_err(|e| e.to_string())?;
    Ok(())
}

fn self_test() -> Result<(Value, i32), String> {
    let mut image_bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(8, 8)
        .write_to(&mut image_bytes, image::ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    let bytes = image_bytes.into_inner();
    let defender = FileDefender::new(DefensePolicy::dissertation_profile());
    let clean = defender
        .defend_bytes(
            bytes.clone(),
            Some("sample.png".into()),
            DefenseContext::default(),
        )
        .map_err(|e| e.to_string())?;
    let mismatch = defender
        .defend_bytes(
            bytes.clone(),
            Some("sample.mp4".into()),
            DefenseContext::default(),
        )
        .is_err();
    let mut policy = DefensePolicy::dissertation_profile();
    policy
        .signature_rules
        .push(mdo_cdr::SignatureRule::anywhere(
            "demo-marker",
            b"MDO_TEST_MARKER".to_vec(),
        ));
    let mut marked = bytes;
    marked.extend_from_slice(b"MDO_TEST_MARKER");
    let blocked = FileDefender::new(policy)
        .defend_bytes(marked, Some("sample.png".into()), DefenseContext::default())
        .map_err(|e| e.to_string())?;
    let ok = clean.can_release()
        && clean.verdict == DefenseVerdict::Clean
        && mismatch
        && !blocked.can_release()
        && blocked.artifact.output_bytes.is_empty();
    Ok((
        json!({"program":"MDO-CDR","passed":ok,"checks":{"valid_png":clean.can_release(),"mismatch_rejected":mismatch,"blocked_bytes_withheld":blocked.artifact.output_bytes.is_empty()}}),
        if ok { 0 } else { 1 },
    ))
}
