pub mod client;
pub mod error;
pub mod ffi;
pub mod handlers;
pub mod policy;
mod process;
pub mod server;
pub mod tenant;
pub mod types;
mod validation;

pub use defender_core::policy_schema;

use std::collections::HashSet;
use std::path::Path;

use defender_observability::{AuditSink, NoopAuditSink, PipelineAuditEvent};
use defender_signatures::{QuarantineEnvelope, SignatureEngine};
use handlers::{
    animated_image::AnimatedImageHandler, audio::AudioHandler, generic::GenericHandler,
    gif::GifHandler, image::ImageHandler, video::VideoHandler,
};
use sha2::{Digest, Sha256};

pub use error::DefenderError;
pub use types::{
    AlertSeverity, CancellationToken, DefendResult, DefendedArtifact, DefenseAlert, DefenseContext,
    DefenseDiagnostics, DefenseVerdict, FileKind, PipelineStage, PipelineStageReport,
    PipelineStageStatus, SignatureLocation, SignatureRule,
};

#[derive(Debug, Clone)]
pub struct FileDefender {
    policy: policy::DefensePolicy,
    signature_engine: SignatureEngine,
    audit_sink: NoopAuditSink,
    mime_index: RuntimeMimeIndex,
}

#[derive(Debug, Clone)]
struct RuntimeMimeIndex {
    image_allow: HashSet<String>,
    gif_allow: HashSet<String>,
    video_allow: HashSet<String>,
    audio_allow: HashSet<String>,
    other_allow: HashSet<String>,
    deny: HashSet<String>,
}

impl FileDefender {
    pub fn new(policy: policy::DefensePolicy) -> Self {
        let mime_index = RuntimeMimeIndex {
            image_allow: to_lower_set(&policy.output_mime_whitelist.image),
            gif_allow: to_lower_set(&policy.output_mime_whitelist.gif),
            video_allow: to_lower_set(&policy.output_mime_whitelist.video),
            audio_allow: to_lower_set(&policy.output_mime_whitelist.audio),
            other_allow: to_lower_set(&policy.output_mime_whitelist.other),
            deny: to_lower_set(&policy.output_mime_denylist),
        };
        // Baseline rules (EICAR canary, executable headers, shebangs) are
        // merged with user-supplied rules and compiled into one Aho-Corasick
        // automaton at construction time. Every scan then traverses the
        // input buffer exactly once regardless of rule count.
        let signature_engine = SignatureEngine::with_baseline(policy.signature_rules.clone());
        Self {
            policy,
            signature_engine,
            audit_sink: NoopAuditSink,
            mime_index,
        }
    }

    pub fn policy(&self) -> &policy::DefensePolicy {
        &self.policy
    }

    pub fn defend_path(
        &self,
        input_path: &Path,
        output_path: &Path,
        context: DefenseContext,
    ) -> Result<DefendResult, DefenderError> {
        use std::io::Read;
        let input = std::fs::File::open(input_path)?;
        let mut input_bytes = Vec::new();
        input
            .take(self.policy.max_input_size_bytes.saturating_add(1))
            .read_to_end(&mut input_bytes)?;
        let name = input_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(std::borrow::ToOwned::to_owned);
        let source = self.defend_bytes(input_bytes, name, context)?;
        if source.can_release() {
            use std::io::Write;
            let parent = output_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut staged = tempfile::NamedTempFile::new_in(parent)?;
            staged.write_all(&source.artifact.output_bytes)?;
            staged.as_file().sync_all()?;
            staged
                .persist_noclobber(output_path)
                .map_err(|error| error.error)?;
        }
        Ok(source)
    }

    pub fn defend_bytes(
        &self,
        input_bytes: Vec<u8>,
        file_name: Option<String>,
        context: DefenseContext,
    ) -> Result<DefendResult, DefenderError> {
        let started_at = std::time::Instant::now();
        let original_size = input_bytes.len() as u64;
        log::debug!(
            "defend_bytes entry: size={original_size} name={} tenant={}",
            file_name.as_deref().unwrap_or("<none>"),
            context.tenant_id.as_deref().unwrap_or("<none>")
        );
        let mime_guess = self.guess_mime(&input_bytes);
        let kind_from_name = FileKind::from_name(file_name.as_deref());
        let kind_from_mime = FileKind::from_mime(mime_guess.as_deref());
        // classify() peeks the input bytes for animation markers (APNG
        // acTL, WebP VP8X animation flag) so we detect AnimatedImage
        // even when the MIME guesser reports image/png or image/webp.
        let file_kind =
            FileKind::classify(&input_bytes, file_name.as_deref(), mime_guess.as_deref());
        let mut stages = Vec::new();
        let mut alerts = Vec::new();

        self.validate_before_rebuild(file_name.as_deref(), original_size)?;
        match self.policy.signature_scan_mode {
            policy::SignatureScanMode::OutputOnly => {}
            policy::SignatureScanMode::InputAndOutput => {
                let pre_scan_alerts = self.scan_signatures(&input_bytes);
                let mut pre_scan_count = 0usize;
                let mut has_pre_scan_blocking = false;
                for value in &pre_scan_alerts {
                    pre_scan_count += 1;
                    if value.is_blocking() {
                        has_pre_scan_blocking = true;
                    }
                }
                stages.push(PipelineStageReport {
                    stage: PipelineStage::PreScan,
                    status: stage_status_from_alerts(&pre_scan_alerts),
                    detail: format!("pre_scan_alerts={pre_scan_count}"),
                });
                for value in pre_scan_alerts {
                    alerts.push(value);
                }
                if has_pre_scan_blocking
                    && self.policy.block_on_pre_scan_match
                    && self.policy.enforcement_mode == policy::EnforcementMode::Enforce
                {
                    let mime = match &mime_guess {
                        Some(value) => value.clone(),
                        None => "application/octet-stream".to_string(),
                    };
                    let output_size = 0;
                    let digest = Self::sha256_hex(&input_bytes);
                    stages.push(PipelineStageReport {
                        stage: PipelineStage::OutputValidation,
                        status: PipelineStageStatus::Blocked,
                        detail: "blocked on input signature pre-scan".to_string(),
                    });
                    let duration_ms = started_at.elapsed().as_millis() as u64;
                    let diagnostics = DefenseDiagnostics {
                        duration_ms,
                        input_bytes: original_size,
                        output_bytes: output_size,
                        stripped_metadata_count: 0,
                        stripped_bytes: 0,
                        parser_used: "pre_scan_blocked".to_string(),
                    };
                    return Ok(DefendResult {
                        verdict: DefenseVerdict::Blocked,
                        alerts,
                        stages,
                        artifact: DefendedArtifact {
                            file_kind,
                            mime,
                            original_size,
                            output_size,
                            sha256: digest,
                            output_bytes: Vec::new(),
                        },
                        diagnostics,
                    });
                }
            }
        }
        self.validate_kind_consistency(kind_from_name, kind_from_mime)?;
        alerts.extend(self.validate_input_metadata(
            file_name.as_deref(),
            mime_guess.as_deref(),
            context.declared_mime.as_deref(),
        )?);
        let detection_status = self.detection_stage_status(kind_from_name, kind_from_mime);
        stages.push(PipelineStageReport {
            stage: PipelineStage::Detect,
            status: detection_status,
            detail: format!(
                "kind_from_name={}, kind_from_mime={}, selected={}, declared_mime={}",
                file_kind_label_optional(kind_from_name),
                file_kind_label_optional(kind_from_mime),
                file_kind_label(file_kind),
                context.declared_mime.as_deref().unwrap_or("unavailable")
            ),
        });

        // Set handler start time and timeout for enforcement.
        let mut rebuild_context = context.clone();
        rebuild_context.started_at = Some(std::time::Instant::now());
        rebuild_context.timeout_ms = self.policy.max_handler_duration_ms;
        let artifact = self.rebuild_with_policy(file_kind, input_bytes, rebuild_context.clone())?;
        let (level_stage, level_alert) = self.validate_reconstruction_level(file_kind, &artifact);
        stages.push(level_stage);
        if let Some(alert) = level_alert {
            alerts.push(alert);
        }
        for value in artifact.alerts {
            alerts.push(value);
        }
        for value in artifact.stages {
            stages.push(value);
        }
        let artifact_alerts =
            self.validate_output_artifact(file_kind, &artifact.mime, &artifact.output_bytes);
        for value in artifact_alerts {
            alerts.push(value);
        }

        if kind_from_name.is_none() {
            match self.policy.unknown_kind_mode {
                policy::UnknownKindMode::Warn => {
                    alerts.push(DefenseAlert::warning(
                        "unknown_extension",
                        "Unknown extension. Decoder selected from content sniffing only.",
                    ));
                }
                policy::UnknownKindMode::Block => {
                    alerts.push(DefenseAlert::blocking(
                        "unknown_extension",
                        "Unknown extension is blocked by policy.",
                    ));
                }
            }
        }
        if kind_from_mime.is_none() {
            match self.policy.unknown_kind_mode {
                policy::UnknownKindMode::Warn => {
                    alerts.push(DefenseAlert::warning(
                        "unknown_mime",
                        "Unknown binary signature. File may use unsupported container.",
                    ));
                }
                policy::UnknownKindMode::Block => {
                    alerts.push(DefenseAlert::blocking(
                        "unknown_mime",
                        "Unknown binary signature is blocked by policy.",
                    ));
                }
            }
        }
        if file_kind == FileKind::Other {
            let (stage, probe) =
                self.structured_probe_other(file_name.as_deref(), &artifact.output_bytes);
            stages.push(stage);
            if let Some(value) = probe {
                alerts.push(value);
            }
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::Rebuild,
            status: stage_status_from_alerts(&alerts),
            detail: format!(
                "rebuild_mime={} required_reconstruction={:?}",
                artifact.mime, self.policy.minimum_reconstruction_level
            ),
        });

        let signature_alerts = self.scan_signatures(&artifact.output_bytes);
        for alert in signature_alerts {
            alerts.push(alert);
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::SignatureScan,
            status: stage_status_from_alerts(&alerts),
            detail: format!("signature_alerts={}", alerts.len()),
        });

        let output_size = artifact.output_bytes.len() as u64;
        if output_size > self.policy.max_output_size_bytes {
            return Err(DefenderError::OutputTooLarge {
                limit: self.policy.max_output_size_bytes,
                actual: output_size,
            });
        }
        if original_size > 0 {
            let ratio = output_size as f64 / original_size as f64;
            if ratio > self.policy.max_output_expansion_ratio {
                return Err(DefenderError::OutputExpansionTooHigh {
                    limit: self.policy.max_output_expansion_ratio,
                    actual: ratio,
                });
            }
        }
        let (verification_stage, verification_alert) = validation::verify_output(
            file_kind,
            &artifact.output_bytes,
            &self.policy,
            &rebuild_context,
        );
        stages.push(verification_stage);
        if let Some(alert) = verification_alert {
            alerts.push(alert);
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::OutputValidation,
            status: stage_status_from_alerts(&alerts),
            detail: format!(
                "output_size={} max_output_size={} max_expansion_ratio={}",
                output_size,
                self.policy.max_output_size_bytes,
                self.policy.max_output_expansion_ratio
            ),
        });
        let digest = Self::sha256_hex(&artifact.output_bytes);

        if self.policy.enforcement_mode == policy::EnforcementMode::DryRun {
            self.apply_dry_run_mode(&mut alerts, &mut stages);
        }

        let mut has_blocking_alert = false;
        for alert in &alerts {
            if alert.is_blocking() {
                has_blocking_alert = true;
                break;
            }
        }
        let verdict = if has_blocking_alert {
            DefenseVerdict::Blocked
        } else {
            // Only Warning-severity alerts trigger Suspicious. Info alerts
            // are audit-only and never downgrade the verdict away from Clean.
            let mut has_warning = false;
            for alert in &alerts {
                if alert.is_warning() {
                    has_warning = true;
                    break;
                }
            }
            if has_warning {
                DefenseVerdict::Suspicious
            } else {
                DefenseVerdict::Clean
            }
        };
        if verdict == DefenseVerdict::Blocked {
            let envelope = self.build_quarantine_envelope(
                &alerts,
                &stages,
                original_size,
                output_size,
                &digest,
            );
            stages.push(PipelineStageReport {
                stage: PipelineStage::OutputValidation,
                status: PipelineStageStatus::Blocked,
                detail: format!(
                    "quarantine_ready reason={} sha256={}",
                    envelope.reason, envelope.sha256
                ),
            });
        }

        let source_label = match context.source {
            crate::types::SourceRole::Outgoing => "outgoing",
            crate::types::SourceRole::Incoming => "incoming",
        };
        let verdict_label = match verdict {
            DefenseVerdict::Clean => "clean",
            DefenseVerdict::Suspicious => "suspicious",
            DefenseVerdict::Blocked => "blocked",
        };
        self.audit_sink.emit(&PipelineAuditEvent {
            tenant_id: context.tenant_id,
            source: source_label.to_string(),
            verdict: verdict_label.to_string(),
            alert_count: alerts.len(),
            stage_count: stages.len(),
        });

        let duration_ms = started_at.elapsed().as_millis() as u64;
        log::info!(
            "defend_bytes exit: verdict={verdict_label} kind={} duration_ms={duration_ms} in={original_size} out={output_size} alerts={}",
            file_kind_label(file_kind),
            alerts.len()
        );
        let diagnostics = DefenseDiagnostics {
            duration_ms,
            input_bytes: original_size,
            output_bytes: output_size,
            stripped_metadata_count: 0,
            stripped_bytes: 0,
            parser_used: file_kind_label(file_kind).to_string(),
        };

        Ok(DefendResult {
            verdict,
            alerts,
            stages,
            artifact: DefendedArtifact {
                file_kind,
                mime: artifact.mime,
                original_size,
                output_size,
                sha256: digest,
                output_bytes: if verdict == DefenseVerdict::Clean {
                    artifact.output_bytes
                } else {
                    Vec::new()
                },
            },
            diagnostics,
        })
    }

    fn rebuild_with_policy(
        &self,
        file_kind: FileKind,
        input_bytes: Vec<u8>,
        context: DefenseContext,
    ) -> Result<handlers::HandlerResult, DefenderError> {
        let raw = input_bytes.clone();
        let rebuild = self.rebuild(file_kind, input_bytes, context.clone());
        match rebuild {
            Ok(value) => Ok(value),
            Err(err) => match self.policy.decoder_failure_mode {
                policy::DecoderFailureMode::Block => Err(err),
                policy::DecoderFailureMode::QuarantineAsOther => {
                    let handler = GenericHandler::new(self.policy.other.clone());
                    let mut value = handler.rebuild(raw, context)?;
                    value.alerts.push(DefenseAlert::blocking(
                        "decoder_failure_quarantine",
                        format!("Decoder failed for {:?}, quarantined as binary.", file_kind),
                    ));
                    Ok(value)
                }
            },
        }
    }

    fn validate_reconstruction_level(
        &self,
        file_kind: FileKind,
        artifact: &handlers::HandlerResult,
    ) -> (PipelineStageReport, Option<DefenseAlert>) {
        use policy::ReconstructionLevel::{Semantic, Structural};
        let achieved = match file_kind {
            FileKind::Image | FileKind::Gif
                if FileKind::from_mime(Some(&artifact.mime)) == Some(file_kind) =>
            {
                Some(Semantic)
            }
            FileKind::AnimatedImage
                if FileKind::from_mime(Some(&artifact.mime)) == Some(FileKind::Image) =>
            {
                Some(Structural)
            }
            FileKind::Audio | FileKind::Video => artifact.stages.iter().find_map(|stage| {
                if stage.stage != PipelineStage::Rebuild {
                    return None;
                }
                match stage.detail.as_str() {
                    "achieved_reconstruction=semantic" => Some(Semantic),
                    "achieved_reconstruction=structural" => Some(Structural),
                    _ => None,
                }
            }),
            _ => None,
        };
        let required = self.policy.minimum_reconstruction_level;
        let passed = matches!(
            (required, achieved),
            (Structural, Some(Structural | Semantic)) | (Semantic, Some(Semantic))
        );
        let detail =
            format!("required_reconstruction={required:?} achieved_reconstruction={achieved:?}");
        let alert = (!passed).then(|| {
            DefenseAlert::blocking(
                "reconstruction_level_not_met",
                "The candidate has not achieved the reconstruction level required by policy.",
            )
        });
        (
            PipelineStageReport {
                stage: PipelineStage::Rebuild,
                status: if passed {
                    PipelineStageStatus::Success
                } else {
                    PipelineStageStatus::Blocked
                },
                detail,
            },
            alert,
        )
    }

    fn rebuild(
        &self,
        file_kind: FileKind,
        input_bytes: Vec<u8>,
        context: DefenseContext,
    ) -> Result<handlers::HandlerResult, DefenderError> {
        // Defense: handlers process adversary-controlled bytes and can
        // panic on malformed input (index-out-of-bounds, arithmetic overflow,
        // unwrap on None, etc.). Any such panic must NOT propagate into the
        // consumer process — it would become a reliable DoS vector. We wrap
        // every handler invocation in catch_unwind, which requires
        // panic = "unwind" in the active profile (see Cargo.toml contract).
        //
        // The panic payload is deliberately summarised to a short type name
        // and not forwarded verbatim, because handler panics can embed
        // fragments of the input bytes via format! in panic messages.
        let image_policy = self.policy.image.clone();
        let animated_image_policy = self.policy.animated_image.clone();
        let gif_policy = self.policy.gif.clone();
        let mut video_policy = self.policy.video.clone();
        let mut audio_policy = self.policy.audio.clone();
        if self.policy.minimum_reconstruction_level == policy::ReconstructionLevel::Semantic {
            if matches!(file_kind, FileKind::AnimatedImage | FileKind::Other) {
                return Err(DefenderError::UnsupportedReconstructionLevel);
            }
            video_policy.mode = policy::VideoMode::RequireFfmpeg;
            audio_policy.mode = policy::AudioMode::RequireFfmpeg;
        }
        let other_policy = self.policy.other.clone();
        let kind_label = file_kind_label(file_kind).to_string();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match file_kind {
            FileKind::Image => {
                let handler = ImageHandler::new(image_policy);
                handler.rebuild(input_bytes, context)
            }
            FileKind::AnimatedImage => {
                let handler = AnimatedImageHandler::new(animated_image_policy);
                handler.rebuild(input_bytes, context)
            }
            FileKind::Gif => {
                let handler = GifHandler::new(gif_policy);
                handler.rebuild(input_bytes, context)
            }
            FileKind::Video => {
                let handler = VideoHandler::new(video_policy);
                handler.rebuild(input_bytes, context)
            }
            FileKind::Audio => {
                let handler = AudioHandler::new(audio_policy);
                handler.rebuild(input_bytes, context)
            }
            FileKind::Other => {
                let handler = GenericHandler::new(other_policy);
                handler.rebuild(input_bytes, context)
            }
        }));

        match result {
            Ok(handler_result) => handler_result,
            Err(payload) => {
                let message = extract_panic_summary(&payload);
                log::warn!("handler for {kind_label} panicked — returning HandlerPanic: {message}");
                Err(DefenderError::HandlerPanic {
                    kind: kind_label,
                    message,
                })
            }
        }
    }

    fn validate_before_rebuild(
        &self,
        file_name: Option<&str>,
        original_size: u64,
    ) -> Result<(), DefenderError> {
        if original_size > self.policy.max_input_size_bytes {
            log::warn!(
                "validate_before_rebuild: file too large size={original_size} limit={}",
                self.policy.max_input_size_bytes
            );
            return Err(DefenderError::FileTooLarge {
                limit: self.policy.max_input_size_bytes,
                actual: original_size,
            });
        }

        let Some(file_name) = file_name else {
            return Ok(());
        };
        let extension = Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);

        let Some(extension) = extension else {
            return Ok(());
        };
        if self.policy.blocked_extensions.contains(&extension) {
            log::warn!("validate_before_rebuild: blocked extension .{extension}");
            return Err(DefenderError::BlockedExtension { extension });
        }

        Ok(())
    }

    fn scan_signatures(&self, input: &[u8]) -> Vec<DefenseAlert> {
        // The engine was built once in FileDefender::new with baseline +
        // user rules. Each scan is a single Aho-Corasick pass.
        let hits = self.signature_engine.scan(input);
        let mut alerts = Vec::new();
        for hit in hits {
            alerts.push(DefenseAlert::blocking(
                "signature_match",
                format!("Matched signature rule: {}", hit.rule_name),
            ));
        }
        alerts
    }

    fn validate_kind_consistency(
        &self,
        kind_from_name: Option<FileKind>,
        kind_from_mime: Option<FileKind>,
    ) -> Result<(), DefenderError> {
        let Some(kind_from_name) = kind_from_name else {
            return Ok(());
        };
        let Some(kind_from_mime) = kind_from_mime else {
            return Ok(());
        };
        if compatible_kinds(kind_from_name, kind_from_mime) {
            return Ok(());
        }
        if self.policy.block_kind_mismatch {
            return Err(DefenderError::FileTypeMismatch);
        }
        Ok(())
    }

    fn detection_stage_status(
        &self,
        kind_from_name: Option<FileKind>,
        kind_from_mime: Option<FileKind>,
    ) -> PipelineStageStatus {
        match (kind_from_name, kind_from_mime) {
            (Some(left), Some(right)) => {
                if compatible_kinds(left, right) {
                    return PipelineStageStatus::Success;
                }
                if self.policy.block_kind_mismatch {
                    return PipelineStageStatus::Blocked;
                }
                PipelineStageStatus::Warning
            }
            (None, None) => match self.policy.unknown_kind_mode {
                policy::UnknownKindMode::Warn => PipelineStageStatus::Warning,
                policy::UnknownKindMode::Block => PipelineStageStatus::Blocked,
            },
            (None, Some(_)) => match self.policy.unknown_kind_mode {
                policy::UnknownKindMode::Warn => PipelineStageStatus::Warning,
                policy::UnknownKindMode::Block => PipelineStageStatus::Blocked,
            },
            (Some(_), None) => match self.policy.unknown_kind_mode {
                policy::UnknownKindMode::Warn => PipelineStageStatus::Warning,
                policy::UnknownKindMode::Block => PipelineStageStatus::Blocked,
            },
        }
    }

    fn guess_mime(&self, input: &[u8]) -> Option<String> {
        let kind = infer::get(input)?;
        Some(kind.mime_type().to_string())
    }

    fn validate_input_metadata(
        &self,
        file_name: Option<&str>,
        sniffed_mime: Option<&str>,
        declared_mime: Option<&str>,
    ) -> Result<Vec<DefenseAlert>, DefenderError> {
        let extension_mime = file_name.and_then(mime_from_filename);
        let mut alerts = Vec::new();
        let mut mismatch = false;
        if let (Some(expected), Some(actual)) = (extension_mime, sniffed_mime) {
            mismatch |= !compatible_mimes(expected, actual);
        }
        if let Some(declared) = declared_mime {
            let declared = normalized_mime(declared);
            if let Some(actual) = sniffed_mime {
                mismatch |= !compatible_mimes(&declared, actual);
            } else {
                alerts.push(DefenseAlert::warning(
                    "declared_mime_unverified",
                    "The declared MIME cannot be confirmed from the input bytes.",
                ));
            }
            if let Some(expected) = extension_mime {
                mismatch |= !compatible_mimes(&declared, expected);
            }
            mismatch |= !declared.contains('/') || declared.contains('*');
        }
        if mismatch {
            if self.policy.block_kind_mismatch {
                return Err(DefenderError::FileTypeMismatch);
            }
            alerts.push(DefenseAlert::warning(
                "input_mime_mismatch",
                "Filename, declared MIME, and detected byte format do not agree.",
            ));
        }
        Ok(alerts)
    }

    fn structured_probe_other(
        &self,
        file_name: Option<&str>,
        input: &[u8],
    ) -> (PipelineStageReport, Option<DefenseAlert>) {
        let Some(file_name) = file_name else {
            return (
                PipelineStageReport {
                    stage: PipelineStage::OtherProbe,
                    status: PipelineStageStatus::Success,
                    detail: "other probe skipped: no file name".to_string(),
                },
                None,
            );
        };
        let extension = Path::new(file_name)
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase);
        let Some(extension) = extension else {
            return (
                PipelineStageReport {
                    stage: PipelineStage::OtherProbe,
                    status: PipelineStageStatus::Success,
                    detail: "other probe skipped: no extension".to_string(),
                },
                None,
            );
        };

        let check = match extension.as_str() {
            "json" => {
                let parsed = serde_json::from_slice::<serde_json::Value>(input);
                parsed.is_ok()
            }
            "pdf" => {
                if input.len() < 5 {
                    false
                } else {
                    let starts = &input[..5] == b"%PDF-";
                    let ends = contains_bytes(input, b"%%EOF");
                    starts && ends
                }
            }
            "xml" => {
                let text = std::str::from_utf8(input);
                match text {
                    Ok(value) => {
                        let value = value.trim_start();
                        value.starts_with('<')
                    }
                    Err(_) => false,
                }
            }
            "zip" | "docx" | "xlsx" | "pptx" | "jar" | "apk" | "odt" => {
                if input.len() < 4 {
                    false
                } else {
                    let sig = &input[..4];
                    sig == b"PK\x03\x04" || sig == b"PK\x05\x06" || sig == b"PK\x07\x08"
                }
            }
            _ => true,
        };
        if check {
            return (
                PipelineStageReport {
                    stage: PipelineStage::OtherProbe,
                    status: PipelineStageStatus::Success,
                    detail: format!("other probe passed for .{extension}"),
                },
                None,
            );
        }

        let message = format!("Structured probe failed for .{extension} payload.");
        match self.policy.other.structured_probe_mode {
            policy::ProbeFailureMode::Warn => (
                PipelineStageReport {
                    stage: PipelineStage::OtherProbe,
                    status: PipelineStageStatus::Warning,
                    detail: format!("other probe warning for .{extension}"),
                },
                Some(DefenseAlert::warning(
                    "other_structured_probe_failed",
                    message,
                )),
            ),
            policy::ProbeFailureMode::Block => (
                PipelineStageReport {
                    stage: PipelineStage::OtherProbe,
                    status: PipelineStageStatus::Blocked,
                    detail: format!("other probe blocked for .{extension}"),
                },
                Some(DefenseAlert::blocking(
                    "other_structured_probe_failed",
                    message,
                )),
            ),
        }
    }

    fn sha256_hex(input: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let digest = hasher.finalize();
        hex::encode(digest)
    }

    fn validate_output_artifact(
        &self,
        expected_kind: FileKind,
        declared_mime: &str,
        output_bytes: &[u8],
    ) -> Vec<DefenseAlert> {
        let mut alerts = Vec::new();
        let declared_mime = declared_mime.to_ascii_lowercase();
        if output_bytes.is_empty() {
            alerts.push(DefenseAlert::blocking(
                "empty_output_artifact",
                "Output artifact is empty.",
            ));
            return alerts;
        }

        // Mandatory executable-magic check — runs ALWAYS regardless of
        // enforce_output_kind_match. A rebuilt media artifact should never
        // begin with an executable header. This catches bypass paths like
        // BypassWhenUnavailable where handlers return input unmodified.
        if let Some(exec_alert) = detect_executable_magic(output_bytes) {
            alerts.push(exec_alert);
        }

        if !self.policy.enforce_output_kind_match {
            return alerts;
        }
        if self.mime_index.deny.contains(declared_mime.as_str()) {
            alerts.push(DefenseAlert::blocking(
                "declared_output_mime_denied",
                format!(
                    "Declared output mime '{}' is denied by policy.",
                    declared_mime
                ),
            ));
        }
        if self.policy.enforce_output_mime_whitelist
            && !self.is_allowed_output_mime(expected_kind, declared_mime.as_str())
        {
            alerts.push(DefenseAlert::blocking(
                "declared_output_mime_not_allowed",
                format!(
                    "Declared output mime '{}' is not allowed for {:?}.",
                    declared_mime, expected_kind
                ),
            ));
        }

        let declared_kind = FileKind::from_mime(Some(&declared_mime));
        if let Some(declared_kind) = declared_kind
            && !compatible_kinds(declared_kind, expected_kind)
        {
            alerts.push(DefenseAlert::blocking(
                "declared_mime_kind_mismatch",
                format!(
                    "Declared mime maps to {:?}, expected {:?}.",
                    declared_kind, expected_kind
                ),
            ));
        }

        let sniffed_mime = self.guess_mime(output_bytes);
        let sniffed_kind = FileKind::from_mime(sniffed_mime.as_deref());
        if let Some(sniffed_kind) = sniffed_kind {
            if !compatible_kinds(sniffed_kind, expected_kind) {
                alerts.push(DefenseAlert::blocking(
                    "sniffed_output_kind_mismatch",
                    format!(
                        "Output bytes map to {:?}, expected {:?}.",
                        sniffed_kind, expected_kind
                    ),
                ));
            }
        } else {
            if self.policy.block_on_unknown_output_mime {
                alerts.push(DefenseAlert::blocking(
                    "unknown_output_mime",
                    "Output mime could not be detected from bytes.",
                ));
            } else {
                alerts.push(DefenseAlert::warning(
                    "unknown_output_mime",
                    "Output mime could not be detected from bytes.",
                ));
            }
        }

        if let Some(sniffed) = sniffed_mime
            && !compatible_mimes(&declared_mime, &sniffed)
        {
            alerts.push(DefenseAlert::blocking(
                "output_mime_mismatch",
                "Declared output MIME does not match the actual byte format.",
            ));
        }

        alerts
    }

    fn is_allowed_output_mime(&self, expected_kind: FileKind, declared_mime: &str) -> bool {
        let set = match expected_kind {
            FileKind::Image => &self.mime_index.image_allow,
            // AnimatedImage shares the Image whitelist until P1-8 ships a
            // dedicated handler with its own output-MIME policy. The static
            // fallback rebuild produces `image/png`, which already lives in
            // image_allow.
            FileKind::AnimatedImage => &self.mime_index.image_allow,
            FileKind::Gif => &self.mime_index.gif_allow,
            FileKind::Video => &self.mime_index.video_allow,
            FileKind::Audio => &self.mime_index.audio_allow,
            FileKind::Other => &self.mime_index.other_allow,
        };
        set.contains(declared_mime)
    }

    fn apply_dry_run_mode(&self, alerts: &mut [DefenseAlert], stages: &mut [PipelineStageReport]) {
        for value in alerts {
            if value.is_blocking() {
                value.severity = crate::types::AlertSeverity::Warning;
                value.message = format!("{} [dry-run: would block]", value.message);
            }
        }
        for value in stages {
            if value.status == PipelineStageStatus::Blocked {
                value.status = PipelineStageStatus::Warning;
                value.detail = format!("{} [dry-run]", value.detail);
            }
        }
    }

    fn build_quarantine_envelope(
        &self,
        alerts: &[DefenseAlert],
        stages: &[PipelineStageReport],
        original_size: u64,
        output_size: u64,
        sha256: &str,
    ) -> QuarantineEnvelope {
        let reason = alerts
            .iter()
            .find(|value| value.is_blocking())
            .map(|value| value.code.clone())
            .unwrap_or_else(|| "blocked".to_string());
        let mut stage_details = Vec::new();
        for value in stages {
            stage_details.push(value.detail.clone());
        }
        QuarantineEnvelope {
            reason,
            sha256: sha256.to_string(),
            original_size,
            output_size,
            stage_details,
        }
    }
}

/// Summarise a panic payload to a short, byte-safe string.
///
/// Handler panic messages may contain fragments of attacker-controlled input
/// bytes (e.g. when a parser uses `format!("unexpected byte: {:x}", b)` in
/// its own panic). Forwarding those verbatim into `DefenderError::HandlerPanic`
/// would leak input bytes into error-reporting channels and, worse, could be
/// used to smuggle attacker-controlled strings into downstream logs.
///
/// We only keep a short, truncated, ASCII-printable view of the first panic
/// line so operators can tell one panic class apart from another without
/// reflecting adversarial content.
fn extract_panic_summary(payload: &(dyn std::any::Any + Send)) -> String {
    let raw = if let Some(text) = payload.downcast_ref::<&'static str>() {
        *text
    } else if let Some(owned) = payload.downcast_ref::<String>() {
        owned.as_str()
    } else {
        return "panic with non-string payload".to_string();
    };
    let first_line = raw.lines().next().unwrap_or("");
    let mut summary = String::with_capacity(first_line.len().min(80));
    for ch in first_line.chars() {
        if summary.len() >= 80 {
            summary.push('…');
            break;
        }
        if ch.is_ascii_graphic() || ch == ' ' {
            summary.push(ch);
        } else {
            summary.push('?');
        }
    }
    if summary.is_empty() {
        return "empty panic message".to_string();
    }
    summary
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }

    if needle.is_empty() {
        return true;
    }

    let start = 0usize;
    let end = haystack.len() - needle.len();
    for offset in start..=end {
        let window = &haystack[offset..offset + needle.len()];
        if window == needle {
            return true;
        }
    }

    false
}

/// Check the first bytes of the output for well-known executable headers.
///
/// This is a **mandatory** defense layer inside `validate_output_artifact`
/// that cannot be disabled by policy flags. A rebuilt media artifact should
/// never start with an executable magic signature. If one does, either the
/// handler failed to CDR properly (bypass) or a polyglot survived the
/// rebuild. Both cases warrant a blocking alert.
fn detect_executable_magic(output_bytes: &[u8]) -> Option<DefenseAlert> {
    const CHECKS: &[(&[u8], &str)] = &[
        (b"MZ", "pe_in_output"),
        (b"\x7fELF", "elf_in_output"),
        (b"\xFE\xED\xFA\xCE", "macho_in_output"),
        (b"\xCE\xFA\xED\xFE", "macho_in_output"),
        (b"\xFE\xED\xFA\xCF", "macho_in_output"),
        (b"\xCF\xFA\xED\xFE", "macho_in_output"),
        (b"\xCA\xFE\xBA\xBE", "java_class_in_output"),
        (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole_cfb_in_output"),
        (b"dex\n", "dex_in_output"),
        (b"\x00asm", "wasm_in_output"),
        (b"#!/", "script_shebang_in_output"),
        (b"<?php", "php_tag_in_output"),
        (b"@echo off", "batch_in_output"),
        (b"Rar!\x1a\x07", "rar_in_output"),
        (b"7z\xBC\xAF\x27\x1C", "seven_zip_in_output"),
    ];
    for (magic, code) in CHECKS {
        if output_bytes.len() >= magic.len() && &output_bytes[..magic.len()] == *magic {
            return Some(DefenseAlert::blocking(
                *code,
                format!(
                    "Output begins with executable/archive magic `{}`.",
                    code.replace("_in_output", "")
                ),
            ));
        }
    }
    None
}

fn to_lower_set(values: &[String]) -> HashSet<String> {
    let mut set = HashSet::new();
    for value in values {
        set.insert(value.to_ascii_lowercase());
    }
    set
}

fn stage_status_from_alerts(alerts: &[DefenseAlert]) -> PipelineStageStatus {
    let mut has_blocking = false;
    for value in alerts {
        if value.is_blocking() {
            has_blocking = true;
            break;
        }
    }
    if has_blocking {
        return PipelineStageStatus::Blocked;
    }
    // Info-level alerts carry audit information only and must NOT promote a
    // stage to Warning. Only Warning-severity alerts do.
    let mut has_warning = false;
    for value in alerts {
        if value.is_warning() {
            has_warning = true;
            break;
        }
    }
    if has_warning {
        return PipelineStageStatus::Warning;
    }
    PipelineStageStatus::Success
}

fn file_kind_label(kind: FileKind) -> &'static str {
    match kind {
        FileKind::Image => "image",
        FileKind::AnimatedImage => "animated_image",
        FileKind::Gif => "gif",
        FileKind::Video => "video",
        FileKind::Audio => "audio",
        FileKind::Other => "other",
    }
}

fn file_kind_label_optional(kind: Option<FileKind>) -> &'static str {
    match kind {
        Some(value) => file_kind_label(value),
        None => "unknown",
    }
}

fn compatible_kinds(left: FileKind, right: FileKind) -> bool {
    left == right
        || matches!(
            (left, right),
            (FileKind::Image, FileKind::AnimatedImage) | (FileKind::AnimatedImage, FileKind::Image)
        )
}

fn normalized_mime(mime: &str) -> String {
    let mime = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match mime.as_str() {
        "image/jpg" | "image/pjpeg" => "image/jpeg",
        "image/x-png" | "image/apng" => "image/png",
        "image/x-ms-bmp" => "image/bmp",
        "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => "audio/wav",
        "audio/x-flac" => "audio/flac",
        "audio/m4a" | "audio/x-m4a" | "audio/mp4" | "video/mp4" | "video/x-m4v" => {
            "application/mp4"
        }
        "audio/x-aiff" => "audio/aiff",
        "application/ogg" | "audio/opus" => "audio/ogg",
        "video/x-matroska" => "video/matroska",
        _ => return mime,
    }
    .to_string()
}

fn compatible_mimes(left: &str, right: &str) -> bool {
    normalized_mime(left) == normalized_mime(right)
}

fn mime_from_filename(name: &str) -> Option<&'static str> {
    let extension = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    Some(match extension.as_str() {
        "png" | "apng" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "mp4" | "m4a" => "application/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/matroska",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "amr" => "audio/amr",
        "aif" | "aiff" => "audio/aiff",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "7z" => "application/x-7z-compressed",
        "txt" | "csv" => "text/plain",
        "json" => "application/json",
        "xml" => "application/xml",
        _ => return None,
    })
}
