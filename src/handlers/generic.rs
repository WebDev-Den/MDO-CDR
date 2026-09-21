//! Generic handler for `FileKind::Other`.
//!
//! Per the media-only architecture decision, non-media files (documents,
//! archives, executables, unknown formats) are **rejected**, not passed
//! through. The defender cannot perform CDR on formats it does not
//! understand, and silent passthrough would create a false sense of security.
//!
//! The handler is still invoked (rather than short-circuiting in lib.rs)
//! so that:
//!   - The pipeline stages are consistently reported.
//!   - Policy profiles that enable `DecoderFailureMode::QuarantineAsOther`
//!     still produce an auditable `DefendResult` before the verdict blocks
//!     delivery.
//!   - Shannon entropy is logged for forensic value (operators can see
//!     whether the payload was compressed/encrypted).

use crate::{
    DefenderError,
    types::{
        AlertSeverity, DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport,
        PipelineStageStatus,
    },
};

use super::HandlerResult;

#[derive(Debug, Clone)]
pub struct GenericHandler {
    _policy: crate::policy::OtherPolicy,
}

impl GenericHandler {
    pub fn new(policy: crate::policy::OtherPolicy) -> Self {
        Self { _policy: policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        _context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        let entropy = if input_bytes.is_empty() {
            0.0
        } else {
            shannon_entropy(&input_bytes)
        };

        log::warn!(
            "generic handler invoked: size={} entropy={entropy:.3} — blocking (media-only policy)",
            input_bytes.len()
        );

        // We still return a HandlerResult (not Err) so that the pipeline
        // records this as a blocking alert with full stage reporting. The
        // verdict derivation in lib.rs will see the blocking alert and
        // produce DefenseVerdict::Blocked.
        Ok(HandlerResult {
            mime: "application/octet-stream".to_string(),
            output_bytes: input_bytes,
            alerts: vec![DefenseAlert {
                code: "unsupported_file_kind".to_string(),
                message: format!(
                    "Non-media file type is not supported by the defense pipeline. \
                     Entropy: {entropy:.3}. File was not rebuilt and must not be delivered."
                ),
                severity: AlertSeverity::Blocking,
            }],
            stages: vec![PipelineStageReport {
                stage: PipelineStage::OtherProbe,
                status: PipelineStageStatus::Blocked,
                detail: format!("generic handler blocked: entropy={entropy:.3}"),
            }],
        })
    }
}

fn shannon_entropy(input: &[u8]) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for byte in input {
        frequencies[*byte as usize] += 1;
    }

    let length = input.len() as f64;
    let mut entropy = 0.0f64;
    for frequency in frequencies {
        if frequency == 0 {
            continue;
        }
        let probability = frequency as f64 / length;
        entropy -= probability * probability.log2();
    }
    entropy
}
