use std::io::Cursor;

use gif::{ColorOutput, DecodeOptions, DisposalMethod, Encoder, Frame, Repeat};

use crate::{
    DefenderError,
    policy::GifPolicy,
    types::{
        AlertSeverity, DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport,
        PipelineStageStatus,
    },
};

use super::HandlerResult;

/// Maximum cumulative frame delay in centiseconds (GIF delay units).
/// 6000cs = 60 seconds. Prevents rapid-fire animation DoS where thousands
/// of 0-delay frames force the renderer to loop at maximum speed.
const MAX_TOTAL_DELAY_CS: u32 = 60 * 100;

/// Minimum per-frame delay in centiseconds. Frames with delay < 2cs (20ms)
/// are clamped to 2cs to prevent rendering DoS. Many browsers do the same
/// internally (Firefox/Chrome clamp to 10cs for 0-delay).
const MIN_FRAME_DELAY_CS: u16 = 2;

#[derive(Debug, Clone)]
pub struct GifHandler {
    policy: GifPolicy,
}

impl GifHandler {
    pub fn new(policy: GifPolicy) -> Self {
        Self { policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        let mut alerts = Vec::new();
        let mut stages = Vec::new();

        log::debug!("gif::rebuild entry: size={}", input_bytes.len());

        // Bomb defense: probe MUST succeed. If the GIF header is malformed
        // or the first frame can't be decoded, we refuse to proceed —
        // regardless of probe_failure_mode. Without a successful probe we
        // cannot bound the work the decoder will do.
        self.probe(&input_bytes).map_err(|value| {
            log::warn!("gif probe failed — refusing to decode (bomb defense): {value}");
            value
        })?;
        stages.push(PipelineStageReport {
            stage: PipelineStage::GifProbe,
            status: PipelineStageStatus::Success,
            detail: "gif probe succeeded".to_string(),
        });

        let mut options = DecodeOptions::new();
        options.set_color_output(ColorOutput::RGBA);
        let mut decoder = options
            .read_info(Cursor::new(input_bytes))
            .map_err(|value| DefenderError::Gif(value.to_string()))?;

        let mut encoded = Vec::new();
        let mut encoder = Encoder::new(&mut encoded, decoder.width(), decoder.height(), &[])
            .map_err(|value| DefenderError::Gif(value.to_string()))?;
        encoder
            .set_repeat(Repeat::Infinite)
            .map_err(|value| DefenderError::Gif(value.to_string()))?;

        let mut frame_count = 0usize;
        let mut total_pixels = 0u64;
        let mut total_delay_cs = 0u32;
        let mut delay_clamped_count = 0u32;
        let max_total_pixels =
            (self.policy.max_frames as u64).saturating_mul(self.policy.max_pixels_per_frame);

        while let Some(frame) = decoder
            .read_next_frame()
            .map_err(|value| DefenderError::Gif(value.to_string()))?
        {
            frame_count += 1;
            // Cancellation + timeout checkpoint.
            context.check_limits()?;
            if frame_count > self.policy.max_frames {
                log::warn!(
                    "gif rejected: frame count {} exceeds max_frames {}",
                    frame_count,
                    self.policy.max_frames
                );
                return Err(DefenderError::Gif(format!(
                    "gif frame count exceeds max_frames: {frame_count} > {}",
                    self.policy.max_frames
                )));
            }

            let pixels = frame.width as u64 * frame.height as u64;
            if pixels > self.policy.max_pixels_per_frame {
                return Err(DefenderError::Gif(format!(
                    "gif frame pixel count exceeds max_pixels_per_frame: {pixels} > {}",
                    self.policy.max_pixels_per_frame
                )));
            }
            total_pixels = total_pixels.saturating_add(pixels);
            if total_pixels > max_total_pixels {
                return Err(DefenderError::Gif(format!(
                    "gif total pixels across frames exceed budget: {total_pixels} > {max_total_pixels}"
                )));
            }

            // Delay budget: clamp short delays to prevent render-loop DoS,
            // and cap cumulative animation duration.
            let mut delay = frame.delay;
            if delay < MIN_FRAME_DELAY_CS {
                delay = MIN_FRAME_DELAY_CS;
                delay_clamped_count += 1;
            }
            total_delay_cs = total_delay_cs.saturating_add(delay as u32);

            let mut rgba = frame.buffer.to_vec();
            let mut output_frame = Frame::from_rgba_speed(frame.width, frame.height, &mut rgba, 10);
            output_frame.delay = delay;
            output_frame.dispose = match frame.dispose {
                DisposalMethod::Any => DisposalMethod::Any,
                DisposalMethod::Keep => DisposalMethod::Keep,
                DisposalMethod::Background => DisposalMethod::Background,
                DisposalMethod::Previous => DisposalMethod::Previous,
            };
            output_frame.transparent = frame.transparent;
            output_frame.top = frame.top;
            output_frame.left = frame.left;

            encoder
                .write_frame(&output_frame)
                .map_err(|value| DefenderError::Gif(value.to_string()))?;
        }
        if frame_count == 0 {
            return Err(DefenderError::Gif(
                "gif has no decodable frames".to_string(),
            ));
        }
        drop(encoder);

        // Audit trail: always report what the rebuild did.
        alerts.push(DefenseAlert {
            code: "gif_metadata_stripped".to_string(),
            message: format!(
                "GIF rebuilt from {frame_count} decoded frame(s). All comment and application \
                 extension blocks were dropped during re-encode."
            ),
            severity: AlertSeverity::Info,
        });
        if delay_clamped_count > 0 {
            alerts.push(DefenseAlert {
                code: "gif_delay_clamped".to_string(),
                message: format!(
                    "{delay_clamped_count} frame(s) had delay < {MIN_FRAME_DELAY_CS}cs and were \
                     clamped to {MIN_FRAME_DELAY_CS}cs to prevent render-loop DoS."
                ),
                severity: AlertSeverity::Warning,
            });
        }
        if total_delay_cs > MAX_TOTAL_DELAY_CS {
            alerts.push(DefenseAlert {
                code: "gif_excessive_duration".to_string(),
                message: format!(
                    "GIF total animation duration {total_delay_cs}cs exceeds cap {MAX_TOTAL_DELAY_CS}cs."
                ),
                severity: AlertSeverity::Warning,
            });
        }

        log::info!(
            "gif::rebuild exit: frames={frame_count} total_pixels={total_pixels} \
             total_delay_cs={total_delay_cs} delay_clamped={delay_clamped_count} output_size={}",
            encoded.len()
        );

        Ok(HandlerResult {
            mime: "image/gif".to_string(),
            output_bytes: encoded,
            alerts,
            stages,
        })
    }

    fn probe(&self, input_bytes: &[u8]) -> Result<(), DefenderError> {
        let mut options = DecodeOptions::new();
        options.set_color_output(ColorOutput::RGBA);
        let mut decoder = options
            .read_info(Cursor::new(input_bytes.to_vec()))
            .map_err(|value| DefenderError::Gif(value.to_string()))?;
        let next = decoder.read_next_frame();
        match next {
            Ok(_) => Ok(()),
            Err(value) => Err(DefenderError::Gif(value.to_string())),
        }
    }
}
