use std::io::Cursor;

use image::{ImageFormat, ImageReader};

use crate::{
    DefenderError,
    policy::{ImageOutputFormat, ImagePolicy},
    types::{
        DefenseAlert, DefenseContext, PipelineStage, PipelineStageReport, PipelineStageStatus,
    },
};

use super::HandlerResult;

#[derive(Debug, Clone)]
pub struct ImageHandler {
    policy: ImagePolicy,
}

impl ImageHandler {
    pub fn new(policy: ImagePolicy) -> Self {
        Self { policy }
    }

    pub fn rebuild(
        &self,
        input_bytes: Vec<u8>,
        _context: DefenseContext,
    ) -> Result<HandlerResult, DefenderError> {
        let mut alerts = Vec::new();
        let mut stages = Vec::new();

        // Decompression-bomb defense: probe dimensions BEFORE decoding.
        //
        // The probe uses ImageReader::into_dimensions() which reads only the
        // file header, not pixel data. If the probe fails we REFUSE to decode,
        // regardless of policy.probe_failure_mode: without a known pixel
        // budget the decoder would have to load the whole image into memory,
        // which is exactly the bomb we are defending against.
        //
        // This intentionally ignores ProbeFailureMode::Warn for bomb
        // defense — Warn is only honoured for soft mismatches between probe
        // and decode dimensions (see below), never as a bypass.
        let (probe_width, probe_height) = self.probe(&input_bytes).map_err(|value| {
            log::warn!("image probe failed — refusing to decode (bomb defense): {value}");
            value
        })?;
        if probe_width == 0 || probe_height == 0 {
            return Err(DefenderError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "image dimensions are zero",
            )));
        }
        let prechecked_pixels = probe_width.saturating_mul(probe_height);
        if prechecked_pixels > self.policy.max_pixels {
            log::warn!(
                "image probe rejected: {prechecked_pixels} pixels exceeds max_pixels {}",
                self.policy.max_pixels
            );
            return Err(DefenderError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "image pixel count exceeds max_pixels: {prechecked_pixels} > {}",
                    self.policy.max_pixels
                ),
            )));
        }
        stages.push(PipelineStageReport {
            stage: PipelineStage::ImageProbe,
            status: PipelineStageStatus::Success,
            detail: format!("image probe succeeded width={probe_width} height={probe_height}"),
        });

        let image = ImageReader::new(Cursor::new(input_bytes))
            .with_guessed_format()?
            .decode()?;
        let decoded_width = image.width() as u64;
        let decoded_height = image.height() as u64;
        if decoded_width == 0 || decoded_height == 0 {
            return Err(DefenderError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decoded image dimensions are zero",
            )));
        }
        let decoded_pixels = decoded_width.saturating_mul(decoded_height);
        if decoded_pixels > self.policy.max_pixels {
            return Err(DefenderError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "decoded image pixel count exceeds max_pixels: {decoded_pixels} > {}",
                    self.policy.max_pixels
                ),
            )));
        }
        if prechecked_pixels != decoded_pixels {
            // A mismatch between the header-declared dimensions and the
            // actual decoded pixel buffer is highly suspicious. If the
            // decoded image is more than 2× larger than the header claimed,
            // this is likely a decompression-bomb variant where the header
            // lies to pass our pre-decode check. Hard-reject.
            if decoded_pixels > prechecked_pixels.saturating_mul(2) {
                log::warn!(
                    "image probe-decode mismatch > 2x: probed={prechecked_pixels} decoded={decoded_pixels} — rejecting"
                );
                return Err(DefenderError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "decoded pixel count {decoded_pixels} exceeds 2× probed {prechecked_pixels}: likely decompression bomb"
                    ),
                )));
            }
            alerts.push(DefenseAlert::warning(
                "image_probe_decode_mismatch",
                format!(
                    "Image dimensions mismatch between probe and decode: probe_pixels={prechecked_pixels}, decode_pixels={decoded_pixels}"
                ),
            ));
        }

        let format = match self.policy.output_format {
            ImageOutputFormat::Png => ImageFormat::Png,
            ImageOutputFormat::Jpeg => ImageFormat::Jpeg,
            ImageOutputFormat::Webp => ImageFormat::WebP,
        };

        let mut output = Vec::new();
        image.write_to(&mut Cursor::new(&mut output), format)?;
        let mime = match self.policy.output_format {
            ImageOutputFormat::Png => "image/png",
            ImageOutputFormat::Jpeg => "image/jpeg",
            ImageOutputFormat::Webp => "image/webp",
        };

        // Audit trail: the re-encode always drops all metadata (EXIF, ICC,
        // XMP, comments) because crate `image` DynamicImage does not carry
        // metadata — only decoded pixel data survives.
        alerts.push(DefenseAlert::info(
            "image_metadata_stripped",
            format!(
                "Image rebuilt as {mime} from decoded pixels ({decoded_width}×{decoded_height}). \
                 All EXIF, ICC, XMP, and comment metadata was discarded."
            ),
        ));

        log::info!(
            "image::rebuild exit: {decoded_width}×{decoded_height} → {mime} output_size={}",
            output.len()
        );

        Ok(HandlerResult {
            mime: mime.to_string(),
            output_bytes: output,
            alerts,
            stages,
        })
    }

    fn probe(&self, input_bytes: &[u8]) -> Result<(u64, u64), DefenderError> {
        let reader = ImageReader::new(Cursor::new(input_bytes)).with_guessed_format()?;
        let (width, height) = reader.into_dimensions()?;
        Ok((width as u64, height as u64))
    }
}
