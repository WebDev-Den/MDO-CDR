pub mod animated_image;
pub mod audio;
pub mod audio_native;
pub mod generic;
pub mod gif;
pub mod image;
pub mod mp4_native;
pub mod ogg_native;
pub mod video;
pub mod webm_native;

use crate::types::{DefenseAlert, PipelineStageReport};

#[derive(Debug, Clone)]
pub struct HandlerResult {
    pub mime: String,
    pub output_bytes: Vec<u8>,
    pub alerts: Vec<DefenseAlert>,
    pub stages: Vec<PipelineStageReport>,
}
