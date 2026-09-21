#[derive(Debug, thiserror::Error)]
pub enum DefenderError {
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("Image rebuild failed: {0}")]
    Image(#[from] image::ImageError),
    #[error("GIF rebuild failed: {0}")]
    Gif(String),
    #[error("Video rebuild failed: {0}")]
    Video(String),
    #[error("Audio rebuild failed: {0}")]
    Audio(String),
    #[error("Blocked extension: {extension}")]
    BlockedExtension { extension: String },
    #[error("File too large. Limit: {limit} bytes, actual: {actual} bytes")]
    FileTooLarge { limit: u64, actual: u64 },
    #[error("Output file too large. Limit: {limit} bytes, actual: {actual} bytes")]
    OutputTooLarge { limit: u64, actual: u64 },
    #[error("Output expansion ratio too high. Limit: {limit:.3}, actual: {actual:.3}")]
    OutputExpansionTooHigh { limit: f64, actual: f64 },
    #[error("File type mismatch between extension and content")]
    FileTypeMismatch,
    #[error("Handler panicked while rebuilding {kind}: {message}")]
    HandlerPanic { kind: String, message: String },
    #[error("Animated image rebuild rejected: {0}")]
    AnimatedImage(String),
    #[error("Defense cancelled by caller")]
    Cancelled,
    #[error("Handler exceeded time limit")]
    Timeout,
}
