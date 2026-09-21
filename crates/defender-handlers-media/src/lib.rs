#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandlerKind {
    Image,
    Gif,
    Video,
    Audio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDecision {
    Success,
    Warning,
    Blocked,
}

pub trait MediaHandler {
    fn kind(&self) -> HandlerKind;
    fn probe(&self, input: &[u8]) -> ProbeDecision;
}
