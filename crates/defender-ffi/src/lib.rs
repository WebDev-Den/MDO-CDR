use prost::Message;

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Verdict {
    Clean = 0,
    Suspicious = 1,
    Blocked = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum FileKind {
    Image = 0,
    Gif = 1,
    Video = 2,
    Audio = 3,
    Other = 4,
    AnimatedImage = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Stage {
    PreScan = 0,
    ImageProbe = 1,
    GifProbe = 2,
    VideoProbe = 3,
    AudioProbe = 4,
    OtherProbe = 5,
    Detect = 6,
    Rebuild = 7,
    SignatureScan = 8,
    OutputValidation = 9,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum StageStatus {
    Success = 0,
    Warning = 1,
    Blocked = 2,
}

#[derive(Clone, PartialEq, Message)]
pub struct Alert {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(bool, tag = "3")]
    pub blocking: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct PipelineStage {
    #[prost(enumeration = "Stage", tag = "1")]
    pub stage: i32,
    #[prost(enumeration = "StageStatus", tag = "2")]
    pub status: i32,
    #[prost(string, tag = "3")]
    pub detail: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Metadata {
    #[prost(enumeration = "Verdict", tag = "1")]
    pub verdict: i32,
    #[prost(enumeration = "FileKind", tag = "2")]
    pub file_kind: i32,
    #[prost(string, tag = "3")]
    pub mime: String,
    #[prost(uint64, tag = "4")]
    pub original_size: u64,
    #[prost(uint64, tag = "5")]
    pub output_size: u64,
    #[prost(string, tag = "6")]
    pub sha256: String,
    #[prost(message, repeated, tag = "7")]
    pub alerts: Vec<Alert>,
    #[prost(message, repeated, tag = "8")]
    pub stages: Vec<PipelineStage>,
}

#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct MetadataV0Compat {
    #[prost(int32, tag = "1")]
    pub verdict: i32,
    #[prost(int32, tag = "2")]
    pub file_kind: i32,
    #[prost(string, tag = "3")]
    pub mime: String,
    #[prost(uint64, tag = "4")]
    pub original_size: u64,
    #[prost(uint64, tag = "5")]
    pub output_size: u64,
    #[prost(string, tag = "6")]
    pub sha256: String,
    #[prost(message, repeated, tag = "7")]
    pub alerts: Vec<Alert>,
    #[prost(message, repeated, tag = "8")]
    pub stages: Vec<PipelineStageV0Compat>,
}

#[cfg(test)]
#[derive(Clone, PartialEq, Message)]
struct PipelineStageV0Compat {
    #[prost(int32, tag = "1")]
    pub stage: i32,
    #[prost(int32, tag = "2")]
    pub status: i32,
    #[prost(string, tag = "3")]
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::{FileKind, Metadata, MetadataV0Compat, Stage, StageStatus, Verdict};

    #[test]
    fn decodes_v0_payload_with_int_fields() {
        let old = MetadataV0Compat {
            verdict: Verdict::Blocked as i32,
            file_kind: FileKind::Audio as i32,
            mime: "audio/mpeg".to_string(),
            original_size: 10,
            output_size: 20,
            sha256: "abc".to_string(),
            alerts: vec![],
            stages: vec![super::PipelineStageV0Compat {
                stage: Stage::AudioProbe as i32,
                status: StageStatus::Warning as i32,
                detail: "compat".to_string(),
            }],
        };
        let bytes = old.encode_to_vec();
        let decoded = Metadata::decode(bytes.as_slice()).expect("decode should succeed");
        assert_eq!(decoded.verdict, Verdict::Blocked as i32);
        assert_eq!(decoded.file_kind, FileKind::Audio as i32);
        assert_eq!(decoded.stages.len(), 1);
    }
}
