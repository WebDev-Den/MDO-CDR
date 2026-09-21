use std::ffi::{CStr, c_char};

use prost::Message;

use crate::{
    DefendResult, DefenseVerdict, FileDefender, client::ClientDefender, policy::DefensePolicy,
};

pub const FFI_STATUS_OK: i32 = 0;
pub const FFI_STATUS_ERROR: i32 = 1;

pub const FFI_VERDICT_ERROR: i32 = -1;
pub const FFI_VERDICT_CLEAN: i32 = 0;
pub const FFI_VERDICT_SUSPICIOUS: i32 = 1;
pub const FFI_VERDICT_BLOCKED: i32 = 2;

pub const FFI_FILE_KIND_IMAGE: i32 = 0;
pub const FFI_FILE_KIND_GIF: i32 = 1;
pub const FFI_FILE_KIND_VIDEO: i32 = 2;
pub const FFI_FILE_KIND_AUDIO: i32 = 3;
pub const FFI_FILE_KIND_OTHER: i32 = 4;
pub const FFI_FILE_KIND_ANIMATED_IMAGE: i32 = 5;
pub const FFI_STAGE_PRE_SCAN: i32 = 0;
pub const FFI_STAGE_IMAGE_PROBE: i32 = 1;
pub const FFI_STAGE_GIF_PROBE: i32 = 2;
pub const FFI_STAGE_VIDEO_PROBE: i32 = 3;
pub const FFI_STAGE_AUDIO_PROBE: i32 = 4;
pub const FFI_STAGE_OTHER_PROBE: i32 = 5;
pub const FFI_STAGE_DETECT: i32 = 6;
pub const FFI_STAGE_REBUILD: i32 = 7;
pub const FFI_STAGE_SIGNATURE_SCAN: i32 = 8;
pub const FFI_STAGE_OUTPUT_VALIDATION: i32 = 9;
pub const FFI_STAGE_STATUS_SUCCESS: i32 = 0;
pub const FFI_STAGE_STATUS_WARNING: i32 = 1;
pub const FFI_STAGE_STATUS_BLOCKED: i32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum FfiVerdictEnum {
    Clean = FFI_VERDICT_CLEAN,
    Suspicious = FFI_VERDICT_SUSPICIOUS,
    Blocked = FFI_VERDICT_BLOCKED,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum FfiFileKindEnum {
    Image = FFI_FILE_KIND_IMAGE,
    Gif = FFI_FILE_KIND_GIF,
    Video = FFI_FILE_KIND_VIDEO,
    Audio = FFI_FILE_KIND_AUDIO,
    Other = FFI_FILE_KIND_OTHER,
    AnimatedImage = FFI_FILE_KIND_ANIMATED_IMAGE,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum FfiStageEnum {
    PreScan = FFI_STAGE_PRE_SCAN,
    ImageProbe = FFI_STAGE_IMAGE_PROBE,
    GifProbe = FFI_STAGE_GIF_PROBE,
    VideoProbe = FFI_STAGE_VIDEO_PROBE,
    AudioProbe = FFI_STAGE_AUDIO_PROBE,
    OtherProbe = FFI_STAGE_OTHER_PROBE,
    Detect = FFI_STAGE_DETECT,
    Rebuild = FFI_STAGE_REBUILD,
    SignatureScan = FFI_STAGE_SIGNATURE_SCAN,
    OutputValidation = FFI_STAGE_OUTPUT_VALIDATION,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum FfiStageStatusEnum {
    Success = FFI_STAGE_STATUS_SUCCESS,
    Warning = FFI_STAGE_STATUS_WARNING,
    Blocked = FFI_STAGE_STATUS_BLOCKED,
}

#[derive(Clone, PartialEq, Message)]
pub struct FfiAlertProto {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(bool, tag = "3")]
    pub blocking: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct FfiPipelineStageProto {
    #[prost(enumeration = "FfiStageEnum", tag = "1")]
    pub stage: i32,
    #[prost(enumeration = "FfiStageStatusEnum", tag = "2")]
    pub status: i32,
    #[prost(string, tag = "3")]
    pub detail: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct FfiMetadataProto {
    #[prost(enumeration = "FfiVerdictEnum", tag = "1")]
    pub verdict: i32,
    #[prost(enumeration = "FfiFileKindEnum", tag = "2")]
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
    pub alerts: Vec<FfiAlertProto>,
    #[prost(message, repeated, tag = "8")]
    pub stages: Vec<FfiPipelineStageProto>,
}

#[derive(Clone, PartialEq, Message)]
pub struct FfiErrorProto {
    #[prost(string, tag = "1")]
    pub message: String,
}

#[repr(C)]
pub struct FfiDefendResult {
    pub status_code: i32,
    pub verdict: i32,
    pub output_ptr: *mut u8,
    pub output_len: usize,
    pub output_cap: usize,
    pub metadata_proto_ptr: *mut u8,
    pub metadata_proto_len: usize,
    pub metadata_proto_cap: usize,
    pub error_proto_ptr: *mut u8,
    pub error_proto_len: usize,
    pub error_proto_cap: usize,
}

impl FfiDefendResult {
    fn success(result: DefendResult) -> Self {
        // `diagnostics` is not yet part of the FFI wire format — consumers
        // that want per-call metrics should read them through the native
        // Rust API. Adding them to the protobuf requires a new optional
        // field and a coordinated consumer rollout.
        let DefendResult {
            verdict,
            alerts,
            stages,
            artifact,
            diagnostics: _,
        } = result;
        let crate::DefendedArtifact {
            file_kind,
            mime,
            original_size,
            output_size,
            sha256,
            output_bytes,
        } = artifact;

        let mut alerts_proto = Vec::new();
        for alert in alerts {
            // FFI wire format keeps `blocking: bool` for backward
            // compatibility. Info and Warning severities both map to
            // blocking=false; only Blocking severity maps to true.
            let is_blocking = alert.is_blocking();
            let crate::DefenseAlert {
                code,
                message,
                severity: _,
            } = alert;
            alerts_proto.push(FfiAlertProto {
                code,
                message,
                blocking: is_blocking,
            });
        }
        let mut stages_proto = Vec::new();
        for crate::PipelineStageReport {
            stage,
            status,
            detail,
        } in stages
        {
            stages_proto.push(FfiPipelineStageProto {
                stage: stage_code(stage),
                status: stage_status_code(status),
                detail,
            });
        }

        let metadata_proto = FfiMetadataProto {
            verdict: verdict_code(verdict),
            file_kind: file_kind_code(file_kind),
            mime,
            original_size,
            output_size,
            sha256,
            alerts: alerts_proto,
            stages: stages_proto,
        }
        .encode_to_vec();

        let (output_ptr, output_len, output_cap) = if verdict == DefenseVerdict::Clean {
            vec_into_raw_parts(output_bytes)
        } else {
            (std::ptr::null_mut(), 0, 0)
        };
        let (metadata_proto_ptr, metadata_proto_len, metadata_proto_cap) =
            vec_into_raw_parts(metadata_proto);

        Self {
            status_code: FFI_STATUS_OK,
            verdict: verdict_code(verdict),
            output_ptr,
            output_len,
            output_cap,
            metadata_proto_ptr,
            metadata_proto_len,
            metadata_proto_cap,
            error_proto_ptr: std::ptr::null_mut(),
            error_proto_len: 0,
            error_proto_cap: 0,
        }
    }

    fn error(message: String) -> Self {
        let error_proto = FfiErrorProto { message }.encode_to_vec();
        let (error_proto_ptr, error_proto_len, error_proto_cap) = vec_into_raw_parts(error_proto);

        Self {
            status_code: FFI_STATUS_ERROR,
            verdict: FFI_VERDICT_ERROR,
            output_ptr: std::ptr::null_mut(),
            output_len: 0,
            output_cap: 0,
            metadata_proto_ptr: std::ptr::null_mut(),
            metadata_proto_len: 0,
            metadata_proto_cap: 0,
            error_proto_ptr,
            error_proto_len,
            error_proto_cap,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_ffi_status_ok() -> i32 {
    FFI_STATUS_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_ffi_status_error() -> i32 {
    FFI_STATUS_ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_verdict_clean() -> i32 {
    FFI_VERDICT_CLEAN
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_verdict_suspicious() -> i32 {
    FFI_VERDICT_SUSPICIOUS
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_verdict_blocked() -> i32 {
    FFI_VERDICT_BLOCKED
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_image() -> i32 {
    FFI_FILE_KIND_IMAGE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_gif() -> i32 {
    FFI_FILE_KIND_GIF
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_video() -> i32 {
    FFI_FILE_KIND_VIDEO
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_audio() -> i32 {
    FFI_FILE_KIND_AUDIO
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_other() -> i32 {
    FFI_FILE_KIND_OTHER
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_file_kind_animated_image() -> i32 {
    FFI_FILE_KIND_ANIMATED_IMAGE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_detect() -> i32 {
    FFI_STAGE_DETECT
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_pre_scan() -> i32 {
    FFI_STAGE_PRE_SCAN
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_image_probe() -> i32 {
    FFI_STAGE_IMAGE_PROBE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_gif_probe() -> i32 {
    FFI_STAGE_GIF_PROBE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_video_probe() -> i32 {
    FFI_STAGE_VIDEO_PROBE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_audio_probe() -> i32 {
    FFI_STAGE_AUDIO_PROBE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_other_probe() -> i32 {
    FFI_STAGE_OTHER_PROBE
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_rebuild() -> i32 {
    FFI_STAGE_REBUILD
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_signature_scan() -> i32 {
    FFI_STAGE_SIGNATURE_SCAN
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_output_validation() -> i32 {
    FFI_STAGE_OUTPUT_VALIDATION
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_status_success() -> i32 {
    FFI_STAGE_STATUS_SUCCESS
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_status_warning() -> i32 {
    FFI_STAGE_STATUS_WARNING
}

#[unsafe(no_mangle)]
pub extern "C" fn file_defender_stage_status_blocked() -> i32 {
    FFI_STAGE_STATUS_BLOCKED
}

#[unsafe(no_mangle)]
/// # Safety
/// `input_ptr` must point to a valid byte buffer of length `input_len` for the duration
/// of this call. `file_name_ptr` and `tenant_id_ptr` must be null or valid UTF-8 C strings.
pub unsafe extern "C" fn file_defender_client_defend_default(
    input_ptr: *const u8,
    input_len: usize,
    file_name_ptr: *const c_char,
    tenant_id_ptr: *const c_char,
) -> FfiDefendResult {
    let execution = std::panic::catch_unwind(|| {
        let input_bytes = read_input_bytes(input_ptr, input_len)?;
        let file_name = c_str_to_optional_string(file_name_ptr)?;
        let tenant_id = c_str_to_optional_string(tenant_id_ptr)?;

        let core = FileDefender::new(DefensePolicy::default());
        let client = ClientDefender::new(core);
        let result = client
            .defend_upload(input_bytes, file_name, tenant_id)
            .map_err(|value| value.to_string())?;

        Ok::<FfiDefendResult, String>(FfiDefendResult::success(result))
    });

    match execution {
        Ok(result) => match result {
            Ok(value) => value,
            Err(message) => FfiDefendResult::error(message),
        },
        Err(_) => FfiDefendResult::error("panic while executing file defense".to_string()),
    }
}

#[unsafe(no_mangle)]
/// # Safety
/// `ptr`, `len`, and `cap` must come from a buffer previously returned by this library
/// through `FfiDefendResult` fields and must not be freed more than once.
pub unsafe extern "C" fn file_defender_free_buffer(ptr: *mut u8, len: usize, cap: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = unsafe { Vec::from_raw_parts(ptr, len, cap) };
}

fn read_input_bytes(input_ptr: *const u8, input_len: usize) -> Result<Vec<u8>, String> {
    if input_len == 0 {
        return Ok(Vec::new());
    }
    if input_ptr.is_null() {
        return Err("input_ptr was null while input_len was non-zero".to_string());
    }
    let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
    Ok(input.to_vec())
}

fn c_str_to_optional_string(ptr: *const c_char) -> Result<Option<String>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    let value = unsafe { CStr::from_ptr(ptr) };
    match value.to_str() {
        Ok(text) => {
            if text.is_empty() {
                return Ok(None);
            }
            Ok(Some(text.to_string()))
        }
        Err(_) => Err("invalid UTF-8 in C string argument".to_string()),
    }
}

fn verdict_code(verdict: DefenseVerdict) -> i32 {
    match verdict {
        DefenseVerdict::Clean => FFI_VERDICT_CLEAN,
        DefenseVerdict::Suspicious => FFI_VERDICT_SUSPICIOUS,
        DefenseVerdict::Blocked => FFI_VERDICT_BLOCKED,
    }
}

fn file_kind_code(file_kind: crate::FileKind) -> i32 {
    match file_kind {
        crate::FileKind::Image => FFI_FILE_KIND_IMAGE,
        crate::FileKind::AnimatedImage => FFI_FILE_KIND_ANIMATED_IMAGE,
        crate::FileKind::Gif => FFI_FILE_KIND_GIF,
        crate::FileKind::Video => FFI_FILE_KIND_VIDEO,
        crate::FileKind::Audio => FFI_FILE_KIND_AUDIO,
        crate::FileKind::Other => FFI_FILE_KIND_OTHER,
    }
}

fn stage_code(stage: crate::PipelineStage) -> i32 {
    match stage {
        crate::PipelineStage::PreScan => FFI_STAGE_PRE_SCAN,
        crate::PipelineStage::ImageProbe => FFI_STAGE_IMAGE_PROBE,
        crate::PipelineStage::GifProbe => FFI_STAGE_GIF_PROBE,
        crate::PipelineStage::VideoProbe => FFI_STAGE_VIDEO_PROBE,
        crate::PipelineStage::AudioProbe => FFI_STAGE_AUDIO_PROBE,
        crate::PipelineStage::OtherProbe => FFI_STAGE_OTHER_PROBE,
        crate::PipelineStage::Detect => FFI_STAGE_DETECT,
        crate::PipelineStage::Rebuild => FFI_STAGE_REBUILD,
        crate::PipelineStage::SignatureScan => FFI_STAGE_SIGNATURE_SCAN,
        crate::PipelineStage::OutputValidation => FFI_STAGE_OUTPUT_VALIDATION,
    }
}

fn stage_status_code(status: crate::PipelineStageStatus) -> i32 {
    match status {
        crate::PipelineStageStatus::Success => FFI_STAGE_STATUS_SUCCESS,
        crate::PipelineStageStatus::Warning => FFI_STAGE_STATUS_WARNING,
        crate::PipelineStageStatus::Blocked => FFI_STAGE_STATUS_BLOCKED,
    }
}

fn vec_into_raw_parts(mut value: Vec<u8>) -> (*mut u8, usize, usize) {
    if value.is_empty() {
        return (std::ptr::null_mut(), 0, 0);
    }
    let ptr = value.as_mut_ptr();
    let len = value.len();
    let cap = value.capacity();
    std::mem::forget(value);
    (ptr, len, cap)
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use prost::Message;

    use super::{
        FFI_STATUS_OK, FfiMetadataProto, file_defender_client_defend_default,
        file_defender_free_buffer,
    };

    #[test]
    fn ffi_roundtrip_success() {
        let mut input = Vec::new();
        image::DynamicImage::new_rgb8(2, 2)
            .write_to(
                &mut std::io::Cursor::new(&mut input),
                image::ImageFormat::Png,
            )
            .expect("encode PNG fixture");
        let file_name = CString::new("picture.png");
        let tenant = CString::new("tenant-a");

        let file_name = match file_name {
            Ok(value) => value,
            Err(_) => panic!("file_name c string creation failed"),
        };
        let tenant = match tenant {
            Ok(value) => value,
            Err(_) => panic!("tenant c string creation failed"),
        };

        let result = unsafe {
            file_defender_client_defend_default(
                input.as_ptr(),
                input.len(),
                file_name.as_ptr(),
                tenant.as_ptr(),
            )
        };

        assert_eq!(result.status_code, FFI_STATUS_OK);
        assert!(!result.output_ptr.is_null());
        assert!(result.output_len > 0);
        assert!(!result.metadata_proto_ptr.is_null());
        assert!(result.metadata_proto_len > 0);

        let metadata = unsafe {
            std::slice::from_raw_parts(result.metadata_proto_ptr, result.metadata_proto_len)
        };
        let decoded = FfiMetadataProto::decode(metadata);
        let decoded = match decoded {
            Ok(value) => value,
            Err(_) => panic!("protobuf decode failed"),
        };
        assert!(!decoded.mime.is_empty());
        assert!(!decoded.stages.is_empty());

        unsafe {
            file_defender_free_buffer(result.output_ptr, result.output_len, result.output_cap);
            file_defender_free_buffer(
                result.metadata_proto_ptr,
                result.metadata_proto_len,
                result.metadata_proto_cap,
            );
            file_defender_free_buffer(
                result.error_proto_ptr,
                result.error_proto_len,
                result.error_proto_cap,
            );
        }
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyStage {
        #[prost(int32, tag = "1")]
        stage: i32,
        #[prost(int32, tag = "2")]
        status: i32,
        #[prost(string, tag = "3")]
        detail: String,
    }

    #[derive(Clone, PartialEq, Message)]
    struct LegacyMetadata {
        #[prost(int32, tag = "1")]
        verdict: i32,
        #[prost(int32, tag = "2")]
        file_kind: i32,
        #[prost(string, tag = "3")]
        mime: String,
        #[prost(uint64, tag = "4")]
        original_size: u64,
        #[prost(uint64, tag = "5")]
        output_size: u64,
        #[prost(string, tag = "6")]
        sha256: String,
        #[prost(message, repeated, tag = "7")]
        alerts: Vec<super::FfiAlertProto>,
        #[prost(message, repeated, tag = "8")]
        stages: Vec<LegacyStage>,
    }

    #[test]
    fn metadata_decodes_legacy_int_wire_format() {
        let legacy = LegacyMetadata {
            verdict: super::FFI_VERDICT_BLOCKED,
            file_kind: super::FFI_FILE_KIND_AUDIO,
            mime: "audio/mpeg".to_string(),
            original_size: 7,
            output_size: 9,
            sha256: "hash".to_string(),
            alerts: vec![],
            stages: vec![LegacyStage {
                stage: super::FFI_STAGE_AUDIO_PROBE,
                status: super::FFI_STAGE_STATUS_WARNING,
                detail: "legacy".to_string(),
            }],
        };
        let bytes = legacy.encode_to_vec();
        let decoded = super::FfiMetadataProto::decode(bytes.as_slice()).expect("decode");
        assert_eq!(decoded.verdict, super::FFI_VERDICT_BLOCKED);
        assert_eq!(decoded.file_kind, super::FFI_FILE_KIND_AUDIO);
        assert_eq!(decoded.stages.len(), 1);
    }

    #[test]
    fn ffi_defensively_drops_nonclean_payloads() {
        for verdict in [
            crate::DefenseVerdict::Blocked,
            crate::DefenseVerdict::Suspicious,
        ] {
            let result = super::FfiDefendResult::success(crate::DefendResult {
                verdict,
                alerts: vec![],
                stages: vec![],
                artifact: crate::DefendedArtifact {
                    file_kind: crate::FileKind::Other,
                    mime: "application/octet-stream".into(),
                    original_size: 4,
                    output_size: 4,
                    sha256: "candidate-digest".into(),
                    output_bytes: b"data".to_vec(),
                },
                diagnostics: Default::default(),
            });
            assert!(result.output_ptr.is_null());
            assert_eq!((result.output_len, result.output_cap), (0, 0));
            unsafe {
                super::file_defender_free_buffer(
                    result.metadata_proto_ptr,
                    result.metadata_proto_len,
                    result.metadata_proto_cap,
                );
            }
        }
    }
}
