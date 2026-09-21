#![no_main]

use mdo_cdr::handlers::audio_native::{try_sanitize_mp3, try_sanitize_wav, try_sanitize_flac};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_mp3(data);
    let _ = try_sanitize_wav(data);
    let _ = try_sanitize_flac(data);
});
