#![no_main]

use mdo_cdr::handlers::webm_native::try_sanitize_webm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_webm(data);
});
