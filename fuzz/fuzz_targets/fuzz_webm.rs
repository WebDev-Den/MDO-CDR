#![no_main]

use file_defender::handlers::webm_native::try_sanitize_webm;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_webm(data);
});
