#![no_main]

use file_defender::handlers::mp4_native::try_sanitize_mp4;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_mp4(data);
});
