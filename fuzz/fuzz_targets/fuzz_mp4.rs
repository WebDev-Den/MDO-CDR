#![no_main]

use mdo_cdr::handlers::mp4_native::try_sanitize_mp4;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_mp4(data);
});
