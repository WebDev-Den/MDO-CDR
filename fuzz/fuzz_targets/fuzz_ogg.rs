#![no_main]

use file_defender::handlers::ogg_native::try_sanitize_ogg;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = try_sanitize_ogg(data);
});
