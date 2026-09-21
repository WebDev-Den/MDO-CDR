#![no_main]

use mdo_cdr::{DefenseContext, policy::AnimatedImagePolicy};
use mdo_cdr::handlers::animated_image::AnimatedImageHandler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
    let _ = handler.rebuild(data.to_vec(), DefenseContext::default());
});
