#![no_main]

use file_defender::{DefenseContext, policy::AnimatedImagePolicy};
use file_defender::handlers::animated_image::AnimatedImageHandler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let handler = AnimatedImageHandler::new(AnimatedImagePolicy::default());
    let _ = handler.rebuild(data.to_vec(), DefenseContext::default());
});
