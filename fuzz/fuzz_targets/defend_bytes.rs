#![no_main]

use mdo_cdr::{DefenseContext, FileDefender, policy::DefensePolicy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let defender = FileDefender::new(DefensePolicy::default());

    // Exercise every handler path by cycling through file extensions that
    // trigger each native sanitizer. The fuzzer mutates `data` to explore
    // malformed inputs; we vary the filename so classification routes them
    // to different handlers.
    let extensions = &[
        "fuzz.png",  // Image (static)
        "fuzz.apng", // AnimatedImage (APNG chunk walker)
        "fuzz.gif",  // GIF (frame decoder)
        "fuzz.mp3",  // Audio native MP3 (ID3 strip)
        "fuzz.wav",  // Audio native WAV (RIFF walker)
        "fuzz.flac", // Audio native FLAC (metadata strip)
        "fuzz.ogg",  // Audio native OGG (page walker)
        "fuzz.m4a",  // Audio native MP4 (atom walker)
        "fuzz.mp4",  // Video native MP4 (atom walker)
        "fuzz.webm", // Video native WebM (EBML walker)
        "fuzz.bin",  // Other (blocked by media-only policy)
    ];

    for ext in extensions {
        let _ = defender.defend_bytes(
            data.to_vec(),
            Some(ext.to_string()),
            DefenseContext::default(),
        );
    }
});
