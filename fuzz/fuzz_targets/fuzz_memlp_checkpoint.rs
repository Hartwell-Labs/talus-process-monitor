#![no_main]
//! Untrusted-input surface #1: MeMLP checkpoint files (JSON on disk).
//! Contract: malformed input is an `Err`, never a panic; an accepted model can
//! be used for inference and one training step without panicking.
use libfuzzer_sys::fuzz_target;
use talus_process_monitor::memlp::MeMLP;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut model) = MeMLP::from_json_bytes(data, "fuzz") {
        let features = [0.5f32; 10];
        let _ = model.assess(&features);
        let _ = model.train_observation(&features, 0.03);
    }
});
