#![no_main]
//! Untrusted-input surface #2: raw kernel event records (comm / path / argv
//! bytes, arbitrary event types). Contract: decoding never panics.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = talus_process_monitor::monitor::decode_event_bytes(data);
});
