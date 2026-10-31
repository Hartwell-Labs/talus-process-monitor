//! Integration test for the artifact download-verification pipeline.
use talus_process_monitor::license::{LicenseCache, activate_license, download_artifact};

#[test]
#[ignore]
fn test_download_artifact_full() {
    // Load cache
    let cache = LicenseCache::load().unwrap()
        .expect("no license cache — run `talus license activate` first");
    eprintln!("License: {} tier: {} machine: {:?}",
        cache.payload.license_id, cache.payload.tier,
        cache.payload.machine_id);

    // Ensure activated on server
    if cache.activation_token.is_none() {
        match activate_license(&cache.key) {
            Ok(c) => eprintln!("Activated: token={:?}", c.activation_token.is_some()),
            Err(e) => eprintln!("activate_license error: {:#}", e),
        }
    }

    // Test download grant + artifact download
    match download_artifact("enterprise", None, false) {
        Ok((path, version)) => {
            eprintln!("SUCCESS: Downloaded to: {} version: {}", path.display(), version);
            // Clean up
            std::fs::remove_file(&path).ok();
        }
        Err(e) => {
            // Print the response body if possible to debug
            eprintln!("ERROR CHAIN: {:#}", e);
            panic!("download failed");
        }
    }
}
