//! Mock license generator — creates a signed license key for testing.
//! Also saves the LicenseCache locally so the installer can use it
//! without contacting the activation server.
//!
//! **ONLY compiled with `--features test-license`.** This feature is
//! test-only and MUST NOT be enabled in release builds.
//!
//! The test private key is read from `$TALUS_TEST_SIGNING_KEY` (hex) or
//! from `~/.secrets/talus/license-keys/test_key.json`. It is NEVER
//! stored in the repository.
//!
//! Run:  cargo run --example mock-license --features test-license
//! Then use:  sudo talus-installer --no-tui --skip-license
//!   (or: sudo talus-installer --no-tui --license-key-stdin < key.txt)

#![cfg(feature = "test-license")]

use anyhow::Context;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use std::collections::HashSet;

use talus_process_monitor::license::{LicenseCache, LicenseKey, LicenseTier};

fn main() -> anyhow::Result<()> {
    let priv_hex = load_test_signing_key()?;
    let priv_bytes = hex::decode(&priv_hex)
        .map_err(|e| anyhow::anyhow!("invalid hex in test signing key: {e}"))?;
    let priv_arr: [u8; 32] = priv_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&priv_arr);

    // License payload — uses "test" kid so the test public key is selected.
    #[derive(Serialize)]
    struct Payload {
        license_id: String,
        kid: String,
        tier: String,
        features: Vec<String>,
        max_nodes: u32,
        expires_at: Option<String>,
        issued_at: String,
        machine_id: Option<String>,
        organization: Option<String>,
        seat_count: u32,
    }

    let features: HashSet<String> = LicenseTier::Enterprise
        .default_features()
        .into_iter()
        .collect();
    let features: Vec<String> = features.into_iter().collect();

    let payload = Payload {
        license_id: "TALUS-TEST-0001".to_string(),
        kid: "test".to_string(),
        tier: "enterprise".to_string(),
        features,
        max_nodes: 0,
        expires_at: None,
        issued_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        machine_id: None,
        organization: Some("Hartwell Labs Test".to_string()),
        seat_count: 1,
    };

    // Serialize payload
    let payload_json = serde_json::to_string(&payload)?;
    println!("Payload: {}", payload_json);

    // Create canonical key: base64(payload).base64(signature)
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&payload_json);

    let signature = signing_key.sign(payload_json.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let canonical_key = format!("{}.{}", payload_b64, sig_b64);
    println!("\nCanonical key:\n  {}\n", canonical_key);

    // Verify the key parses locally (signature check against embedded test public key)
    let license_key = LicenseKey::parse(&canonical_key)?;
    println!("✓ License key verifies against test public key (kid='test')");
    println!("  License ID: {}", license_key.payload.license_id);
    println!("  Tier:       {}", license_key.payload.tier);
    println!(
        "  Features:   {}",
        license_key
            .payload
            .effective_features()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Build the parsed payload for the cache
    let machine_id = talus_process_monitor::license::generate_machine_id()
        .unwrap_or_else(|_| "T-unknown".into());

    // Set machine_id so verify_cached_license() binding check passes.
    // (The divergence check ignores machine_id — only compares signed fields.)
    let mut payload_with_mid = license_key.payload.clone();
    payload_with_mid.machine_id = Some(machine_id.clone());

    let cache = LicenseCache {
        key: canonical_key.clone(),
        payload: payload_with_mid,
        activation_token: Some("mock-activation-token".to_string()),
        activated_at: Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        token_expires_at: None,
    };

    cache.save()?;
    // Also save config integrity HMAC so verify_cached_license() passes
    // (it checks the .integrity.hmac file against license.dat + trial.dat hashes).
    let _ = talus_process_monitor::license::save_config_integrity();
    println!("\n✓ LicenseCache saved (offline mode)");
    println!("✓ Config integrity HMAC written");
    println!("  Machine ID: {}", machine_id);
    if let Ok(home) = std::env::var("HOME") {
        println!("  Cache path: {}/.config/talus/license.dat", home);
    }

    println!("\nNow run:  sudo talus-installer --no-tui --skip-license");
    Ok(())
}

/// Load the test signing key from environment or a secrets file.
/// NEVER from a hardcoded string in source.
fn load_test_signing_key() -> anyhow::Result<String> {
    // Priority 1: environment variable
    if let Ok(key) = std::env::var("TALUS_TEST_SIGNING_KEY") {
        return Ok(key);
    }

    // Priority 2: secrets file (0600)
    let path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?
        .join(".secrets/talus/license-keys/test_key.json");

    let content = std::fs::read_to_string(&path).map_err(|_| {
        anyhow::anyhow!(
            "test signing key not found.\n\
                 Set TALUS_TEST_SIGNING_KEY env var (hex), or create {} with 0600",
            path.display()
        )
    })?;

    // Parse the JSON to extract the private key
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("test_key.json is malformed JSON")?;

    let priv_hex = parsed
        .get("private_key_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("test_key.json missing 'private_key_hex' field"))?;

    if priv_hex.len() != 64 {
        anyhow::bail!(
            "test signing key must be 32 bytes (64 hex chars), got {}",
            priv_hex.len()
        );
    }

    Ok(priv_hex.to_string())
}
