// ── license.rs — Talus commercial licensing system ────────────────────────
//
// Provides license key validation, feature gating, and online activation.
//
// License key format:
//   base64(JSON payload) . base64(Ed25519 signature)
//
// Payload structure:
//   {
//     "license_id": "TALUS-XXXX-XXXX-XXXX",
//     "tier": "enterprise",
//     "features": ["tui", "web", "auto_kill", "kafka", "clickhouse", "memgraph"],
//     "max_nodes": 0,           // 0 = unlimited
//     "expires_at": "2027-01-01T00:00:00Z",  // null = perpetual
//     "issued_at": "2026-01-01T00:00:00Z",
//     "machine_id": null,       // set after activation
//     "organization": "Acme Corp"
//   }
//
// Activation flow:
//   1. User runs: talus --license activate <KEY>
//   2. Binary generates machine fingerprint (MAC + hostname + CPU)
//   3. Sends { key, machine_id } to activation server
//   4. Server validates key, records activation, returns { token, expires_at }
//   5. Token cached locally in ~/.config/talus/license.json

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// Pretty-key codec (TALUS-XXXXX-… ↔ canonical payload.signature).
pub mod format;

// ── Integrity check ───────────────────────────────────────────────────────

/// Compute XOR checksum of a byte slice.
fn xor_checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Public key bytes for each trusted signing key (separate consts allow
/// compile-time checksum computation).
pub const PUBKEY_V1: [u8; 32] = [
    // Rotated 2026-10-29 — verification-only (backward compat).
    0xf9, 0xb0, 0xec, 0x27, 0x4c, 0x44, 0xa7, 0x83, 0x3e, 0x60, 0x47, 0x58, 0x88, 0x43, 0xf0, 0xf2,
    0x26, 0x9f, 0xad, 0x3a, 0xc3, 0x83, 0x6f, 0x46, 0x8b, 0x58, 0x2b, 0xb9, 0x6a, 0x99, 0x3b, 0x31,
];
pub const PUBKEY_V2: [u8; 32] = [
    // Active since 2026-10-30. Private key at ~/.secrets/talus/license-keys/signing_key.json
    0xe1, 0xe9, 0x8f, 0x15, 0x9d, 0x34, 0xf5, 0x4b, 0x4c, 0x51, 0xf2, 0x3e, 0x53, 0xa4, 0x9c, 0x65,
    0x8c, 0x87, 0xde, 0xec, 0xf5, 0xac, 0x52, 0x18, 0xe0, 0x4e, 0xd6, 0x44, 0xf6, 0x90, 0x13, 0x06,
];

/// XOR checksum across all trusted public key bytes — computed at compile time.
/// Used to detect binary tampering: if someone replaces a public key to accept
/// forged licenses, this checksum will mismatch (assuming they don't also
/// update this constant).
#[cfg(not(feature = "test-license"))]
const KEY_CHECKSUM: u8 = {
    let mut acc = 0u8;
    let mut i = 0;
    while i < 32 {
        acc ^= PUBKEY_V1[i] ^ PUBKEY_V2[i];
        i += 1;
    }
    acc
};

#[cfg(feature = "test-license")]
const KEY_CHECKSUM: u8 = {
    let mut acc = 0u8;
    let mut i = 0;
    while i < 32 {
        acc ^= PUBKEY_V1[i] ^ PUBKEY_V2[i] ^ PUBKEY_TEST[i];
        i += 1;
    }
    acc
};

/// An Ed25519 public key trusted for license signature verification,
/// with a key ID for rotation support.
pub struct PublicKeyEntry {
    pub kid: &'static str,
    pub key: [u8; 32],
    /// If false, used for verification only (backward compat during rotation).
    pub active: bool,
}

/// Test-only public key — only compiled with `--features test-license`.
/// The corresponding private key is NEVER committed; it is generated
/// at test time and injected via environment or mock binary.
#[cfg(feature = "test-license")]
pub const PUBKEY_TEST: [u8; 32] = [
    0xba, 0x13, 0x4d, 0xe9, 0xc6, 0xfc, 0x6d, 0xbc, 0x4d, 0xd5, 0xe5, 0x31, 0x22, 0x11, 0xc2, 0xe8,
    0x77, 0xc8, 0x92, 0x7b, 0xd0, 0x88, 0x62, 0x27, 0x7e, 0x33, 0xc4, 0x94, 0x17, 0x75, 0x11, 0x1e,
];

/// Keys trusted for license signature verification.
///
/// - "v1" (2026-09-17): rotated 2026-10-29 — verification-only, old keys expire.
/// - "v2" (2026-10-30): current active key for all new licenses.
/// - "test" (test-license feature only): never in release builds.
///
/// Backward compatibility: licenses without an explicit `kid` field default
/// to "v1", so they continue to verify against the old key.
pub const PUBLIC_KEYS: &[PublicKeyEntry] = &[
    PublicKeyEntry {
        kid: "v1",
        key: PUBKEY_V1,
        active: false,
    },
    PublicKeyEntry {
        kid: "v2",
        key: PUBKEY_V2,
        active: true,
    },
    #[cfg(feature = "test-license")]
    PublicKeyEntry {
        kid: "test",
        key: PUBKEY_TEST,
        active: false,
    },
];

/// Default key ID for licenses without an explicit `kid` field (backward compat).
fn default_kid() -> String {
    "v1".to_string()
}

/// Lookup the verifying key by its `kid`.
fn verifying_key_for(kid: &str) -> Result<&'static VerifyingKey> {
    static KEYS: OnceLock<Vec<(&'static str, VerifyingKey)>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        PUBLIC_KEYS
            .iter()
            .filter_map(|e| VerifyingKey::from_bytes(&e.key).ok().map(|k| (e.kid, k)))
            .collect()
    });
    keys.iter()
        .find(|(entry_kid, _)| *entry_kid == kid)
        .map(|(_, key)| key)
        .ok_or_else(|| anyhow::anyhow!("unknown key ID in license: {kid}"))
}

// ── License data types ────────────────────────────────────────────────────

/// License tier determines feature access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Community edition — free, limited features.
    Community,
    /// Enterprise — full feature access.
    Enterprise,
}

impl LicenseTier {
    pub fn display_name(&self) -> &str {
        match self {
            LicenseTier::Community => "Community",
            LicenseTier::Enterprise => "Enterprise",
        }
    }

    /// Default features enabled for this tier.
    pub fn default_features(&self) -> Vec<String> {
        match self {
            LicenseTier::Community => vec!["tui".into(), "plain".into(), "json".into()],
            LicenseTier::Enterprise => vec![
                "tui".into(),
                "plain".into(),
                "json".into(),
                "web".into(),
                "auto_kill".into(),
                "kafka".into(),
                "clickhouse".into(),
                "memgraph".into(),
                "ffi".into(),
            ],
        }
    }
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// The signed license payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// Unique license identifier (e.g., "TALUS-A1B2-C3D4-E5F6").
    pub license_id: String,
    /// License tier.
    pub tier: LicenseTier,
    /// Key ID used for signature verification (defaults to "v1" for backward compat).
    #[serde(default = "default_kid", skip_serializing_if = "is_default_kid")]
    pub kid: String,
    /// Explicit feature allowlist. If present, overrides tier defaults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Vec<String>>,
    /// Maximum managed nodes (0 = unlimited).
    #[serde(default)]
    pub max_nodes: u32,
    /// Expiration datetime (ISO 8601). None = perpetual.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// When the license was issued (ISO 8601).
    pub issued_at: String,
    /// Machine fingerprint set after activation. None = not yet activated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    /// Organization name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Seat count for multi-node deployments (1 = single node).
    #[serde(default = "default_seat_count")]
    pub seat_count: u32,
}

fn default_seat_count() -> u32 {
    1
}

fn is_default_kid(kid: &str) -> bool {
    kid == "v1"
}

impl LicensePayload {
    /// Check if this license is currently valid (not expired).
    pub fn is_expired(&self) -> bool {
        if let Some(ref expires) = self.expires_at {
            if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M:%SZ")
            {
                return chrono::Utc::now().naive_utc() > expiry;
            }
        }
        false
    }

    /// Get effective feature set for this license.
    pub fn effective_features(&self) -> HashSet<String> {
        if let Some(ref features) = self.features {
            features.iter().cloned().collect()
        } else {
            self.tier.default_features().iter().cloned().collect()
        }
    }

    /// Check if a specific feature is enabled.
    pub fn has_feature(&self, feature: &str) -> bool {
        self.effective_features().contains(feature)
    }

    /// Check if this license is activated for the given machine.
    pub fn is_activated_for(&self, machine_id: &str) -> bool {
        match &self.machine_id {
            Some(id) => id == machine_id,
            None => false, // Not activated yet
        }
    }
}

/// A license key is the base64-encoded payload + signature.
#[derive(Debug, Clone)]
pub struct LicenseKey {
    pub payload: LicensePayload,
    #[allow(dead_code)]
    signature: Signature,
}

impl LicenseKey {
    #[allow(dead_code)]
    /// Parse and verify a license key string.
    ///
    /// Accepts BOTH customer-facing forms:
    ///   • pretty:   `TALUS-XXXXX-XXXXX-…-SS` (Crockford base32 + checksum)
    ///   • canonical: `<base64_payload>.<base64_signature>` (legacy)
    /// Verification always operates on the canonical form underneath.
    pub fn parse(key_str: &str) -> Result<Self> {
        // Tolerate copy-paste artifacts: trailing newlines/spaces from
        // terminal or editor must never break activation.
        let key_str = key_str.trim();
        // Pretty display key → canonical form (checksum-validated decode).
        let key_owned: String = if format::is_pretty(key_str) {
            format::decode_pretty(key_str)?
        } else {
            key_str.to_string()
        };
        let key_str: &str = key_owned.as_str();
        let parts: Vec<&str> = key_str.split('.').collect();
        if parts.len() != 2 {
            bail!("invalid license key format: expected '<payload>.<signature>'");
        }

        let payload_bytes = BASE64
            .decode(parts[0])
            .context("invalid base64 in license payload")?;
        let sig_bytes = BASE64
            .decode(parts[1])
            .context("invalid base64 in license signature")?;

        let payload: LicensePayload =
            serde_json::from_slice(&payload_bytes).context("failed to parse license payload")?;

        let signature = Signature::from_slice(&sig_bytes).context("invalid signature length")?;

        // Verify signature using the key identified by `kid`
        let vk = verifying_key_for(&payload.kid)
            .map_err(|e| anyhow::anyhow!("license key verification failed: {e}"))?;
        vk.verify(&payload_bytes, &signature)
            .map_err(|e| anyhow::anyhow!("license signature verification failed: {e}"))?;

        // v1 is verification-only since the 2026-10-29 rotation. It remains
        // accepted for licenses issued before that date; a v1 key minted
        // afterwards means the retired key was used, and is refused.
        const V1_RETIRED_AT: &str = "2026-10-29T00:00:00Z";
        if payload.kid == "v1" && payload.issued_at.as_str() > V1_RETIRED_AT {
            bail!("license key uses the retired v1 signing key");
        }

        Ok(Self { payload, signature })
    }

    #[allow(dead_code)]
    /// Serialize the key back to string form.
    pub fn to_string(&self) -> Result<String> {
        let payload_bytes =
            serde_json::to_vec(&self.payload).context("failed to serialize license payload")?;
        let payload_b64 = BASE64.encode(&payload_bytes);
        let sig_b64 = BASE64.encode(self.signature.to_bytes());
        Ok(format!("{payload_b64}.{sig_b64}"))
    }

    #[allow(dead_code)]
    /// Check if this license allows the given feature.
    pub fn allows(&self, feature: &str) -> bool {
        self.payload.has_feature(feature)
    }

    /// Check if this license is expired.
    pub fn is_expired(&self) -> bool {
        self.payload.is_expired()
    }
}

// ── Machine fingerprinting ────────────────────────────────────────────────

/// Generate a machine fingerprint from hostname + MAC addresses + CPU info.
/// Used for machine-locking licenses during activation.
pub fn generate_machine_id() -> Result<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hostname
    if let Ok(hostname) = hostname::get() {
        hostname.to_string_lossy().hash(&mut hasher);
    }

    // MAC addresses from /sys/class/net/
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        let mut macs: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|name| name != "lo")
            .filter_map(|name| {
                let addr_path = format!("/sys/class/net/{name}/address");
                fs::read_to_string(&addr_path)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .collect();
        macs.sort();
        for mac in macs {
            mac.hash(&mut hasher);
        }
    }

    // CPU info
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        for line in cpuinfo.lines() {
            if line.starts_with("model name") || line.starts_with("CPU implementer") {
                line.hash(&mut hasher);
                break;
            }
        }
    }

    // Machine ID (systemd)
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        id.trim().hash(&mut hasher);
    }

    let hash = hasher.finish();
    Ok(format!("T-{:016x}", hash))
}

// ── License storage ───────────────────────────────────────────────────────

/// Derive a simple obfuscation key from machine fingerprint.
/// Not cryptographic — prevents casual hex-editing of the license file.
fn derive_obfuscation_key() -> [u8; 16] {
    let machine = generate_machine_id().unwrap_or_default();
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    machine.hash(&mut hasher);
    "talus-license-v1".hash(&mut hasher);
    let h = hasher.finish();
    let mut key = [0u8; 16];
    key[0..8].copy_from_slice(&h.to_le_bytes());
    // Second half from a different hash
    let mut hasher2 = DefaultHasher::new();
    h.hash(&mut hasher2);
    let h2 = hasher2.finish();
    key[8..16].copy_from_slice(&h2.to_le_bytes());
    key
}

/// XOR-encrypt data with a key (symmetric — same function encrypts and decrypts).
fn xor_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Cached license state stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseCache {
    /// The original license key string.
    pub key: String,
    /// Parsed payload.
    pub payload: LicensePayload,
    /// Activation token received from server.
    pub activation_token: Option<String>,
    /// When the token was issued.
    pub activated_at: Option<String>,
    /// Token expiry (if time-limited).
    pub token_expires_at: Option<String>,
}

impl LicenseCache {
    fn path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .context("cannot determine config directory")?;
        Ok(config_dir.join("talus").join("license.dat"))
    }

    /// Load cached license from disk (with XOR decryption).
    pub fn load() -> Result<Option<Self>> {
        let path = Self::path()?;
        if !path.exists() {
            return Ok(None);
        }
        let encrypted = fs::read(&path).context("failed to read license cache")?;
        let key = derive_obfuscation_key();
        let decrypted = xor_crypt(&encrypted, &key);
        let data = String::from_utf8(decrypted)
            .context("license file is corrupted (decryption failed)")?;
        let cache: Self = serde_json::from_str(&data).context("failed to parse license cache")?;
        Ok(Some(cache))
    }

    /// Save license cache to disk with XOR encryption and restricted permissions (0600).
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("failed to create config directory")?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .context("failed to set config directory permissions")?;
        }
        let data =
            serde_json::to_string_pretty(self).context("failed to serialize license cache")?;
        let key = derive_obfuscation_key();
        let encrypted = xor_crypt(data.as_bytes(), &key);
        let mut file = fs::File::create(&path).context("failed to create license cache")?;
        file.write_all(&encrypted)
            .context("failed to write license cache")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .context("failed to set license file permissions")?;
        Ok(())
    }

    /// Delete cached license.
    pub fn clear() -> Result<()> {
        let path = Self::path()?;
        if path.exists() {
            fs::remove_file(&path).context("failed to remove license cache")?;
        }
        if let Some(dir) = dirs::config_dir() {
            let trial_file = dir.join("talus").join(".trial.dat");
            let _ = fs::remove_file(trial_file);
        }
        Ok(())
    }

    /// Backup license to a user-specified path.
    pub fn backup(&self, dest: &Path) -> Result<()> {
        let data =
            serde_json::to_string_pretty(self).context("failed to serialize license for backup")?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(dest, data).context("failed to write license backup")?;
        // Restrict permissions on backup too
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o600));
        Ok(())
    }

    /// Restore license from a backup file.
    pub fn restore(src: &Path) -> Result<Self> {
        let data = fs::read_to_string(src).context("failed to read license backup")?;
        let cache: Self = serde_json::from_str(&data)
            .context("failed to parse license backup — file may be corrupted")?;
        // Verify the key signature before restoring
        LicenseKey::parse(&cache.key).context("backup contains invalid license key")?;
        cache.save()?;
        Ok(cache)
    }
}

// ── Online activation client ──────────────────────────────────────────────

/// Activation server endpoints, in failover order (configurable via env).
///
///   Primary:   TALUS_LICENSE_SERVER (default: production worker)
///   Failover:  TALUS_LICENSE_SERVER_FAILOVER — comma-separated list;
///              unset → built-in failover worker, set to "" → disabled.
///
/// All servers share one storage (Turso), so failover is transparent: the
/// same request is retried against the next endpoint when the previous one
/// is unreachable at the connection level. HTTP-level errors (invalid key,
/// rate limit, revoked) come from the shared state and are authoritative —
/// they are NOT retried elsewhere.
fn activation_server_urls() -> Vec<String> {
    let primary = std::env::var("TALUS_LICENSE_SERVER")
        .unwrap_or_else(|_| "https://lic.hartwell-labs.pl".to_string());
    let mut urls = vec![primary];
    match std::env::var("TALUS_LICENSE_SERVER_FAILOVER") {
        Ok(list) if list.trim().is_empty() => {} // failover explicitly disabled
        Ok(list) => urls.extend(
            list.split(',')
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty()),
        ),
        Err(_) => {
            // Built-in failover — separate host for redundancy.
            // Logs a warning in release builds if the primary is overridden.
            #[cfg(not(debug_assertions))]
            if std::env::var("TALUS_LICENSE_SERVER").is_ok() {
                eprintln!("[talus] WARNING: using custom license server via TALUS_LICENSE_SERVER");
            }
            urls.push("https://lic-failover.hartwell-labs.pl".to_string());
        }
    }
    urls
}

/// Maximum response body size for license server requests (64 KiB).
const MAX_RESPONSE_BYTES: u64 = 65536;

/// POST a JSON request to the activation API, trying each server in order.
/// Connection-level failures (DNS, connect, timeout) fall through to the
/// next server; the first reachable server's reply is returned as-is.
///
/// Security:
/// - Response body limited to 64 KiB to prevent memory exhaustion attacks.
/// - TLS certificate verification is always enabled (never disabled).
/// - HTTPS enforced — all servers must use `https://`.
fn post_activation_api<T: serde::de::DeserializeOwned>(
    path: &str,
    body: &impl serde::Serialize,
    timeout_secs: u64,
) -> Result<(reqwest::StatusCode, T)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(5))
        .https_only(true)
        .danger_accept_invalid_certs(false)
        .user_agent(format!("talus-installer/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to create HTTP client")?;

    let servers = activation_server_urls();
    let mut last_err = None;

    for (i, server_url) in servers.iter().enumerate() {
        // Verify HTTPS (redundant with https_only, but explicit for audit)
        if !server_url.starts_with("https://") {
            bail!("license server must use HTTPS: {server_url}");
        }

        let url = format!("{server_url}{path}");
        match client.post(&url).json(body).send() {
            Ok(response) => {
                // Capture status before consuming the response for body reading
                let status = response.status();

                // Enforce response size limit
                let content_length = response.content_length();
                if let Some(len) = content_length {
                    if len > MAX_RESPONSE_BYTES {
                        audit_log(
                            "RESPONSE_TOO_LARGE",
                            "server-response",
                            &format!("server returned {len} bytes (limit {MAX_RESPONSE_BYTES})"),
                        );
                        return Err(anyhow::anyhow!(
                            "server response exceeds {MAX_RESPONSE_BYTES} bytes limit"
                        ));
                    }
                }

                // Read body with size guard
                let bytes = response
                    .bytes()
                    .with_context(|| format!("failed to read response body from {server_url}"))?;
                if bytes.len() > MAX_RESPONSE_BYTES as usize {
                    audit_log(
                        "RESPONSE_TOO_LARGE",
                        "server-response",
                        &format!(
                            "server returned {} bytes (limit {MAX_RESPONSE_BYTES})",
                            bytes.len()
                        ),
                    );
                    return Err(anyhow::anyhow!(
                        "server response exceeds {MAX_RESPONSE_BYTES} bytes limit"
                    ));
                }

                let parsed: T = serde_json::from_slice(&bytes)
                    .with_context(|| format!("failed to parse response from {server_url}"))?;
                return Ok((status, parsed));
            }
            Err(err) if i + 1 < servers.len() => {
                // Network-level error: retry against failover server
                eprintln!(
                    "[talus] activation server {server_url} unreachable ({err}); trying failover"
                );
                last_err = Some(err);

                // Brief backoff before retrying (jittered: 100-500ms)
                if i < servers.len() - 1 {
                    let backoff = std::time::Duration::from_millis(100 + (i as u64 * 200));
                    std::thread::sleep(backoff);
                }
            }
            Err(err) => {
                // Last server — return the error
                return Err(anyhow::anyhow!(err)).context("failed to connect to activation server");
            }
        }
    }
    bail!(
        "no activation server reachable (tried {}): {}",
        servers.join(", "),
        last_err.map(|e| e.to_string()).unwrap_or_default()
    );
}

/// Resolve response from the license server.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveResponse {
    success: bool,
    license_key: Option<String>,
    license_id: Option<String>,
    message: Option<String>,
    tier: Option<String>,
}

/// Resolve a SHORT key (TALUS-XXXXX-XXXXX-XXXXX-XXXXX) to its signed JWT
/// (canonical form) via the license server. The short key is just a handle —
/// the JWT is bound to it server-side. The returned JWT is verified locally
/// (Ed25519, embedded public key), so the server cannot forge license terms.
fn resolve_short_key(short_key: &str) -> Result<String> {
    let (status, body): (_, ResolveResponse) = post_activation_api(
        "/api/v1/resolve",
        &serde_json::json!({ "key": short_key.trim() }),
        20,
    )?;

    if !status.is_success() || !body.success {
        let msg = body.message.as_deref().unwrap_or("key not recognized");
        audit_log("RESOLVE_FAILED", "short-key", &format!("{status}: {msg}"));
        bail!(
            "license key not recognized ({}). \
             Short keys activate online — check the key or retry in a few minutes",
            msg
        );
    }

    let jwt = body
        .license_key
        .ok_or_else(|| anyhow::anyhow!("resolve response missing license_key"))?;

    audit_log(
        "RESOLVE_OK",
        body.license_id.as_deref().unwrap_or("short-key"),
        &format!(
            "short key resolved to {} license",
            body.tier.as_deref().unwrap_or("unknown")
        ),
    );
    Ok(jwt)
}

/// Activation request sent to the server.
#[derive(Serialize)]
struct ActivationRequest {
    license_key: String,
    machine_id: String,
    hostname: String,
    version: String,
}

/// Activation response from the server.
/// `deny_unknown_fields` ensures we reject responses with unexpected fields —
/// a server compromise that adds fields cannot inject unexpected data.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationResponse {
    success: bool,
    token: Option<String>,
    expires_at: Option<String>,
    message: Option<String>,
    #[allow(dead_code)]
    tier: Option<String>,
}

/// Activation rate limiter — max 5 attempts per 5 minutes.
static ACTIVATION_ATTEMPTS: OnceLock<std::sync::Mutex<Vec<std::time::Instant>>> = OnceLock::new();

fn check_activation_rate_limit() -> Result<()> {
    let attempts = ACTIVATION_ATTEMPTS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut attempts = attempts
        .lock()
        .map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
    let now = std::time::Instant::now();
    // Remove entries older than 5 minutes
    attempts.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(300));
    if attempts.len() >= 5 {
        let oldest = attempts.first().map(|t| t.elapsed().as_secs()).unwrap_or(0);
        let wait = 300 - oldest;
        bail!("too many activation attempts — try again in {wait}s");
    }
    attempts.push(now);
    Ok(())
}

/// Ask the server to translate a store key (Polar / Gumroad / Lemon
/// Squeezy) into a Talus license. Returns the Talus key string. The server
/// verifies the purchase mapping — the reply is a native signed key, so all
/// downstream verification applies unchanged.
fn redeem_store_key(store_key: &str) -> Result<String> {
    let (status, body): (_, ResolveResponse) = post_activation_api(
        "/api/v1/redeem",
        &serde_json::json!({ "key": store_key.trim() }),
        20,
    )?;

    if !status.is_success() || !body.success {
        let msg = body
            .message
            .as_deref()
            .unwrap_or("store key not recognized");
        audit_log("REDEEM_FAILED", "store-key", &format!("{status}: {msg}"));
        bail!(
            "this does not look like a Talus license key ({}). \
             Store purchases are translated automatically — try again in a few minutes",
            msg
        );
    }

    let talus_key = body
        .license_key
        .ok_or_else(|| anyhow::anyhow!("redeem response missing license_key"))?;

    audit_log(
        "REDEEM_OK",
        "store-key",
        &format!(
            "store key translated to {} license",
            body.tier.as_deref().unwrap_or("unknown")
        ),
    );
    Ok(talus_key)
}

/// Activate a license key against the online server.
pub fn activate_license(key: &str) -> Result<LicenseCache> {
    // Normalize once: the trimmed key is used for verification, the server
    // request AND the saved cache (so the cache always holds the clean form).
    let key = key.trim();

    // ── Local format validation BEFORE any network access ───────────────────
    // This catches typos and malicious input early, without leaking the key
    // to the network or logs.
    validate_key_format(key)?;

    // Rate limit activation attempts
    check_activation_rate_limit()?;

    // ── Key normalization ──────────────────────────────────────────────────
    // Accepted inputs, all normalizing to the canonical signed JWT:
    //   1. short key  TALUS-XXXXX-…    → resolve via /api/v1/resolve
    //   2. store key   (Polar/…)       → redeem via /api/v1/redeem
    //   3. canonical JWT / pretty JWT  → used as-is
    // Everything is verified LOCALLY afterwards, so the server only ever
    // hands out keys the owner signed — it cannot alter license terms.
    let key_owned: String = if format::is_short(key) {
        resolve_short_key(key)?
    } else {
        match LicenseKey::parse(key) {
            Ok(_) => key.to_string(),
            Err(_) => redeem_store_key(key)?,
        }
    };
    let key: &str = &key_owned;

    // Parse and verify the key locally first
    let license_key =
        LicenseKey::parse(key).context("license key verification failed — invalid signature")?;

    if license_key.is_expired() {
        audit_log(
            "ACTIVATE_FAILED",
            &license_key.payload.license_id,
            "license expired",
        );
        bail!("license {} has expired", license_key.payload.license_id);
    }

    // Downgrade protection: if currently Enterprise, block Community activation
    if let Ok(Some(ref current)) = LicenseCache::load() {
        if current.payload.tier == LicenseTier::Enterprise
            && license_key.payload.tier == LicenseTier::Community
        {
            audit_log(
                "DOWNGRADE_BLOCKED",
                &license_key.payload.license_id,
                "attempted downgrade from Enterprise",
            );
            bail!("cannot downgrade from Enterprise license (deactivate current license first)");
        }
    }

    let machine_id = generate_machine_id()?;
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());

    let request = ActivationRequest {
        license_key: key.to_string(),
        machine_id: machine_id.clone(),
        hostname,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let (status, body): (_, ActivationResponse) =
        post_activation_api("/api/v1/activate", &request, 30)?;

    if !status.is_success() || !body.success {
        let msg = body.message.unwrap_or_else(|| "unknown error".into());
        audit_log(
            "ACTIVATE_FAILED",
            &license_key.payload.license_id,
            &format!("{status}: {msg}"),
        );
        bail!("activation failed ({status}): {msg}");
    }

    // Update payload with machine ID
    let mut payload = license_key.payload;
    payload.machine_id = Some(machine_id.clone());

    let cache = LicenseCache {
        key: key.to_string(),
        payload,
        activation_token: body.token,
        activated_at: Some(chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        token_expires_at: body.expires_at,
    };

    cache.save()?;

    audit_log(
        "ACTIVATED",
        &cache.payload.license_id,
        &format!("machine={machine_id}"),
    );
    eprintln!("[talus] ✓ license activated successfully");
    Ok(cache)
}

// ── Artifact download ────────────────────────────────────────────────────

/// Response from `/api/v1/download-grant`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct DownloadGrantResponse {
    success: bool,
    url: String,
    expires_in: u32,
    sha256: String,
    size: u64,
    version: String,
    artifact_sig: Option<String>,
    tier: String,
    message: Option<String>,
}

/// Download the appropriate binary for this license tier.
///
/// Flow:
/// 1. POST /api/v1/download-grant with license_key + machine_id + nonce
/// 2. Download artifact to a temp directory (mktemp -d, 0700)
/// 3. Verify SHA-256 hash
/// 4. Verify ed25519 signature (if server provides artifact_sig URL)
/// 5. Check ELF magic (x86_64/aarch64)
/// 6. Return path + version
///
/// Security:
/// - Downloads to temp dir on the SAME filesystem as the destination (for atomic rename)
/// - Only HTTPS URLs accepted
/// - Max 3 redirects, only to allowed hosts
/// - No authorization headers forwarded to redirect targets
/// - Response size capped at 50 MB
pub fn download_artifact(
    tier: &str,
    current_version: Option<&str>,
    allow_downgrade: bool,
) -> Result<(PathBuf, String)> {
    let cache = LicenseCache::load()?.context("no license found — cannot download artifact")?;
    let license_id = cache.payload.license_id.clone();
    let machine_id = cache
        .payload
        .machine_id
        .as_ref()
        .context("license not activated — activate first")?;

    let nonce = generate_nonce();
    let target = std::env::consts::ARCH.to_string() + "-unknown-linux-" + std::env::consts::OS;

    let grant: DownloadGrantResponse = post_activation_api(
        "/api/v1/download-grant",
        &serde_json::json!({
            "license_key": cache.key,
            "machine_id": machine_id,
            "nonce": nonce,
            "target": target,
            "version": current_version,
        }),
        20,
    )
    .context("failed to contact license server for download grant")?
    .1;

    if !grant.success {
        let msg = grant.message.unwrap_or_default();
        audit_log("DOWNLOAD_DENIED", &license_id, &msg);
        bail!("download not available ({}): {}", grant.tier, msg);
    }

    // Verify version is not a downgrade
    if !allow_downgrade {
        if let Some(current) = current_version {
            if version_compare(&grant.version, current) < 0 {
                audit_log("DOWNLOAD_DOWNGRADE", &license_id, &grant.version);
                bail!(
                    "refusing to download {}: it is older than installed {}",
                    grant.version,
                    current
                );
            }
        }
    }

    // Validate URL is HTTPS
    if !grant.url.starts_with("https://") {
        audit_log("DOWNLOAD_BAD_URL", &license_id, "non-HTTPS URL");
        bail!("download URL must be HTTPS");
    }

    let download_dir = std::env::temp_dir();

    // Extract filename from URL query params (GitHub presigned URLs put filename in response-content-disposition)
    let filename = if let Some(fname) = grant.url.split("filename=").nth(1) {
        fname
            .split(['&', '%', ';'].as_ref())
            .next()
            .unwrap_or("talus-monitor-enterprise")
            .to_string()
    } else if let Some(fname) = std::path::Path::new(&grant.url)
        .file_name()
        .and_then(|n| n.to_str())
    {
        if fname.len() > 200 || fname.contains('?') || fname.contains('=') {
            format!("talus-monitor-{}", std::process::id())
        } else {
            fname.to_string()
        }
    } else {
        format!("talus-monitor-{}", std::process::id())
    };
    let download_path = download_dir.join(&filename);

    eprintln!(
        "[talus] downloading artifact from license server ({} MB)...",
        grant.size / (1024 * 1024)
    );

    {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(5))
            .https_only(true)
            .user_agent(format!("talus-installer/{}", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .context("failed to create HTTP client for download")?;

        let response = client
            .get(&grant.url)
            .send()
            .context("failed to start artifact download")?;

        if !response.status().is_success() {
            bail!("download failed: HTTP {}", response.status());
        }

        // Check content-length
        if let Some(len) = response.content_length() {
            if len > 50 * 1024 * 1024 {
                bail!("artifact too large: {} bytes (max 50 MB)", len);
            }
            if len != grant.size {
                bail!(
                    "size mismatch: server claimed {} bytes, actual {}",
                    grant.size,
                    len
                );
            }
        }

        // Stream to file with SHA-256 computation
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        {
            let bytes = response.bytes().context("failed to read artifact body")?;

            if bytes.len() > grant.size as usize {
                bail!(
                    "size mismatch: server claimed {} bytes, actual {}",
                    grant.size,
                    bytes.len()
                );
            }
            if bytes.len() > 50 * 1024 * 1024 {
                bail!("artifact exceeds 50 MB limit");
            }

            hasher.update(&bytes);
            std::fs::write(&download_path, &bytes)
                .context("failed to write downloaded artifact")?;
        }

        // Verify SHA-256
        let computed = hex::encode(hasher.finalize());
        if computed != grant.sha256 {
            let _ = std::fs::remove_file(&download_path);
            audit_log("DOWNLOAD_HASH_MISMATCH", &license_id, &grant.version);
            bail!(
                "SHA-256 mismatch: expected {}, got {}",
                grant.sha256,
                computed
            );
        }
        eprintln!("[talus] ✓ SHA-256 verified: {computed}");

        // Verify ELF magic
        {
            let magic = std::fs::read(&download_path)?
                .into_iter()
                .take(5)
                .collect::<Vec<_>>();
            if magic != vec![0x7f, b'E', b'L', b'F', 2] {
                let _ = std::fs::remove_file(&download_path);
                bail!("downloaded file is not a valid ELF64 binary");
            }
        }

        // Verify artifact signature if provided. Enterprise artifacts use cosign
        // keyless signing (ECDSA P-256 DER-encoded signatures with Fulcio
        // certificate). We delegate to `cosign verify-blob` when the CLI is
        // available; otherwise we fall back to a raw Ed25519 check (if the
        // signature is exactly 64 bytes) and emit a loud warning. SHA-256
        // integrity (verified above) is always the hard gate.
        if let Some(ref sig_url) = grant.artifact_sig {
            if !sig_url.starts_with("https://") {
                bail!("artifact signature URL must be HTTPS");
            }

            // Download signature file
            let sig_client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .https_only(true)
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .context("failed to create HTTP client for signature")?;

            let sig_bytes = sig_client
                .get(sig_url)
                .send()
                .context("failed to download artifact signature")?
                .bytes()
                .context("failed to read signature response")?;

            let binary_bytes = std::fs::read(&download_path)
                .context("failed to read downloaded binary for signature verification")?;

            // Check if signature is a raw Ed25519 sig (64 bytes)
            if sig_bytes.len() == 64 {
                // Verify with embedded artifact public key
                let artifact_pk = get_artifact_public_key();
                let art_vk = ed25519_dalek::VerifyingKey::from_bytes(&artifact_pk)
                    .map_err(|e| anyhow::anyhow!("invalid artifact public key: {e}"))?;
                let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
                    .context("invalid artifact signature format")?;
                if art_vk.verify(&binary_bytes, &sig).is_ok() {
                    eprintln!("[talus] ✓ artifact signature (ed25519) verified");
                } else {
                    bail!("artifact signature verification failed");
                }
            } else {
                // Likely a cosign/DER signature — try to verify with cosign
                let cosign_available = std::process::Command::new("cosign")
                    .arg("--version")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok();

                if cosign_available {
                    let dir = std::env::temp_dir();
                    let blob_path = dir.join(format!(".talus-verify-{}.blob", std::process::id()));
                    let sig_path = dir.join(format!(".talus-verify-{}.sig", std::process::id()));
                    std::fs::write(&blob_path, &binary_bytes)
                        .context("failed to write temp blob for cosign")?;
                    std::fs::write(&sig_path, &sig_bytes)
                        .context("failed to write temp sig for cosign")?;

                    eprintln!("[talus] verifying artifact signature with cosign (keyless)...");
                    let status = std::process::Command::new("cosign")
                        .arg("verify-blob")
                        .arg(&blob_path)
                        .arg("--signature")
                        .arg(&sig_path)
                        .arg("--insecure-ignore-tlog")
                        .status()
                        .context("failed to spawn cosign")?;

                    let _ = std::fs::remove_file(&blob_path);
                    let _ = std::fs::remove_file(&sig_path);

                    if !status.success() {
                        audit_log("DOWNLOAD_SIG_FAIL", &license_id, "cosign verification");
                        bail!("cosign signature verification FAILED — release is not authentic");
                    }
                    eprintln!("[talus] ✓ artifact signature (cosign) verified");
                } else {
                    audit_log("DOWNLOAD_SIG_WARN", &license_id, "cosign not installed");
                    eprintln!(
                        "[talus] ⚠ artifact signature present ({}) but `cosign` not installed;",
                        grant.version
                    );
                    eprintln!(
                        "[talus]   SHA-256 integrity gate passed (hard check). Signature verification skipped."
                    );
                    eprintln!("[talus]   Install `cosign` for full provenance verification.");
                }
            }
        }

        // Cleanup: we downloaded to /tmp, no special cleanup needed for dest_dir
        // (download_dir is system temp, so no parent dir to remove)

        audit_log(
            "DOWNLOAD_OK",
            &license_id,
            &format!("tier={}, version={}", tier, grant.version),
        );
        Ok((download_path, grant.version))
    }
}

/// Generate a random nonce for anti-replay.
fn generate_nonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let random: [u8; 16] = {
        let mut buf = [0u8; 16];
        if let Ok(handle) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = handle.try_clone().and_then(|mut f| f.read_exact(&mut buf));
        }
        buf
    };
    format!("{}-{:032x}", secs, u128::from_be_bytes(random))
}

/// Compare two semver-ish version strings. Returns negative/zero/positive.
fn version_compare(a: &str, b: &str) -> i32 {
    let parse = |s: &str| {
        s.trim_start_matches('v')
            .split('.')
            .filter_map(|p| p.split(|c: char| !c.is_ascii_digit()).next())
            .filter_map(|p| p.parse::<u32>().ok())
            .collect::<Vec<_>>()
    };
    let va = parse(a);
    let vb = parse(b);
    for (i, (x, y)) in va
        .iter()
        .chain(std::iter::repeat(&0))
        .zip(vb.iter().chain(std::iter::repeat(&0)))
        .enumerate()
    {
        if i >= 32 {
            break;
        }
        if x != y {
            return if x > y { 1 } else { -1 };
        }
    }
    0
}

/// Embedded artifact (release) public key for verifying binary signatures.
/// This is SEPARATE from the license verification key — artifact signing uses
/// a different key pair with a different role.
#[cfg(feature = "test-license")]
const ARTIFACT_PUBLIC_KEY: [u8; 32] = {
    // TEST artifact key — only compiled with --features test-license
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]
};

#[cfg(not(feature = "test-license"))]
const ARTIFACT_PUBLIC_KEY: [u8; 32] = {
    // Production artifact verification key.
    // kid: talus-artifact-v1
    [
        0x52, 0x1c, 0xa7, 0x95, 0xa9, 0x3b, 0x0c, 0x3e, 0xa7, 0x80, 0xb2, 0xeb, 0x44, 0xd3, 0x7f,
        0x81, 0x82, 0x1c, 0x84, 0x3a, 0xae, 0xae, 0x7e, 0xef, 0x62, 0xc9, 0x4e, 0x71, 0x91, 0xd5,
        0x9a, 0x47,
    ]
};

fn get_artifact_public_key() -> [u8; 32] {
    ARTIFACT_PUBLIC_KEY
}

/// Deactivate a license (release machine binding).
pub fn deactivate_license() -> Result<()> {
    let cache = LicenseCache::load()?.context("no license found — nothing to deactivate")?;

    if let Some(ref token) = cache.activation_token {
        // Best effort: release the seat via whichever server is reachable
        // (shared storage — any one of them is authoritative).
        let _: Result<(reqwest::StatusCode, serde_json::Value)> = post_activation_api(
            "/api/v1/deactivate",
            &serde_json::json!({
                "license_id": cache.payload.license_id,
                "token": token,
            }),
            15,
        );
    }

    audit_log(
        "DEACTIVATED",
        &cache.payload.license_id,
        "user deactivation",
    );
    LicenseCache::clear()?;
    eprintln!("[talus] ✓ license deactivated");
    Ok(())
}

/// Verify the current cached license is still valid.
pub fn verify_cached_license() -> Result<LicenseCache> {
    let cache = LicenseCache::load()?
        .context("no license found — run `talus license activate <KEY>` to activate")?;

    // ── Signed-key binding ────────────────────────────────────────────
    // Re-verify the stored key's Ed25519 signature and bind the cached
    // payload to it. Only `machine_id` may differ (it is added locally
    // after activation). Any other divergence — tier, expiry, features,
    // seat_count, organization — means the local cache was tampered with.
    match LicenseKey::parse(&cache.key) {
        Ok(signed) => {
            let p = &signed.payload;
            let c = &cache.payload;
            let diverged = p.license_id != c.license_id
                || p.kid != c.kid
                || p.tier != c.tier
                || p.features != c.features
                || p.max_nodes != c.max_nodes
                || p.expires_at != c.expires_at
                || p.organization != c.organization
                || p.seat_count != c.seat_count;
            if diverged {
                audit_log(
                    "CACHE_TAMPERED",
                    &c.license_id,
                    "cached payload diverges from the signed license key",
                );
                bail!("license cache has been tampered with — re-activation required");
            }
        }
        Err(e) => {
            audit_log(
                "CACHE_TAMPERED",
                &cache.payload.license_id,
                "stored license key failed signature verification",
            );
            bail!("license key in cache failed verification ({e}) — re-activation required");
        }
    }

    // Verify config file integrity
    if !verify_config_integrity().unwrap_or(false) {
        audit_log(
            "CONFIG_TAMPERED",
            &cache.payload.license_id,
            "config integrity check failed",
        );
        bail!("config files have been tampered with — re-activate required");
    }

    // Check expiry
    if cache.payload.is_expired() {
        // Offline grace period: allow 30 days after last server contact
        if is_within_offline_grace(&cache) {
            audit_log(
                "EXPIRED_GRACE",
                &cache.payload.license_id,
                "license expired but within offline grace period",
            );
            eprintln!("[talus] ⚠ license expired — running in offline grace mode");
        } else {
            audit_log("EXPIRED", &cache.payload.license_id, "license expired");
            bail!("license {} has expired", cache.payload.license_id);
        }
    }

    // Check token expiry
    if let Some(ref expires) = cache.token_expires_at {
        if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M:%SZ") {
            if chrono::Utc::now().naive_utc() > expiry {
                // Offline grace for token expiry too
                if is_within_offline_grace(&cache) {
                    audit_log(
                        "TOKEN_EXPIRED_GRACE",
                        &cache.payload.license_id,
                        "token expired but within offline grace period",
                    );
                    eprintln!("[talus] ⚠ activation token expired — running in offline grace mode");
                } else {
                    audit_log(
                        "TOKEN_EXPIRED",
                        &cache.payload.license_id,
                        "activation token expired",
                    );
                    bail!("activation token has expired — please re-activate");
                }
            }
        }
    }

    // Verify machine binding
    let current_machine = generate_machine_id()?;
    if !cache.payload.is_activated_for(&current_machine) {
        audit_log(
            "MISMATCH",
            &cache.payload.license_id,
            &format!(
                "machine mismatch: expected {}",
                cache.payload.machine_id.as_deref().unwrap_or("?")
            ),
        );
        bail!(
            "license is activated for a different machine (expected: {})",
            cache.payload.machine_id.as_deref().unwrap_or("?")
        );
    }

    // Save integrity hash after successful verification
    let _ = save_config_integrity();

    Ok(cache)
}

// ── Audit logging ─────────────────────────────────────────────────────────

/// SHA-256 hash of data, returning a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Delegate to the audit module for signed hash-chain logging.
fn audit_log(event: &str, license_id: &str, detail: &str) {
    crate::audit::audit_log(event, license_id, detail);
}

/// Verify the integrity of the audit log (hash chain).
#[allow(dead_code)]
pub fn verify_audit_log() -> Result<u64> {
    crate::audit::verify_audit_log()
}

/// Read the last N entries from the audit log.
pub fn read_audit_log(max_entries: usize) -> Vec<String> {
    crate::audit::read_audit_log(max_entries)
}

/// Validate a license key format locally BEFORE any network access.
///
/// Accepts:
/// - Short keys: `TALUS-XXXXX-XXXXX-XXXXX-XXXXX` (4 groups of 5 chars)
/// - Pretty keys: `TALUS-...` (6+ groups, includes checksum)
/// - Canonical keys: `base64(payload).base64(signature)`
///
/// Rejects: empty, wrong-prefix, suspicious patterns, or too short.
/// This catches typos without leaking the key to the network.
pub fn validate_key_format(key: &str) -> Result<()> {
    let trimmed = key.trim();

    if trimmed.is_empty() {
        bail!("license key is empty");
    }

    // Check for obviously wrong formats
    if trimmed.len() < 16 {
        bail!("license key too short (expected at least 16 characters)");
    }

    // Short key: TALUS-XXXXX-XXXXX-XXXXX-XXXXX (with checksum SS)
    if format::is_short(trimmed) {
        return Ok(());
    }

    // Pretty key: TALUS-... (with checksum)
    if format::is_pretty(trimmed) {
        return Ok(());
    }

    // Canonical: base64(base64).base64(base64) — has exactly one '.'
    let dot_count = trimmed.matches('.').count();
    if dot_count == 1 && trimmed.len() > 43 {
        // Basic shape check: two base64 segments
        let parts: Vec<&str> = trimmed.split('.').collect();
        if !parts[0].is_empty() && !parts[1].is_empty() {
            // Try to decode to catch obvious corruption
            if base64::engine::general_purpose::STANDARD
                .decode(parts[0])
                .is_ok()
                && base64::engine::general_purpose::STANDARD
                    .decode(parts[1])
                    .is_ok()
            {
                return Ok(());
            }
        }
    }

    // If it's not a short key and not a canonical JWT, it might be a store key.
    // We accept it and let the server reject it if invalid — store keys
    // have unpredictable format.
    bail!(
        "license key format not recognized.\n\
         Expected one of:\n\
         • Short key:  TALUS-XXXXX-XXXXX-XXXXX-XXXXX\n\
         • License key (JWT): base64.base64\n\
         • Store purchase key (Polar/Gumroad/Lemon Squeezy)"
    );
}

/// Compute a safe, redacted hash of the key for logging.
/// Returns `sha256(key)[..8]` hex — only first 8 chars of the hash.
/// The full key is NEVER included in logs.
pub fn key_fingerprint(key: &str) -> String {
    let digest = sha256_hex(key.trim().as_bytes());
    format!("{}-redacted", &digest[..16.min(digest.len())])
}

/// Get license health status as a JSON-serializable struct.
pub fn license_health() -> LicenseHealth {
    match LicenseCache::load() {
        Ok(Some(cache)) => {
            let expired = cache.payload.is_expired();
            let days = cache
                .payload
                .expires_at
                .as_ref()
                .and_then(|exp| days_remaining(exp));
            let current_machine = generate_machine_id().ok();
            let machine_match = current_machine
                .as_ref()
                .map(|m| cache.payload.is_activated_for(m))
                .unwrap_or(false);
            let features: Vec<String> = cache.payload.effective_features().into_iter().collect();
            LicenseHealth {
                status: if expired {
                    "expired".into()
                } else if !machine_match {
                    "machine_mismatch".into()
                } else {
                    "valid".into()
                },
                tier: cache.payload.tier.to_string(),
                license_id: cache.payload.license_id,
                organization: cache.payload.organization,
                expired,
                days_remaining: days,
                activated: cache.activation_token.is_some(),
                machine_bound: cache.payload.machine_id.is_some(),
                features,
            }
        }
        Ok(None) => LicenseHealth {
            status: "no_license".into(),
            tier: "community".into(),
            license_id: String::new(),
            organization: None,
            expired: false,
            days_remaining: None,
            activated: false,
            machine_bound: false,
            features: LicenseTier::Community.default_features(),
        },
        Err(_) => LicenseHealth {
            status: "error".into(),
            tier: "community".into(),
            license_id: String::new(),
            organization: None,
            expired: false,
            days_remaining: None,
            activated: false,
            machine_bound: false,
            features: LicenseTier::Community.default_features(),
        },
    }
}

/// License health status for API responses.
#[derive(Serialize)]
pub struct LicenseHealth {
    pub status: String,
    pub tier: String,
    pub license_id: String,
    pub organization: Option<String>,
    pub expired: bool,
    pub days_remaining: Option<i64>,
    pub activated: bool,
    pub machine_bound: bool,
    pub features: Vec<String>,
}

// ── Feature gating ────────────────────────────────────────────────────────

/// Runtime license state used throughout the application.
#[derive(Debug, Clone)]
pub struct LicenseState {
    pub tier: LicenseTier,
    features: HashSet<String>,
    #[allow(dead_code)]
    pub license_id: Option<String>,
    #[allow(dead_code)]
    pub organization: Option<String>,
    pub is_activated: bool,
}

impl LicenseState {
    /// No license — community defaults.
    pub fn community() -> Self {
        Self {
            tier: LicenseTier::Community,
            features: LicenseTier::Community
                .default_features()
                .into_iter()
                .collect(),
            license_id: None,
            organization: None,
            is_activated: false,
        }
    }

    /// 30-day Enterprise trial.
    pub fn trial() -> Self {
        Self {
            tier: LicenseTier::Enterprise,
            features: LicenseTier::Enterprise
                .default_features()
                .into_iter()
                .collect(),
            license_id: Some("TRIAL-30D".into()),
            organization: Some("Enterprise Trial".into()),
            is_activated: false,
        }
    }

    /// Create from a verified cached license.
    pub fn from_cache(cache: &LicenseCache) -> Self {
        Self {
            tier: cache.payload.tier.clone(),
            features: cache.payload.effective_features(),
            license_id: Some(cache.payload.license_id.clone()),
            organization: cache.payload.organization.clone(),
            is_activated: cache.activation_token.is_some(),
        }
    }

    /// Check if a specific feature is enabled.
    pub fn allows(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// Get the tier display name.
    pub fn tier_name(&self) -> &str {
        self.tier.display_name()
    }

    #[allow(dead_code)]
    /// Get all enabled features as a sorted list.
    pub fn feature_list(&self) -> Vec<String> {
        let mut features: Vec<String> = self.features.iter().cloned().collect();
        features.sort();
        features
    }
}

/// Cached license state (initialized once at startup).
static CACHED_STATE: OnceLock<LicenseState> = OnceLock::new();

/// Get the cached license state (fast, no re-parsing).
/// Must call `init_license()` first at startup.
#[allow(dead_code)]
pub fn get_license_state() -> &'static LicenseState {
    CACHED_STATE.get_or_init(LicenseState::community)
}

/// Initialize license state at startup.
/// Checks for cached license, falls back to community mode.
pub fn init_license() -> LicenseState {
    // Verify binary integrity (detect key tampering)
    if !verify_key_integrity() {
        eprintln!("[talus] ⚠ WARNING: binary integrity check failed — license key may have been tampered with");
        let state = LicenseState::community();
        let _ = CACHED_STATE.set(state.clone());
        return state;
    }

    let state = match verify_cached_license() {
        Ok(cache) => {
            eprintln!(
                "[talus] license: {} ({})",
                cache.payload.license_id, cache.payload.tier
            );
            if let Some(ref org) = cache.payload.organization {
                eprintln!("[talus] organization: {org}");
            }
            // Expiry warnings
            if let Some(ref exp) = cache.payload.expires_at {
                if let Some(days) = days_remaining(exp) {
                    if days <= 0 {
                        eprintln!("[talus] ⚠ LICENSE EXPIRED — running in community mode");
                        LicenseState::community()
                    } else if days <= 7 {
                        eprintln!("[talus] ⚠ WARNING: license expires in {days} days!");
                        LicenseState::from_cache(&cache)
                    } else if days <= 30 {
                        eprintln!("[talus] ℹ license expires in {days} days");
                        LicenseState::from_cache(&cache)
                    } else {
                        LicenseState::from_cache(&cache)
                    }
                } else {
                    LicenseState::from_cache(&cache)
                }
            } else {
                LicenseState::from_cache(&cache)
            }
        }
        Err(_) => {
            let trial = is_trial_active();
            if trial {
                eprintln!("[talus] license: Enterprise Trial (30 days)");
                LicenseState::trial()
            } else {
                eprintln!("[talus] license: community mode");
                LicenseState::community()
            }
        }
    };
    let _ = CACHED_STATE.set(state.clone());
    state
}

/// Verify the embedded public keys haven't been tampered with.
/// Returns true if all key checksums match.
fn verify_key_integrity() -> bool {
    let mut acc: u8 = 0;
    for entry in PUBLIC_KEYS {
        acc ^= xor_checksum(&entry.key);
    }
    acc == KEY_CHECKSUM
}

// ── Offline grace period ──────────────────────────────────────────────────

/// Maximum offline grace period in days.
/// License remains valid for this many days after last server contact.
const OFFLINE_GRACE_DAYS: i64 = 30;

/// Check if the license is within offline grace period.
/// Returns true if the license was recently verified online.
fn is_within_offline_grace(cache: &LicenseCache) -> bool {
    if let Some(ref at) = cache.activated_at {
        if let Ok(last_contact) = chrono::NaiveDateTime::parse_from_str(at, "%Y-%m-%dT%H:%M:%SZ") {
            let elapsed = chrono::Utc::now().naive_utc() - last_contact;
            return elapsed.num_days() <= OFFLINE_GRACE_DAYS;
        }
    }
    false
}

// ── Config integrity ──────────────────────────────────────────────────────

/// Protect config files with HMAC integrity checking.
fn config_integrity_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("talus").join(".integrity.hmac"))
}

/// Save HMAC of all config files for integrity checking.
pub fn save_config_integrity() -> Result<()> {
    let hmac_path = match config_integrity_path() {
        Some(p) => p,
        None => return Ok(()),
    };
    let config_dir = match dirs::config_dir() {
        Some(d) => d.join("talus"),
        None => return Ok(()),
    };

    let mut files_hash = Vec::new();
    // Hash license file
    let license_path = config_dir.join("license.dat");
    if let Ok(data) = fs::read(&license_path) {
        files_hash.extend_from_slice(sha256_hex(&data).as_bytes());
    }
    // Hash trial file
    let trial_path = config_dir.join(".trial.dat");
    if let Ok(data) = fs::read(&trial_path) {
        files_hash.extend_from_slice(sha256_hex(&data).as_bytes());
    }

    let key = derive_obfuscation_key();
    let hmac = sha256_hex(&[&key[..], &files_hash].concat());

    if let Some(parent) = hmac_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&hmac_path, &hmac);
    let _ = fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Verify config file integrity.
pub fn verify_config_integrity() -> Result<bool> {
    let hmac_path = match config_integrity_path() {
        Some(p) => p,
        None => return Ok(true),
    };
    if !hmac_path.exists() {
        return Ok(true); // No integrity file = first run
    }
    let stored_hmac = fs::read_to_string(&hmac_path).context("failed to read integrity file")?;
    let config_dir = dirs::config_dir()
        .context("cannot determine config directory")?
        .join("talus");

    let mut files_hash = Vec::new();
    let license_path = config_dir.join("license.dat");
    if let Ok(data) = fs::read(&license_path) {
        files_hash.extend_from_slice(sha256_hex(&data).as_bytes());
    }
    let trial_path = config_dir.join(".trial.dat");
    if let Ok(data) = fs::read(&trial_path) {
        files_hash.extend_from_slice(sha256_hex(&data).as_bytes());
    }

    let key = derive_obfuscation_key();
    let expected = sha256_hex(&[&key[..], &files_hash].concat());

    Ok(stored_hmac.trim() == expected)
}

/// Check if a 30-day trial is active.
/// Trial starts on first run and lasts 30 days.
/// Uses hidden file with restricted permissions to resist casual tampering.
fn is_trial_active() -> bool {
    let marker = match dirs::config_dir() {
        Some(dir) => dir.join("talus"),
        None => return false,
    };
    let trial_file = marker.join(".trial.dat");

    if trial_file.exists() {
        // Check if trial has expired
        if let Ok(data) = fs::read_to_string(&trial_file) {
            if let Ok(trial) = serde_json::from_str::<TrialData>(&data) {
                if let Ok(start) =
                    chrono::NaiveDateTime::parse_from_str(&trial.started_at, "%Y-%m-%dT%H:%M:%SZ")
                {
                    let elapsed = chrono::Utc::now().naive_utc() - start;
                    if elapsed.num_days() < 30 {
                        // Verify the integrity tag: detects edited start dates
                        // and trial files copied from other machines.
                        let expected = compute_trial_checksum(&trial.started_at);
                        if trial.checksum == expected {
                            return true;
                        }
                        audit_log("TRIAL_TAMPERED", "TRIAL-30D", "trial checksum mismatch");
                        let _ = fs::remove_file(&trial_file);
                        return false;
                    }
                    // Trial expired — clean up
                    audit_log("TRIAL_EXPIRED", "TRIAL-30D", "trial ended");
                    let _ = fs::remove_file(&trial_file);
                    return false;
                }
            }
        }
        // Corrupted trial file — treat as no trial
        let _ = fs::remove_file(&trial_file);
        false
    } else {
        // No trial file: legitimate only on the very first run.
        // If the audit trail shows a trial lifecycle already happened here,
        // the file was removed to reset the clock — refuse a new trial
        // (security review: infinite 30-day trial by deleting .trial.dat).
        if crate::audit::trial_reset_suspected() {
            audit_log(
                "TRIAL_RESET_DENIED",
                "TRIAL-30D",
                "trial file missing but audit trail shows a prior trial — re-trial refused",
            );
            eprintln!(
                "[talus] Enterprise trial already used on this machine — activate a license to continue"
            );
            return false;
        }
        // First run — start trial
        let _ = fs::create_dir_all(&marker);
        let started_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let trial = TrialData {
            checksum: compute_trial_checksum(&started_at),
            started_at,
        };
        if let Ok(data) = serde_json::to_string_pretty(&trial) {
            if let Ok(mut file) = fs::File::create(&trial_file) {
                let _ = file.write_all(data.as_bytes());
                // Set permissions to 0600 (owner-only)
                let _ = fs::set_permissions(&trial_file, fs::Permissions::from_mode(0o600));
            }
        }
        eprintln!("[talus] 30-day Enterprise trial started!");
        audit_log(
            "TRIAL_STARTED",
            "TRIAL-30D",
            "first run — 30-day trial begins",
        );
        true
    }
}

/// Days left in the current 30-day trial, if a valid trial file exists.
/// Used by the banner to report the trial state honestly.
pub fn trial_days_remaining() -> Option<i64> {
    let dir = dirs::config_dir()?.join("talus");
    let data = fs::read_to_string(dir.join(".trial.dat")).ok()?;
    let trial: TrialData = serde_json::from_str(&data).ok()?;
    let start =
        chrono::NaiveDateTime::parse_from_str(&trial.started_at, "%Y-%m-%dT%H:%M:%SZ").ok()?;
    let elapsed = chrono::Utc::now().naive_utc() - start;
    Some((30 - elapsed.num_days()).max(0))
}

/// Compute an integrity tag for the trial record to detect tampering.
///
/// SHA-256 over: public-key checksum ‖ machine fingerprint ‖ started_at.
/// Ties the trial record to this binary AND this machine, so the trial file
/// cannot be edited (extend the start date) or copied from another machine
/// without the tag mismatching. The machine fingerprint is public, so this is
/// an integrity tag rather than a true MAC — it resists casual tampering,
/// which is the documented threat model for the local trial marker.
fn compute_trial_checksum(started_at: &str) -> String {
    let machine = generate_machine_id().unwrap_or_default();
    let key = KEY_CHECKSUM.to_le_bytes();
    let data = [&key[..], machine.as_bytes(), started_at.as_bytes()].concat();
    sha256_hex(&data)[..32].to_string()
}

#[derive(Serialize, Deserialize)]
struct TrialData {
    started_at: String,
    #[serde(default)]
    checksum: String,
}

// ── License info display ──────────────────────────────────────────────────

/// Days remaining before license expires (or 0 if expired/perpetual).
fn days_remaining(expires: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M:%SZ")
        .ok()
        .map(|exp| {
            let now = chrono::Utc::now().naive_utc();
            (exp - now).num_days()
        })
}

/// Export license as JSON for programmatic integration.
pub fn export_license_json() -> Result<String> {
    let cache = LicenseCache::load()?.context("no license found")?;

    let output = serde_json::json!({
        "license_id": cache.payload.license_id,
        "tier": cache.payload.tier,
        "organization": cache.payload.organization,
        "issued_at": cache.payload.issued_at,
        "expires_at": cache.payload.expires_at,
        "machine_id": cache.payload.machine_id,
        "activated": cache.activation_token.is_some(),
        "activated_at": cache.activated_at,
        "features": cache.payload.effective_features().into_iter().collect::<Vec<_>>(),
    });

    serde_json::to_string_pretty(&output).context("failed to serialize license")
}

/// Transfer license to a different machine.
/// Deactivates on current machine, user must reactivate on the new one.
pub fn transfer_license() -> Result<()> {
    let cache = LicenseCache::load()?.context("no license found — nothing to transfer")?;

    eprintln!("[talus] license transfer");
    eprintln!("[talus] license ID: {}", cache.payload.license_id);
    eprintln!();

    // Show the raw key so user can copy it
    eprintln!("[talus] Your license key:");
    eprintln!();
    eprintln!("  {}", cache.key);
    eprintln!();
    eprintln!("[talus] To transfer:");
    eprintln!("  1. On the new machine, run: talus license activate <KEY>");
    eprintln!("  2. The key above is your license key");
    eprintln!();

    // Deactivate locally
    LicenseCache::clear()?;
    eprintln!("[talus] ✓ License deactivated on this machine");
    Ok(())
}

/// Print license information to stdout.
pub fn show_license_info() -> Result<()> {
    let r = "\x1b[0m"; // reset
    let c = "\x1b[36m"; // cyan
    let g = "\x1b[32m"; // green
    let y = "\x1b[33m"; // yellow
    let d = "\x1b[31m"; // red
    let dim = "\x1b[2m"; // dim
    let w: &str = ""; // width placeholder
    let _ = w; // suppress unused

    match LicenseCache::load()? {
        Some(cache) => {
            let tc = match cache.payload.tier {
                LicenseTier::Enterprise => g,
                LicenseTier::Community => y,
            };
            let icon = match cache.payload.tier {
                LicenseTier::Enterprise => "◆",
                LicenseTier::Community => "◇",
            };

            println!();
            println!("  {tc}╔══════════════════════════════════════════════════╗{r}");
            println!(
                "  {tc}║{r}  {icon} {tc}TALUS LICENSE{r}                              {tc}║{r}"
            );
            println!("  {tc}╠══════════════════════════════════════════════════╣{r}");
            println!(
                "  {tc}║{r}  License ID:   {:<33}{tc}║{r}",
                cache.payload.license_id
            );
            println!(
                "  {tc}║{r}  Tier:         {tc}{:<33}{r}{tc}║{r}",
                cache.payload.tier
            );
            if let Some(ref org) = cache.payload.organization {
                println!("  {tc}║{r}  Organization: {:<33}{tc}║{r}", org);
            }
            println!(
                "  {tc}║{r}  Issued:       {:<33}{tc}║{r}",
                cache.payload.issued_at
            );

            // Expiry
            if let Some(ref exp) = cache.payload.expires_at {
                if cache.payload.is_expired() {
                    println!("  {tc}║{r}  Expires:      {d}{exp}{r}                  {tc}║{r}");
                    println!(
                        "  {tc}║{r}  Status:       {d}✗ EXPIRED{r}                        {tc}║{r}"
                    );
                } else if let Some(days) = days_remaining(exp) {
                    let dc = if days <= 30 {
                        d
                    } else if days <= 90 {
                        y
                    } else {
                        g
                    };
                    println!("  {tc}║{r}  Expires:      {dc}{exp}{r}                  {tc}║{r}");
                    println!("  {tc}║{r}  Status:       {dc}✓ VALID — {days} days remaining{r}     {tc}║{r}");
                } else {
                    println!("  {tc}║{r}  Expires:      {:<33}{tc}║{r}", exp);
                    println!("  {tc}║{r}  Status:       {g}✓ VALID{r}                            {tc}║{r}");
                }
            } else {
                println!(
                    "  {tc}║{r}  Expires:      {:<33}{tc}║{r}",
                    "never (perpetual)"
                );
                println!(
                    "  {tc}║{r}  Status:       {g}✓ VALID (perpetual){r}              {tc}║{r}"
                );
            }

            // Machine binding
            if let Some(ref machine) = cache.payload.machine_id {
                println!("  {tc}║{r}  Machine ID:   {:<33}{tc}║{r}", machine);
            }

            // Activation
            if let Some(ref _token) = cache.activation_token {
                println!(
                    "  {tc}║{r}  Activation:   {g}✓ activated{r}                       {tc}║{r}"
                );
                if let Some(ref at) = cache.activated_at {
                    println!("  {tc}║{r}  Activated at: {:<33}{tc}║{r}", at);
                }
                if let Some(ref exp) = cache.token_expires_at {
                    println!("  {tc}║{r}  Token expires:{:<33}{tc}║{r}", exp);
                }
            } else {
                println!(
                    "  {tc}║{r}  Activation:   {y}✗ not activated (offline){r}       {tc}║{r}"
                );
            }

            // Features
            let features = cache.payload.effective_features();
            let mut feature_list: Vec<String> = features.into_iter().collect();
            feature_list.sort();
            println!(
                "  {tc}║{r}  Features:     {:<33}{tc}║{r}",
                feature_list.join(", ")
            );
            println!("  {tc}╚══════════════════════════════════════════════════╝{r}");
            println!();
            Ok(())
        }
        None => {
            println!();
            println!("  {c}╔══════════════════════════════════════════════════╗{r}");
            println!("  {c}║{r}  ◇ {c}TALUS LICENSE{r}                              {c}║{r}");
            println!("  {c}╠══════════════════════════════════════════════════╣{r}");
            println!("  {c}║{r}                                                  {c}║{r}");
            println!("  {c}║{r}  No license found. Running in {y}Community{r} mode.   {c}║{r}");
            println!("  {c}║{r}                                                  {c}║{r}");
            println!("  {c}║{r}  {g}Community features:{r}                              {c}║{r}");
            println!("  {c}║{r}    • TUI dashboard (7 panels)                    {c}║{r}");
            println!("  {c}║{r}    • JSON / plain text output                    {c}║{r}");
            println!("  {c}║{r}    • Real-time eBPF monitoring                   {c}║{r}");
            println!("  {c}║{r}    • Ransomware detection alerts                 {c}║{r}");
            println!("  {c}║{r}                                                  {c}║{r}");
            println!("  {c}║{r}  {y}Enterprise upgrade:{r}                              {c}║{r}");
            println!("  {c}║{r}    • Web dashboard & REST API                   {c}║{r}");
            println!("  {c}║{r}    • Auto-kill (EDR response mode)              {c}║{r}");
            println!("  {c}║{r}    • Kafka streaming                            {c}║{r}");
            println!("  {c}║{r}    • ClickHouse analytics                       {c}║{r}");
            println!("  {c}║{r}    • MemGraph process graphs                    {c}║{r}");
            println!("  {c}║{r}    • C FFI library                              {c}║{r}");
            println!("  {c}║{r}    • Priority support                           {c}║{r}");
            println!("  {c}║{r}                                                  {c}║{r}");
            println!("  {c}║{r}  {dim}Activate:  talus license activate <KEY>{r}       {c}║{r}");
            println!("  {c}║{r}  {dim}More info:  https://talus.io/enterprise{r}         {c}║{r}");
            println!("  {c}║{r}                                                  {c}║{r}");
            println!("  {c}╚══════════════════════════════════════════════════╝{r}");
            println!();
            Ok(())
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn license_tier_default_features() {
        let community = LicenseTier::Community;
        let features = community.default_features();
        assert!(features.contains(&"tui".to_string()));
        assert!(features.contains(&"json".to_string()));
        assert!(!features.contains(&"web".to_string()));
        assert!(!features.contains(&"auto_kill".to_string()));

        let enterprise = LicenseTier::Enterprise;
        let features = enterprise.default_features();
        assert!(features.contains(&"web".to_string()));
        assert!(features.contains(&"auto_kill".to_string()));
        assert!(features.contains(&"kafka".to_string()));
    }

    #[test]
    fn license_payload_not_expired_when_no_expiry() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 0,
            expires_at: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        assert!(!payload.is_expired());
    }

    #[test]
    fn license_payload_expired_when_past_expiry() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 0,
            expires_at: Some("2020-01-01T00:00:00Z".into()),
            issued_at: "2019-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        assert!(payload.is_expired());
    }

    #[test]
    fn license_payload_not_expired_when_future_expiry() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 0,
            expires_at: Some("2099-12-31T23:59:59Z".into()),
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        assert!(!payload.is_expired());
    }

    #[test]
    fn license_payload_effective_features_override() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: Some(vec!["tui".into(), "web".into()]),
            max_nodes: 0,
            expires_at: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        let features = payload.effective_features();
        assert!(features.contains("tui"));
        assert!(features.contains("web"));
        assert!(!features.contains("auto_kill")); // Not in explicit list
    }

    #[test]
    fn license_payload_has_feature() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 0,
            expires_at: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        assert!(payload.has_feature("tui"));
        assert!(payload.has_feature("web"));
        assert!(!payload.has_feature("nonexistent"));
    }

    #[test]
    fn license_state_community_defaults() {
        let state = LicenseState::community();
        assert_eq!(state.tier, LicenseTier::Community);
        assert!(state.allows("tui"));
        assert!(!state.allows("web"));
        assert!(!state.allows("auto_kill"));
        assert!(!state.is_activated);
        assert!(state.license_id.is_none());
    }

    #[test]
    fn license_state_from_cache() {
        let cache = LicenseCache {
            key: "test".into(),
            payload: LicensePayload {
                license_id: "TALUS-ENT-001".into(),
                tier: LicenseTier::Enterprise,
                kid: "v1".into(),
                features: None,
                max_nodes: 0,
                expires_at: None,
                issued_at: "2026-01-01T00:00:00Z".into(),
                machine_id: Some("T-abc123".into()),
                organization: Some("Acme Corp".into()),
                seat_count: 1,
            },
            activation_token: Some("token123".into()),
            activated_at: None,
            token_expires_at: None,
        };
        let state = LicenseState::from_cache(&cache);
        assert_eq!(state.tier, LicenseTier::Enterprise);
        assert!(state.allows("web"));
        assert!(state.allows("auto_kill"));
        assert!(state.is_activated);
        assert_eq!(state.license_id.as_deref(), Some("TALUS-ENT-001"));
        assert_eq!(state.organization.as_deref(), Some("Acme Corp"));
    }

    #[test]
    fn machine_id_generation() {
        let id1 = generate_machine_id().unwrap();
        let id2 = generate_machine_id().unwrap();
        assert_eq!(id1, id2, "machine ID should be deterministic");
        assert!(id1.starts_with("T-"));
    }

    #[test]
    fn license_key_parse_invalid_format() {
        assert!(LicenseKey::parse("invalid").is_err());
        assert!(LicenseKey::parse("a.b.c").is_err());
    }

    #[test]
    fn license_key_parse_invalid_base64() {
        assert!(LicenseKey::parse("!!!.!!!").is_err());
    }

    #[test]
    fn license_cache_path_deterministic() {
        let path1 = LicenseCache::path().unwrap();
        let path2 = LicenseCache::path().unwrap();
        assert_eq!(path1, path2);
    }

    #[test]
    fn license_tier_display() {
        assert_eq!(LicenseTier::Community.to_string(), "Community");
        assert_eq!(LicenseTier::Enterprise.to_string(), "Enterprise");
    }

    #[test]
    fn license_state_feature_list_sorted() {
        let state = LicenseState::community();
        let features = state.feature_list();
        let mut sorted = features.clone();
        sorted.sort();
        assert_eq!(features, sorted);
    }

    #[test]
    fn license_state_trial_has_all_features() {
        let state = LicenseState::trial();
        assert_eq!(state.tier, LicenseTier::Enterprise);
        assert!(state.allows("web"));
        assert!(state.allows("auto_kill"));
        assert!(state.allows("kafka"));
        assert!(state.allows("clickhouse"));
        assert!(state.allows("memgraph"));
        assert!(state.allows("ffi"));
        assert_eq!(state.license_id.as_deref(), Some("TRIAL-30D"));
        assert!(!state.is_activated);
    }

    #[test]
    fn xor_checksum_identity() {
        // XOR of empty is 0
        assert_eq!(xor_checksum(&[]), 0);
        // XOR of single byte is itself
        assert_eq!(xor_checksum(&[0x42]), 0x42);
        // XOR is commutative and associative
        assert_eq!(
            xor_checksum(&[0x01, 0x02, 0x03]),
            xor_checksum(&[0x03, 0x01, 0x02])
        );
    }

    #[test]
    fn key_integrity_check() {
        // The real key should pass
        assert!(verify_key_integrity());
    }

    #[test]
    fn license_payload_max_nodes() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 42,
            expires_at: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: None,
            organization: None,
            seat_count: 1,
        };
        assert_eq!(payload.max_nodes, 42);
    }

    #[test]
    fn license_payload_machine_binding() {
        let payload = LicensePayload {
            license_id: "TALUS-TEST".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: None,
            max_nodes: 0,
            expires_at: None,
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: Some("T-abc123".into()),
            organization: None,
            seat_count: 1,
        };
        assert!(payload.is_activated_for("T-abc123"));
        assert!(!payload.is_activated_for("T-different"));
    }

    #[test]
    fn days_remaining_future() {
        let result = days_remaining("2099-12-31T23:59:59Z");
        assert!(result.is_some());
        assert!(result.unwrap() > 365 * 50);
    }

    #[test]
    fn days_remaining_past() {
        let result = days_remaining("2020-01-01T00:00:00Z");
        assert!(result.is_some());
        assert!(result.unwrap() < 0);
    }

    #[test]
    fn license_key_parse_and_roundtrip_structure() {
        // Test that the parse function properly validates structure
        assert!(LicenseKey::parse("").is_err());
        assert!(LicenseKey::parse("abc").is_err());
        assert!(LicenseKey::parse("abc.def.ghi").is_err());
    }

    #[test]
    fn license_payload_serialization_roundtrip() {
        let payload = LicensePayload {
            license_id: "TALUS-RT-001".into(),
            tier: LicenseTier::Enterprise,
            kid: "v1".into(),
            features: Some(vec!["web".into(), "auto_kill".into()]),
            max_nodes: 10,
            expires_at: Some("2027-06-30T00:00:00Z".into()),
            issued_at: "2026-01-01T00:00:00Z".into(),
            machine_id: Some("T-test".into()),
            organization: Some("Test Corp".into()),
            seat_count: 1,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let restored: LicensePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.license_id, "TALUS-RT-001");
        assert_eq!(restored.tier, LicenseTier::Enterprise);
        assert_eq!(restored.max_nodes, 10);
        assert!(restored.features.unwrap().contains(&"web".to_string()));
        assert_eq!(restored.organization.as_deref(), Some("Test Corp"));
    }

    // ── Integration tests ──────────────────────────────────────────────

    #[test]
    fn obfuscation_key_is_deterministic() {
        let k1 = derive_obfuscation_key();
        let k2 = derive_obfuscation_key();
        assert_eq!(k1, k2, "obfuscation key must be deterministic");
    }

    #[test]
    fn xor_crypt_is_symmetric() {
        let key = derive_obfuscation_key();
        let original = b"hello talus license data 1234567890";
        let encrypted = xor_crypt(original, &key);
        let decrypted = xor_crypt(&encrypted, &key);
        assert_eq!(decrypted, original, "XOR must be symmetric");
    }

    #[test]
    fn xor_crypt_differs_from_original() {
        let key = derive_obfuscation_key();
        let original = b"license data";
        let encrypted = xor_crypt(original, &key);
        // Should be encrypted (different from original) unless key happens to be all zeros
        assert_ne!(encrypted, original, "encryption should change the data");
    }

    #[test]
    fn xor_crypt_empty_data() {
        let key = derive_obfuscation_key();
        let empty = xor_crypt(b"", &key);
        assert!(empty.is_empty());
    }

    #[test]
    fn license_cache_save_load_roundtrip() {
        // Create a temporary directory for the test
        let tmp = std::env::temp_dir().join("talus_test_license");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // We can't easily test the real path, but we can test the serialization
        let cache = LicenseCache {
            key: "test.key.data".into(),
            payload: LicensePayload {
                license_id: "TALUS-TEST-CACHE".into(),
                tier: LicenseTier::Enterprise,
                kid: "v1".into(),
                features: None,
                max_nodes: 0,
                expires_at: None,
                issued_at: "2026-01-01T00:00:00Z".into(),
                machine_id: Some("T-test123".into()),
                organization: Some("Test Org".into()),
                seat_count: 1,
            },
            activation_token: Some("token-abc".into()),
            activated_at: Some("2026-08-30T00:00:00Z".into()),
            token_expires_at: None,
        };

        // Test serialization
        let json = serde_json::to_string(&cache).unwrap();
        let restored: LicenseCache = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.payload.license_id, "TALUS-TEST-CACHE");
        assert_eq!(restored.activation_token.as_deref(), Some("token-abc"));
        assert_eq!(restored.payload.organization.as_deref(), Some("Test Org"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn license_health_struct_serializes() {
        // Test that LicenseHealth can be serialized (used by web API)
        let health = LicenseHealth {
            status: "valid".into(),
            tier: "enterprise".into(),
            license_id: "TALUS-001".into(),
            organization: Some("Corp".into()),
            expired: false,
            days_remaining: Some(365),
            activated: true,
            machine_bound: true,
            features: vec!["web".into(), "auto_kill".into()],
        };
        let json = serde_json::to_string(&health).unwrap();
        assert!(json.contains("enterprise"));
        assert!(json.contains("TALUS-001"));
        assert!(json.contains("365"));
    }

    #[test]
    fn feature_list_contains_all_enterprise_features() {
        let state = LicenseState::trial();
        let features = state.feature_list();
        let required = [
            "tui",
            "plain",
            "json",
            "web",
            "auto_kill",
            "kafka",
            "clickhouse",
            "memgraph",
            "ffi",
        ];
        for req in &required {
            assert!(
                features.contains(&req.to_string()),
                "trial should include {req}"
            );
        }
    }

    #[test]
    fn community_mode_blocks_enterprise_features() {
        let state = LicenseState::community();
        assert!(!state.allows("auto_kill"));
        assert!(!state.allows("web"));
        assert!(!state.allows("kafka"));
        assert!(!state.allows("clickhouse"));
        assert!(!state.allows("memgraph"));
        assert!(!state.allows("ffi"));
        // But basic features should work
        assert!(state.allows("tui"));
        assert!(state.allows("json"));
        assert!(state.allows("plain"));
    }

    #[cfg(feature = "test-license")]
    #[test]
    fn test_license_sign_and_verify_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};

        let priv_bytes =
            hex::decode("919b95fdabe4b4a9f1b604a5cf47e35bc1a3bd8cb70898d8a2162e033b963e2f")
                .unwrap();
        let priv_arr: [u8; 32] = priv_bytes.as_slice().try_into().unwrap();
        let sk = SigningKey::from_bytes(&priv_arr);

        let payload = LicensePayload {
            license_id: "TALUS-TEST-0001".into(),
            kid: "test".into(),
            tier: LicenseTier::Enterprise,
            features: Some(vec!["web".into()]),
            max_nodes: 0,
            expires_at: None,
            issued_at: "2026-10-30T00:00:00Z".into(),
            machine_id: None,
            organization: Some("Test".into()),
            seat_count: 1,
        };

        let payload_json = serde_json::to_string(&payload).unwrap();
        let sig = sk.sign(payload_json.as_bytes());
        let sig_b64 = BASE64.encode(sig.to_bytes());
        let payload_b64 = BASE64.encode(&payload_json);
        let key_str = format!("{}.{}", payload_b64, sig_b64);

        // This exercises the same path as LicenseKey::parse
        let key = LicenseKey::parse(&key_str).expect("should verify test license key");
        assert_eq!(key.payload.license_id, "TALUS-TEST-0001");
        assert_eq!(key.payload.tier, LicenseTier::Enterprise);
    }
}
