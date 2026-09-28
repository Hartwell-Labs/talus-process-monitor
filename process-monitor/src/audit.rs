// ── audit.rs — Signed audit log with hash chain ──────────────────────────
//
// Enterprise-grade audit logging:
// - Each entry is SHA-256 hashed with machine-derived key
// - Hash chain links entries (tamper detection)
// - Entries stored as JSON lines with entry_hash + prev_hash
// - Verification function checks entire chain integrity
//
// Compliance: SOC2 Type II, ISO 27001 audit trail requirements.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Cross-process locking (concurrency fix) ─────────────────────────────
//
// audit_log() implements read-last-line → compute-hash → append → anchor.
// Without a cross-process lock, two concurrent writers (e.g. monitor +
// license CLI, parallel test binaries) read the SAME prev_hash and append
// interleaved entries → the chain reads as corrupted afterwards. A flock-ed
// `audit.log.lock` next to the log serializes the critical section;
// verification takes the lock shared so it never observes a torn append.

extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_SH: i32 = 1;
const LOCK_UN: i32 = 8;

/// RAII guard holding a lock on the audit lock file.
struct AuditFileLock {
    file: fs::File,
}

impl AuditFileLock {
    fn acquire(path: &PathBuf, operation: i32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
            .with_context(|| format!("open lock file {}", path.display()))?;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        // flock blocks until the lock is free; a failure to lock is fatal —
        // appending unlocked is exactly the bug being fixed (fail-closed).
        let rc = unsafe { flock(fd, operation) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "flock failed on {} (io error)",
                path.display()
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for AuditFileLock {
    fn drop(&mut self) {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&self.file);
        unsafe { flock(fd, LOCK_UN) };
    }
}

fn audit_lock_path(log_path: &Path) -> PathBuf {
    let mut p = log_path.to_path_buf().into_os_string();
    p.push(".lock");
    PathBuf::from(p)
}

/// A single signed audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 timestamp.
    pub ts: String,
    /// User ID that performed the action.
    pub uid: u32,
    /// Hostname of the machine.
    pub host: String,
    /// Event type (ACTIVATED, DEACTIVATED, EXPIRED, etc.).
    pub event: String,
    /// License ID involved.
    pub license_id: String,
    /// Human-readable detail.
    pub detail: String,
    /// SHA-256 hash of the previous entry (hash chain).
    pub prev_hash: String,
    /// HMAC-SHA256 of this entry (tamper detection).
    pub entry_hash: String,
}

impl AuditEntry {
    /// Compute HMAC for this entry under the given key.
    fn compute_hash_with(&self, key: &[u8; 32], prev_hash: &str) -> String {
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.ts, self.uid, self.host, self.event, self.license_id, self.detail, prev_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(payload.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Compute HMAC for this entry using the current (stable) audit key.
    fn compute_hash(&self, prev_hash: &str) -> String {
        self.compute_hash_with(&audit_hmac_key(), prev_hash)
    }

    /// True if the entry hash verifies under ANY known key (stable or legacy).
    fn verifies_under_known_key(&self, prev_hash: &str) -> bool {
        audit_verify_keys()
            .iter()
            .any(|k| self.entry_hash == self.compute_hash_with(k, prev_hash))
    }
}

/// Derive the *legacy* audit key from machine fingerprint.
///
/// KEPT FOR VERIFICATION FALLBACK ONLY (security hardening review): entries written
/// before the stable key file existed verify under this key. The fingerprint
/// (hostname + MACs) is volatile — a NIC change used to invalidate the entire
/// audit history — and public (it is printed by `license machine-id`), so this
/// derivation is no longer used for new writes.
fn derive_audit_key() -> [u8; 32] {
    let machine = crate::license::generate_machine_id().unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(b"talus-audit-v1");
    hasher.update(machine.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Path of the stable audit key file (created once, 0600).
fn audit_key_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("talus").join(".audit.key"))
}

/// Load the stable audit HMAC key, creating it on first use.
///
/// The key is a random 32-byte value persisted outside the log, so the audit
/// MAC does not depend on the volatile machine fingerprint (MAC/hostname
/// changes used to make every historical entry verify as corrupted).
/// Threat model unchanged and documented: user-level storage, resists casual
/// tampering; a user who reads this file can forge entries — same trust level
/// as the previous machine-derived key, which was publicly recomputable.
fn audit_hmac_key() -> [u8; 32] {
    let path = match audit_key_path() {
        Some(p) => p,
        None => return derive_audit_key(), // no config dir: legacy behavior
    };
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(key) = hex::decode(data.trim()) {
            if key.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                return k;
            }
        }
    }
    // First run (or damaged file): create a fresh random key.
    let mut key = [0u8; 32];
    match fs::File::open("/dev/urandom") {
        Ok(mut f) => {
            use std::io::Read;
            if f.read_exact(&mut key).is_err() {
                key = derive_audit_key(); // last-resort fallback
            }
        }
        Err(_) => key = derive_audit_key(),
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, hex::encode(key));
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    key
}

/// Keys to try when verifying an entry, in order: stable key first,
/// then the legacy machine-derived key (for pre-stable-key entries).
fn audit_verify_keys() -> Vec<[u8; 32]> {
    vec![audit_hmac_key(), derive_audit_key()]
}

/// Get the audit log file path.
fn audit_log_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("talus").join("audit.log"))
}

/// Path of the hidden length-anchor file for the audit log.
///
/// The hash chain alone only detects *modification* and *append-forgery*;
/// a truncated (or fully deleted) log verifies as VALID because every
/// remaining prefix is internally consistent. The anchor binds the last
/// entry hash and the entry count outside the log file, so truncation
/// breaks verification.
fn anchor_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("talus").join(".audit.anchor"))
}

/// MAC over (last entry hash, entry count) under an explicit key.
fn anchor_mac_with(key: &[u8; 32], last_hash: &str, count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(b"talus-audit-anchor-v1");
    hasher.update(last_hash.as_bytes());
    hasher.update(count.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// MAC over (last entry hash, entry count) using the current audit key.
fn anchor_mac(last_hash: &str, count: u64) -> String {
    anchor_mac_with(&audit_hmac_key(), last_hash, count)
}

/// Persist the length anchor after appending an entry.
fn write_anchor(last_hash: &str, count: u64) {
    if let Some(path) = anchor_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let line = format!("{last_hash}|{count}|{}", anchor_mac(last_hash, count));
        if fs::write(&path, line).is_ok() {
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
    }
}

/// Read and authenticate the length anchor. Returns (last_hash, count).
/// Returns None if missing, malformed, or MAC-invalid (treated as absent).
fn read_anchor() -> Option<(String, u64)> {
    let path = anchor_path()?;
    let data = fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = data.trim().split('|').collect();
    if parts.len() != 3 {
        return None;
    }
    let count: u64 = parts[1].parse().ok()?;
    // Anchors written before the stable key existed use the legacy key.
    let valid = audit_verify_keys()
        .iter()
        .any(|k| anchor_mac_with(k, parts[0], count) == parts[2]);
    if !valid {
        return None;
    }
    Some((parts[0].to_string(), count))
}

/// Heuristic evidence that a trial is being restarted on this machine.
///
/// Used to refuse a second 30-day trial (security hardening review finding):
/// - the audit log already records a trial lifecycle (TRIAL_STARTED /
///   TRIAL_EXPIRED), i.e. the trial file was removed to reset the clock;
/// - or the log/anchor pair shows the log was truncated or deleted
///   (possible evidence destruction before a re-trial).
///
/// Residual risk (documented): a user removing audit.log, .audit.anchor and
/// .trial.dat together on a machine that never contacted the license server
/// leaves no trace. Server-side trial tracking (license-server keyed by
/// machine_id) closes this for online installs.
pub fn trial_reset_suspected() -> bool {
    let log_path = match audit_log_path() {
        Some(p) => p,
        None => return false,
    };
    if !log_path.exists() {
        // Log deleted while the anchor still records entries.
        return matches!(read_anchor(), Some((_, c)) if c > 0);
    }
    let data = fs::read_to_string(&log_path).unwrap_or_default();
    if data.contains("\"event\":\"TRIAL_STARTED\"")
        || data.contains("\"event\":\"TRIAL_EXPIRED\"")
    {
        return true;
    }
    match read_anchor() {
        Some((_, c)) => {
            c > 0
                && data.lines().filter(|l| !l.trim().is_empty()).count() < c as usize
        }
        None => false,
    }
}

/// Append a signed entry to the audit log with hash chain.
pub fn audit_log(event: &str, license_id: &str, detail: &str) {
    let log_path = match audit_log_path() {
        Some(p) => p,
        None => return,
    };

    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Serialize the read-tail → append → anchor critical section across
    // processes. Lock file is stable, separate from the log, so anchor/log
    // file replacement never affects lock identity. Underscore-prefixed
    // binding: the guard must live until the end of the critical section.
    let _audit_lock = match AuditFileLock::acquire(&audit_lock_path(&log_path), LOCK_EX) {
        Ok(l) => l,
        Err(_) => {
            // Failing to acquire the lock means we cannot guarantee chain
            // integrity — refuse to append rather than corrupt silently.
            eprintln!("[talus] audit: cannot lock audit log — entry not recorded (fail-closed)");
            return;
        }
    };

    // Get previous hash and current entry count from the log
    let log_data = fs::read_to_string(&log_path).ok();
    let prev_hash = log_data
        .as_deref()
        .and_then(|data| {
            data.lines().last().and_then(|line| {
                serde_json::from_str::<AuditEntry>(line)
                    .ok()
                    .map(|e| e.entry_hash)
            })
        })
        .unwrap_or_else(|| "0".to_string());
    let prev_count = log_data
        .as_deref()
        .map(|data| {
            data.lines().filter(|l| !l.trim().is_empty()).count() as u64
        })
        .unwrap_or(0);

    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());
    // SAFETY: getuid() is a simple syscall.
    let uid = unsafe { libc::getuid() };

    let mut entry = AuditEntry {
        ts,
        uid,
        host: hostname,
        event: event.to_string(),
        license_id: license_id.to_string(),
        detail: detail.to_string(),
        prev_hash,
        entry_hash: String::new(),
    };
    entry.entry_hash = entry.compute_hash(&entry.prev_hash);

    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = writeln!(file, "{json}");
        }
        let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
        // Refresh the length anchor so truncation becomes detectable.
        write_anchor(&entry.entry_hash, prev_count + 1);
    }
}

/// Verify the integrity of the entire audit log (hash chain).
/// Returns the number of verified entries, or an error if any entry is corrupted.
pub fn verify_audit_log() -> Result<u64> {
    let log_path = audit_log_path().context("cannot determine audit log path")?;

    if !log_path.exists() {
        // A missing log is only legitimate when no entries were ever recorded.
        // An existing anchor for a non-empty state means the log was deleted.
        return match read_anchor() {
            None => Ok(0),
            Some((h, c)) if h == "0" && c == 0 => Ok(0),
            Some((h, c)) => bail!(
                "audit log is missing but length anchor records {c} entries (last: {h}) — log was deleted"
            ),
        };
    }

    // Shared lock for the whole verification pass: concurrent writers block
    // until verification finishes, so the chain/anchor are never read
    // mid-append. Waiting writers then chain onto the fresh tail.
    let _lock = AuditFileLock::acquire(&audit_lock_path(&log_path), LOCK_SH)
        .context("cannot lock audit log for verification (fail-closed)")?;

    let data = fs::read_to_string(&log_path).context("failed to read audit log")?;

    let mut prev_hash = "0".to_string();
    let mut verified = 0u64;
    let mut corrupted = 0u64;

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => {
                // Verify hash chain
                if entry.prev_hash != prev_hash {
                    corrupted += 1;
                    continue;
                }
                // Verify entry hash under any known key (stable first, then
                // legacy machine-derived for pre-stable-key entries).
                if !entry.verifies_under_known_key(&prev_hash) {
                    corrupted += 1;
                    continue;
                }
                prev_hash = entry.entry_hash;
                verified += 1;
            }
            Err(_) => {
                corrupted += 1;
            }
        }
    }

    if corrupted > 0 {
        bail!(
            "audit log integrity check failed: {corrupted} corrupted entries out of {}",
            verified + corrupted
        );
    }

    // Length anchor check: the chain above validates the *content* of the
    // remaining entries; this validates their *number* against the state
    // recorded outside the log file at last append.
    let last_hash = if verified > 0 {
        prev_hash.clone()
    } else {
        "0".to_string()
    };
    match read_anchor() {
        Some((anchor_hash, anchor_count)) => {
            if anchor_hash != last_hash || anchor_count != verified {
                bail!(
                    "audit log length anchor mismatch: log ends at {last_hash} ({verified} entries), anchor records {anchor_hash} ({anchor_count} entries) — log may have been truncated or rewritten"
                );
            }
        }
        None => {
            // Legacy install (pre-anchor log) or first run: establish the
            // anchor at the current state. From this point on, any further
            // truncation or deletion is detected.
            write_anchor(&last_hash, verified);
        }
    }

    Ok(verified)
}

/// Read the last N entries from the audit log.
pub fn read_audit_log(max_entries: usize) -> Vec<String> {
    let log_path = match audit_log_path() {
        Some(p) => p,
        None => return Vec::new(),
    };

    fs::read_to_string(&log_path)
        .ok()
        .map(|data| {
            data.lines()
                .rev()
                .take(max_entries)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_key_is_deterministic() {
        let k1 = derive_audit_key();
        let k2 = derive_audit_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn anchor_mac_binds_hash_and_count() {
        let a = anchor_mac("hash1", 5);
        assert_eq!(a, anchor_mac("hash1", 5), "deterministic");
        assert_eq!(a.len(), 64);
        assert_ne!(a, anchor_mac("hash2", 5), "binds last hash");
        assert_ne!(a, anchor_mac("hash1", 6), "binds count");
    }

    #[test]
    fn audit_entry_hash_deterministic() {
        let entry = AuditEntry {
            ts: "2026-01-01T00:00:00Z".into(),
            uid: 0,
            host: "test".into(),
            event: "TEST".into(),
            license_id: "TALUS-001".into(),
            detail: "test detail".into(),
            prev_hash: "0".into(),
            entry_hash: String::new(),
        };
        let h1 = entry.compute_hash("0");
        let h2 = entry.compute_hash("0");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn audit_entry_hash_depends_on_prev() {
        let entry = AuditEntry {
            ts: "2026-01-01T00:00:00Z".into(),
            uid: 0,
            host: "test".into(),
            event: "TEST".into(),
            license_id: "TALUS-001".into(),
            detail: "test detail".into(),
            prev_hash: "0".into(),
            entry_hash: String::new(),
        };
        let h1 = entry.compute_hash("aaa");
        let h2 = entry.compute_hash("bbb");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_chain_end_to_end() {
        // Build a 3-entry chain manually and verify
        let _key = derive_audit_key();

        let entry1 = AuditEntry {
            ts: "2026-01-01T00:00:00Z".into(),
            uid: 0,
            host: "host1".into(),
            event: "ACTIVATED".into(),
            license_id: "TALUS-001".into(),
            detail: "machine=T-abc".into(),
            prev_hash: "0".into(),
            entry_hash: String::new(),
        };
        let h1 = entry1.compute_hash("0");

        let entry2 = AuditEntry {
            ts: "2026-01-01T00:01:00Z".into(),
            uid: 0,
            host: "host1".into(),
            event: "EXPIRED".into(),
            license_id: "TALUS-001".into(),
            detail: "license expired".into(),
            prev_hash: h1.clone(),
            entry_hash: String::new(),
        };
        let h2 = entry2.compute_hash(&h1);

        let entry3 = AuditEntry {
            ts: "2026-01-01T00:02:00Z".into(),
            uid: 0,
            host: "host1".into(),
            event: "DEACTIVATED".into(),
            license_id: "TALUS-001".into(),
            detail: "user deactivation".into(),
            prev_hash: h2.clone(),
            entry_hash: String::new(),
        };
        let h3 = entry3.compute_hash(&h2);

        // Verify chain: each prev_hash must match the previous entry_hash
        assert_eq!(entry1.prev_hash, "0");
        assert_eq!(entry2.prev_hash, h1);
        assert_eq!(entry3.prev_hash, h2);

        // Verify each entry's hash is correct
        assert_eq!(h1, entry1.compute_hash("0"));
        assert_eq!(h2, entry2.compute_hash(&h1));
        assert_eq!(h3, entry3.compute_hash(&h2));

        // Tamper detection: change entry2 detail → hash breaks
        let mut tampered = entry2.clone();
        tampered.detail = "TAMPERED".into();
        let h2_tampered = tampered.compute_hash(&h1);
        assert_ne!(
            h2_tampered, h2,
            "tampered entry must produce different hash"
        );

        // Chain break: entry3.prev_hash no longer matches
        assert_ne!(entry3.prev_hash, h2_tampered);
    }

    #[test]
    fn audit_log_write_and_verify() {
        // Write 3 entries to a temp file, then verify the chain
        let tmp_dir = std::env::temp_dir().join("talus_audit_test");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let log_path = tmp_dir.join("audit.log");

        // Write 3 entries
        for i in 0..3 {
            let prev_hash = if i == 0 {
                "0".to_string()
            } else {
                let data = fs::read_to_string(&log_path).unwrap();
                let last_line = data.lines().last().unwrap();
                let entry: AuditEntry = serde_json::from_str(last_line).unwrap();
                entry.entry_hash
            };

            let mut entry = AuditEntry {
                ts: format!("2026-01-01T00:0{i}:00Z"),
                uid: 1000,
                host: "test-host".into(),
                event: format!("TEST_{i}"),
                license_id: "TALUS-TEST".into(),
                detail: format!("entry {i}"),
                prev_hash,
                entry_hash: String::new(),
            };
            entry.entry_hash = entry.compute_hash(&entry.prev_hash);

            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }

        // Verify the chain
        let data = fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = data.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 3);

        let mut prev_hash = "0".to_string();
        let mut verified = 0u64;
        for line in &lines {
            let entry: AuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(entry.prev_hash, prev_hash, "chain break at entry");
            let expected = entry.compute_hash(&prev_hash);
            assert_eq!(entry.entry_hash, expected, "hash mismatch at entry");
            prev_hash = entry.entry_hash;
            verified += 1;
        }
        assert_eq!(verified, 3);

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn audit_log_detects_tampering() {
        let tmp_dir = std::env::temp_dir().join("talus_audit_tamper_test");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();
        let log_path = tmp_dir.join("audit.log");

        // Write 2 entries
        for i in 0..2 {
            let prev_hash = if i == 0 {
                "0".to_string()
            } else {
                let data = fs::read_to_string(&log_path).unwrap();
                let last_line = data.lines().last().unwrap();
                let entry: AuditEntry = serde_json::from_str(last_line).unwrap();
                entry.entry_hash
            };
            let mut entry = AuditEntry {
                ts: format!("2026-01-01T00:0{i}:00Z"),
                uid: 1000,
                host: "test-host".into(),
                event: format!("TEST_{i}"),
                license_id: "TALUS-TEST".into(),
                detail: format!("entry {i}"),
                prev_hash,
                entry_hash: String::new(),
            };
            entry.entry_hash = entry.compute_hash(&entry.prev_hash);
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(file, "{}", serde_json::to_string(&entry).unwrap()).unwrap();
        }

        // Tamper with entry 1 (change detail)
        let data = fs::read_to_string(&log_path).unwrap();
        let mut lines: Vec<String> = data.lines().map(String::from).collect();
        let mut entry1: AuditEntry = serde_json::from_str(&lines[1]).unwrap();
        entry1.detail = "HACKED".into();
        lines[1] = serde_json::to_string(&entry1).unwrap();
        fs::write(&log_path, lines.join("\n") + "\n").unwrap();

        // Verify should fail
        let data = fs::read_to_string(&log_path).unwrap();
        let mut prev_hash = "0".to_string();
        let mut corrupted = 0u64;
        for line in data.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(line).unwrap();
            if entry.prev_hash != prev_hash {
                corrupted += 1;
                continue;
            }
            let expected = entry.compute_hash(&prev_hash);
            if entry.entry_hash != expected {
                corrupted += 1;
                continue;
            }
            prev_hash = entry.entry_hash;
        }
        assert!(corrupted > 0, "tampering should be detected");

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}

#[cfg(test)]
mod flock_stress_tests {
    use super::*;

    /// Concurrent writers: 4 threads append interleaved entries through the
    /// real flock-ed critical section; afterwards the chain must verify
    /// 100% (without the lock this test reliably produces a corrupted chain).
    #[test]
    fn concurrent_writers_chain_stays_valid() {
        let n_before = verify_audit_log().unwrap_or(0);

        let handles: Vec<_> = (0..4)
            .map(|w| {
                std::thread::spawn(move || {
                    for i in 0..15 {
                        audit_log("FLOCK_STRESS", "-", &format!("writer={w} iter={i}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("writer thread panicked");
        }

        let n_after = verify_audit_log().expect("chain corrupted after concurrent writes!");
        assert!(
            n_after >= n_before + 60,
            "expected >= 60 new entries, got {n_after} (before: {n_before})"
        );
    }
}
