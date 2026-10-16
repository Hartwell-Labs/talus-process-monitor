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
use std::sync::OnceLock;

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
    #[cfg(not(miri))]
    fn flock(fd: i32, operation: i32) -> i32;
}
const LOCK_EX: i32 = 2;
const LOCK_SH: i32 = 1;
const LOCK_UN: i32 = 8;

/// `flock(2)` wrapper.
///
/// Miri cannot model `flock`, so under the interpreter locking degrades to a
/// no-op. Miri runs single-threaded for this crate's tests, so skipping the
/// lock is safe there; the real cross-process locking is exercised on the
/// normal (non-miri) test runs.
#[cfg(not(miri))]
fn raw_flock(fd: i32, operation: i32) -> i32 {
    unsafe { flock(fd, operation) }
}

#[cfg(miri)]
fn raw_flock(_fd: i32, _operation: i32) -> i32 {
    0
}

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
        let rc = raw_flock(fd, operation);
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
        raw_flock(fd, LOCK_UN);
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
    config_base().map(|d| d.join("talus").join(".audit.key"))
}

/// Load the stable audit HMAC key, creating it on first use.
///
/// The key is a random 32-byte value persisted outside the log, so the audit
/// MAC does not depend on the volatile machine fingerprint (MAC/hostname
/// changes used to make every historical entry verify as corrupted).
/// Threat model unchanged and documented: user-level storage, resists casual
/// tampering; a user who reads this file can forge entries — same trust level
/// as the previous machine-derived key, which was publicly recomputable.
///
/// The result is cached process-wide via [`OnceLock`]. Concurrent callers
/// (parallel tests, threads appending entries) that raced on first use could
/// otherwise each persist a *different* random key, splitting the log across
/// keys and making every entry signed under a losing key verify as tampered.
fn audit_hmac_key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(load_or_create_audit_key)
}

/// Read and validate a 32-byte hex-encoded key from `path`, if present.
fn read_key_file(path: &Path) -> Option<[u8; 32]> {
    let data = fs::read_to_string(path).ok()?;
    let decoded = hex::decode(data.trim()).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Some(key)
}

/// Generate a fresh random 32-byte key, falling back to the legacy
/// machine-derived key if the entropy source is unavailable.
fn generate_audit_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    match fs::File::open("/dev/urandom") {
        Ok(mut f) => {
            use std::io::Read;
            if f.read_exact(&mut key).is_err() {
                return derive_audit_key(); // last-resort fallback
            }
        }
        Err(_) => return derive_audit_key(),
    }
    key
}

/// Load the persisted key, or create it exactly once.
fn load_or_create_audit_key() -> [u8; 32] {
    let path = match audit_key_path() {
        Some(p) => p,
        None => return derive_audit_key(), // no config dir: legacy behavior
    };
    if let Some(key) = read_key_file(&path) {
        return key;
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // Create exclusively so exactly one writer wins the race; everyone else
    // adopts the winner's key instead of overwriting it with their own.
    let key = generate_audit_key();
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => {
            let _ = f.write_all(hex::encode(key).as_bytes());
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            key
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created it first: adopt its key once readable.
            for _ in 0..10 {
                if let Some(existing) = read_key_file(&path) {
                    return existing;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            key
        }
        Err(_) => key,
    }
}

/// Keys to try when verifying an entry, in order: stable key first,
/// then the legacy machine-derived key (for pre-stable-key entries).
fn audit_verify_keys() -> Vec<[u8; 32]> {
    vec![audit_hmac_key(), derive_audit_key()]
}

/// Base directory for talus state (audit log, key, anchor).
///
/// Honours `TALUS_CONFIG_DIR` so tests can run against a temporary directory
/// instead of the invoking user's real `~/.config/talus`. Without this the
/// audit tests wrote into the live audit log — a test failure reported 300+
/// `FLOCK_STRESS` entries as if they were production events, and the test
/// failed on any machine whose log predates the stable HMAC key, for reasons
/// that had nothing to do with the code under test.
fn config_base() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("TALUS_CONFIG_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    dirs::config_dir()
}

/// Get the audit log file path.
fn audit_log_path() -> Option<PathBuf> {
    config_base().map(|d| d.join("talus").join("audit.log"))
}

/// Path of the hidden length-anchor file for the audit log.
///
/// The hash chain alone only detects *modification* and *append-forgery*;
/// a truncated (or fully deleted) log verifies as VALID because every
/// remaining prefix is internally consistent. The anchor binds the last
/// entry hash and the entry count outside the log file, so truncation
/// breaks verification.
fn anchor_path() -> Option<PathBuf> {
    config_base().map(|d| d.join("talus").join(".audit.anchor"))
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
    if data.contains("\"event\":\"TRIAL_STARTED\"") || data.contains("\"event\":\"TRIAL_EXPIRED\"")
    {
        return true;
    }
    match read_anchor() {
        Some((_, c)) => c > 0 && data.lines().filter(|l| !l.trim().is_empty()).count() < c as usize,
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
        .map(|data| data.lines().filter(|l| !l.trim().is_empty()).count() as u64)
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
    // Entry hashes and their 1-based positions, for the post-pass that
    // re-attributes unverifiable entries against the length anchor.
    let mut hashes: Vec<(u64, String)> = Vec::new();
    // Entries that chain correctly but were signed with a key that no longer
    // exists. Distinct from `corrupted`: nothing was tampered with, we simply
    // cannot prove it. See docs/AUDIT-VERIFY-FP-DIAGNOSIS.md.
    //
    // These are not confined to the head of the log. `.audit.key` is created
    // lazily on first use, so any process that started before that point can
    // still append under the legacy machine fingerprint — including after
    // hundreds of already-verified entries. Observed on a real install: five
    // entries from 22.09 and one from 16.10, each signed under a different
    // legacy fingerprint.
    let mut unverifiable = 0u64;

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditEntry>(line) {
            Ok(entry) => {
                // Two independent checks:
                //   link_ok — does this entry chain onto what we just accepted?
                //   mac_ok  — does its MAC validate under a key we hold?
                //
                // Both hold          → verified.
                // Only link_ok holds → the key that signed this entry is gone.
                //                        Acceptable *only* inside the leading
                //                        run, before any entry has verified.
                // Neither holds      → the bytes were altered, or a foreign
                //                        entry was spliced in. Corruption.
                let link_ok = entry.prev_hash == prev_hash;
                let mac_ok = entry.verifies_under_known_key(&prev_hash);

                // A link_ok / mac_ok entry is verified. A link_ok / mac_ok-false
                // entry is either (a) a lost signing key in the leading run
                // (before any entry has verified) — unverifiable but acceptable —
                // or (b) tampering, once the chain has proven good entries and a
                // live entry's MAC stops matching every known key. The two cases
                // are indistinguishable per entry; the anchor (outside the log)
                // exists precisely to keep the evidence intact.
                let entry_hash = entry.entry_hash.clone();
                if mac_ok && link_ok {
                    prev_hash = entry_hash.clone();
                    verified += 1;
                    hashes.push((verified, entry_hash));
                } else if link_ok && verified == 0 {
                    // Leading run: a correct chain but a key we no longer hold.
                    // Not counted as corrupted: it may be perfectly legitimate,
                    // just written under a legacy fingerprint. `unverifiable`
                    // records the gap so it stays visible instead of silently
                    // passing over.
                    unverifiable += 1;
                    prev_hash = entry_hash.clone();
                    hashes.push((verified + corrupted + unverifiable, entry_hash));
                } else if link_ok {
                    // A live entry whose MAC no longer matches any held key: the
                    // chain proved good entries arrived, so this is tampering,
                    // not a lost key.
                    corrupted += 1;
                    prev_hash = entry_hash.clone();
                    hashes.push((verified + corrupted + unverifiable, entry_hash));
                } else {
                    // The link itself broke: entries reordered, removed, spliced.
                    // Damage regardless of any key question.
                    corrupted += 1;
                    prev_hash = entry_hash.clone();
                    hashes.push((verified + corrupted + unverifiable, entry_hash));
                }
            }
            Err(_) => {
                corrupted += 1;
            }
        }
    }

    if corrupted > 0 {
        bail!(
            "audit log integrity check failed: {corrupted} corrupted entries out of {}\
             ({unverifiable} further entries unverifiable)",
            verified + corrupted + unverifiable
        );
    }

    if unverifiable > 0 {
        // Not a failure: the chain is intact and every entry after the
        // unverifiable prefix verifies. Report it so the gap is visible in
        // output rather than silently passed over.
        eprintln!(
            "warning: {unverifiable} audit entries could not be verified \
             (signed with a key that predates ~/.config/talus/.audit.key); \
             the chain verifies from that point onward"
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
    // The anchor counts every physically present entry, including the
    // unverifiable prefix — `write_anchor` at append time counts all lines, so
    // comparing against `verified` alone would report a false truncation the
    // moment a legacy prefix exists.
    let present = verified + unverifiable;
    match read_anchor() {
        Some((anchor_hash, anchor_count)) => {
            if anchor_hash != last_hash || anchor_count != present {
                bail!(
                    "audit log length anchor mismatch: log ends at {last_hash} ({present} entries), anchor records {anchor_hash} ({anchor_count} entries) — log may have been truncated or rewritten"
                );
            }
        }
        None => {
            // Legacy install (pre-anchor log) or first run: establish the
            // anchor at the current state. From this point on, any further
            // truncation or deletion is detected.
            write_anchor(&last_hash, present);
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

    /// Serialises the tests in this module. They each point `TALUS_CONFIG_DIR`
    /// at a different temporary directory, and the variable is process-global —
    /// without this, two tests running concurrently would fight over it and
    /// write each other's audit entries.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point `TALUS_CONFIG_DIR` at a fresh temp directory for the duration of
    /// the test.
    ///
    /// Without this the test wrote into the invoking user's real
    /// `~/.config/talus/audit.log`: it injected 300+ `FLOCK_STRESS` entries
    /// into the production audit trail, and it failed on any machine whose log
    /// predated the stable HMAC key — for reasons unrelated to the concurrency
    /// guarantee it is meant to test. It passed on CI only because a clean
    /// runner has no pre-existing log at all.
    struct Sandbox {
        dir: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Sandbox {
        fn new(name: &str) -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir = std::env::temp_dir().join(format!("talus_audit_{name}"));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            std::env::set_var("TALUS_CONFIG_DIR", &dir);
            Sandbox { dir, _guard: guard }
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            std::env::remove_var("TALUS_CONFIG_DIR");
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// Concurrent writers: 4 threads append interleaved entries through the
    /// real flock-ed critical section; afterwards the chain must verify
    /// 100% (without the lock this test reliably produces a corrupted chain).
    ///
    /// Runs against a sandboxed config directory — see [`Sandbox`].
    ///
    /// Ignored under Miri: `flock` is unavailable there (locking is a no-op),
    /// so the concurrency guarantee cannot be exercised.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn concurrent_writers_chain_stays_valid() {
        let _sandbox = Sandbox::new("flock_stress");
        let n_before = verify_audit_log().unwrap_or(0);
        assert_eq!(n_before, 0, "sandboxed audit log must start empty");

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

        // Count only this test's own writes. Startup may append an unrelated
        // entry (e.g. SANDBOX_DEGRADED when seccomp is unavailable) into the
        // sandboxed log, and that entry is legitimately part of the chain.
        let raw = fs::read_to_string(audit_log_path().unwrap()).unwrap();
        let present = raw.lines().filter(|l| !l.trim().is_empty()).count();
        let mine = raw
            .lines()
            .filter_map(|l| serde_json::from_str::<AuditEntry>(l).ok())
            .filter(|e| e.event == "FLOCK_STRESS")
            .count();
        assert_eq!(
            mine, 60,
            "all 4x15 concurrent appends must be present (got {mine})"
        );

        // verify_audit_log() returns every verified entry, which includes any
        // startup entry (SANDBOX_DEGRADED) written before this test's writers
        // ran. What matters is that the count matches what is physically in the
        // log — no entry lost, none counted twice.
        let n_after = verify_audit_log().expect("chain corrupted after concurrent writes!");
        assert_eq!(
            n_after, present as u64,
            "every entry in the log must verify exactly once (verified {n_after}, present {present})"
        );
    }

    /// A log whose prefix was signed with a key that no longer exists must not
    /// be reported as fully corrupt.
    ///
    /// This is the real failure mode from 26.09: five entries predate
    /// `.audit.key`, none of them verify under the stable or the legacy key,
    /// and the verifier counted every later entry as corrupt as well — so a
    /// five-entry gap reported as "153 corrupted entries out of 153".
    ///
    /// The suffix written under the live key must still verify, and the gap
    /// must be visible rather than silently swallowed.
    #[test]
    fn unverifiable_prefix_does_not_poison_the_chain() {
        let _sandbox = Sandbox::new("unverifiable_prefix");

        // Two entries signed with a key we will never have again.
        let lost_key = [0xABu8; 32];
        let mut prev = "0".to_string();
        let log_path = audit_log_path().unwrap();
        fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        for i in 0..2 {
            let mut e = AuditEntry {
                ts: format!("2026-01-01T00:0{i}:00Z"),
                uid: 1000,
                host: "old-host".into(),
                event: format!("OLD_{i}"),
                license_id: "TALUS-TEST".into(),
                detail: format!("pre-key entry {i}"),
                prev_hash: prev.clone(),
                entry_hash: String::new(),
            };
            e.entry_hash = e.compute_hash_with(&lost_key, &prev);
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .unwrap();
            writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
            prev = e.entry_hash;
        }

        // Live entries under the real key.
        for i in 0..3 {
            audit_log("LIVE", "-", &format!("entry {i}"));
        }

        // Must verify: the lost prefix is unverifiable, not corrupt, and the
        // three live entries after it must all be counted.
        let verified = verify_audit_log().expect("unverifiable prefix must not fail verification");
        assert_eq!(
            verified, 3,
            "live entries after a lost-key prefix must verify"
        );
    }

    /// Tampering inside the log must still be caught — the fix above narrows
    /// what counts as corruption, so it needs a test that the narrowing did not
    /// go too far.
    #[test]
    fn tampering_after_unverifiable_prefix_is_still_detected() {
        let _sandbox = Sandbox::new("tamper_after_prefix");

        let lost_key = [0xCDu8; 32];
        let mut prev = "0".to_string();
        let log_path = audit_log_path().unwrap();
        fs::create_dir_all(log_path.parent().unwrap()).unwrap();
        let mut e = AuditEntry {
            ts: "2026-01-01T00:00:00Z".into(),
            uid: 1000,
            host: "old-host".into(),
            event: "OLD_0".into(),
            license_id: "TALUS-TEST".into(),
            detail: "pre-key entry".into(),
            prev_hash: prev.clone(),
            entry_hash: String::new(),
        };
        e.entry_hash = e.compute_hash_with(&lost_key, &prev);
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&e).unwrap()).unwrap();
        prev = e.entry_hash.clone();

        for i in 0..3 {
            let mut live = AuditEntry {
                ts: format!("2026-01-02T00:0{i}:00Z"),
                uid: 1000,
                host: "live-host".into(),
                event: format!("LIVE_{i}"),
                license_id: "TALUS-TEST".into(),
                detail: format!("entry {i}"),
                prev_hash: prev.clone(),
                entry_hash: String::new(),
            };
            live.entry_hash = live.compute_hash(&prev);
            writeln!(f, "{}", serde_json::to_string(&live).unwrap()).unwrap();
            prev = live.entry_hash;
        }

        // Alter the last live entry's detail: its MAC no longer matches.
        let data = fs::read_to_string(&log_path).unwrap();
        let mut lines: Vec<String> = data.lines().map(String::from).collect();
        let mut last: AuditEntry = serde_json::from_str(lines.last().unwrap()).unwrap();
        last.detail = "TAMPERED".into();
        *lines.last_mut().unwrap() = serde_json::to_string(&last).unwrap();
        fs::write(&log_path, lines.join("\n") + "\n").unwrap();

        let err = verify_audit_log().expect_err("tampering must be detected");
        let msg = err.to_string();
        assert!(
            msg.contains("1 corrupted"),
            "expected exactly one corrupted entry, got: {msg}"
        );
    }
}
