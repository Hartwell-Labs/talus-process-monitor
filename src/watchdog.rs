// ── watchdog.rs — Fail-closed security watchdog ──────────────────────────
//
// Monitors the eBPF reader thread and agent health.
// If the agent crashes or the eBPF pipeline stops flowing events,
// triggers an alarm (webhook, log, network policy).
//
// Design:
//   - Heartbeat from reader thread every 1s
//   - If no heartbeat for WATCHDOG_TIMEOUT seconds → alarm
//   - Alarm = log + optional webhook POST

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Watchdog timeout in seconds — if no heartbeat, trigger alarm.
const WATCHDOG_TIMEOUT: u64 = 10;

/// Global heartbeat counter — incremented by reader thread.
static HEARTBEAT: AtomicU64 = AtomicU64::new(0);

/// Global alarm flag — set when watchdog triggers.
static ALARM: AtomicBool = AtomicBool::new(false);

/// Alarm webhook URL (configurable via env).
fn alarm_webhook_url() -> Option<String> {
    std::env::var("TALUS_ALARM_WEBHOOK").ok()
}

/// Signal a heartbeat from the reader thread.
pub fn heartbeat() {
    HEARTBEAT.fetch_add(1, Ordering::Relaxed);
}

/// Check if the watchdog has triggered an alarm.
#[allow(dead_code)]
pub fn is_alarm() -> bool {
    ALARM.load(Ordering::Relaxed)
}

/// Get the current heartbeat count.
#[allow(dead_code)]
pub fn heartbeat_count() -> u64 {
    HEARTBEAT.load(Ordering::Relaxed)
}

/// Spawn the watchdog thread.
pub fn spawn_watchdog() -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("talus-watchdog".into())
        .spawn(move || {
            let mut last_heartbeat = HEARTBEAT.load(Ordering::Relaxed);
            let mut last_check = Instant::now();

            loop {
                std::thread::sleep(Duration::from_secs(WATCHDOG_TIMEOUT));

                let current = HEARTBEAT.load(Ordering::Relaxed);
                let elapsed = last_check.elapsed().as_secs();
                last_check = Instant::now();

                if current == last_heartbeat && elapsed >= WATCHDOG_TIMEOUT {
                    if !ALARM.load(Ordering::Relaxed) {
                        ALARM.store(true, Ordering::Relaxed);
                        eprintln!("[watchdog] ⚠ ALARM: no heartbeat for {WATCHDOG_TIMEOUT}s — eBPF pipeline may be unresponsive");

                        // Log to watchdog.log
                        let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
                        if let Some(config_dir) = dirs::config_dir() {
                            let log_path = config_dir.join("talus").join("watchdog.log");
                            let _ = std::fs::create_dir_all(config_dir.join("talus"));
                            let entry = format!("[{ts}] ALARM: no heartbeat for {WATCHDOG_TIMEOUT}s\n");
                            let _ = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(&log_path)
                                .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
                        }

                        // Optional webhook notification
                        if let Some(url) = alarm_webhook_url() {
                            let payload = serde_json::json!({
                                "type": "watchdog_alarm",
                                "ts": ts.to_string(),
                                "reason": "no_heartbeat",
                                "timeout_secs": WATCHDOG_TIMEOUT,
                                "hostname": hostname::get().map(|h| h.to_string_lossy().into_owned()).unwrap_or_default(),
                            });
                            let _ = std::thread::spawn(move || {
                                if let Ok(client) = reqwest::blocking::Client::builder()
                                    .timeout(Duration::from_secs(10))
                                    .build()
                                {
                                    let _ = client.post(url).json(&payload).send();
                                }
                            });
                        }
                    }
                } else if ALARM.load(Ordering::Relaxed) {
                    eprintln!("[watchdog] ✓ heartbeat restored — pipeline recovered");
                    ALARM.store(false, Ordering::Relaxed);
                    last_heartbeat = current;
                } else {
                    last_heartbeat = current;
                }
            }
        })
        .expect("failed to spawn watchdog thread")
}
