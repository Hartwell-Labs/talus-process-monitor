use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};

#[derive(Clone, serde::Serialize)]
struct MonitorEvent {
    raw: String,
}

#[derive(Clone, serde::Serialize)]
struct MonitorStatus {
    running: bool,
    pid: Option<u32>,
}

struct MonitorState {
    pid: Mutex<Option<u32>>,
    running: Mutex<bool>,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            pid: Mutex::new(None),
            running: Mutex::new(false),
        }
    }
}

#[tauri::command]
fn get_status(state: tauri::State<'_, Arc<MonitorState>>) -> MonitorStatus {
    MonitorStatus {
        running: *state.running.lock().unwrap(),
        pid: *state.pid.lock().unwrap(),
    }
}

/// Validate a value that becomes a `talus` argument.
///
/// The webview should not be able to turn a broker/topic string into an extra
/// command-line flag (or shell-ish content) in a process started through sudo.
fn safe_arg(value: &str, what: &str) -> Result<String, String> {
    let ok = !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('-')
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | ',' | '/' | '=')
        });
    if ok {
        Ok(value.to_string())
    } else {
        Err(format!("invalid {what}: {value}"))
    }
}

#[tauri::command]
fn start_monitor(
    state: tauri::State<'_, Arc<MonitorState>>,
    app: AppHandle,
    auto_kill: bool,
    threshold: u64,
    kafka_brokers: Option<String>,
    kafka_topic: Option<String>,
    clickhouse: bool,
    memgraph: bool,
) -> Result<String, String> {
    {
        let running = state.running.lock().unwrap();
        if *running {
            return Err("Monitor already running".into());
        }
    }

    let mut args: Vec<String> = vec!["--json".into()];
    if auto_kill {
        args.push("--auto-kill".into());
    }
    if threshold != 50 {
        args.push("--alert-threshold".into());
        args.push(threshold.to_string());
    }
    if let Some(ref brokers) = kafka_brokers {
        args.push("--kafka-brokers".into());
        args.push(safe_arg(brokers, "kafka brokers")?);
    }
    if let Some(ref topic) = kafka_topic {
        args.push("--kafka-topic".into());
        args.push(safe_arg(topic, "kafka topic")?);
    }
    if clickhouse {
        args.push("--clickhouse".into());
    }
    if memgraph {
        args.push("--memgraph".into());
    }

    // Find talus binary
    let binary_paths = ["/usr/local/bin/talus", "/usr/bin/talus"];
    let binary = binary_paths
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .copied()
        .unwrap_or("talus");

    let mut child = Command::new("sudo")
        .arg(binary)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start talus: {e}"))?;

    let pid = child.id();
    *state.pid.lock().unwrap() = Some(pid);
    *state.running.lock().unwrap() = true;

    let stdout = child.stdout.take().expect("no stdout");
    let stderr = child.stderr.take().expect("no stderr");
    let app_clone = app.clone();
    let state_clone = Arc::clone(&state);

    // Thread 1: read stdout → emit events
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) if !l.is_empty() => {
                    let _ = app_clone.emit("monitor-event", MonitorEvent { raw: l });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Thread 2: drain stderr (so it doesn't block), then wait for process exit
    std::thread::spawn(move || {
        let _ = BufReader::new(stderr).lines().count();
        // When stdout closes, the process is likely dead — but let's also wait
        // We can't call wait() here easily because we moved child, so just mark stopped
        // Give it a moment for the stdout thread to finish
        std::thread::sleep(std::time::Duration::from_millis(200));
        *state_clone.running.lock().unwrap() = false;
        *state_clone.pid.lock().unwrap() = None;
        let _ = app_clone.emit("monitor-stopped", ());
    });

    Ok(format!("Monitor started (pid={})", pid))
}

#[tauri::command]
fn stop_monitor(state: tauri::State<'_, Arc<MonitorState>>) -> Result<String, String> {
    let running = state.running.lock().unwrap();
    if !*running {
        return Err("Monitor not running".into());
    }
    drop(running);

    if let Some(pid) = *state.pid.lock().unwrap() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    *state.running.lock().unwrap() = false;
    *state.pid.lock().unwrap() = None;
    Ok("Monitor stopped".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = Arc::new(MonitorState::new());

    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            start_monitor,
            stop_monitor,
            get_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
