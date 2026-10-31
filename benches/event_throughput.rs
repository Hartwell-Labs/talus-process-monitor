use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

/// Benchmark: serialization throughput of process events
fn bench_event_serialize(c: &mut Criterion) {
    let event_json = serde_json::json!({
        "pid": 12345,
        "ppid": 1,
        "comm": "process-monitor",
        "event_type": "exec",
        "timestamp": 1_700_000_000,
        "exe": "/usr/bin/process-monitor",
        "args": ["process-monitor", "--tui"],                "uid": 1_000,
        "cwd": "/home/user"
    });

    let payload = serde_json::to_string(&event_json).unwrap();

    c.bench_function("serialize_event_json", |b| {
        b.iter(|| {
            black_box(serde_json::to_string(&event_json).unwrap());
        });
    });

    c.bench_function("deserialize_event_json", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<serde_json::Value>(&payload).unwrap());
        });
    });
}

/// Benchmark: filter matching (event type, PID, comm)
fn bench_event_filter(c: &mut Criterion) {
    let events: Vec<serde_json::Value> = (0..1000)
        .map(|i| {
            serde_json::json!({
                "pid": i,
                "comm": format!("process_{}", i % 10),
                "event_type": if i % 3 == 0 { "exec" } else if i % 3 == 1 { "open" } else { "connect" },
                "uid": 1_000
            })
        })
        .collect();

    c.bench_function("filter_by_event_type", |b| {
        b.iter(|| {
            black_box(events.iter().filter(|e| e["event_type"] == "exec").count());
        });
    });

    c.bench_function("filter_by_pid_range", |b| {
        b.iter(|| {
            black_box(
                events
                    .iter()
                    .filter(|e| {
                        e["pid"].as_i64().unwrap_or(0) >= 100
                            && e["pid"].as_i64().unwrap_or(0) < 200
                    })
                    .count(),
            );
        });
    });
}

/// Benchmark: colored string formatting (TUI rendering)
fn bench_tui_render(c: &mut Criterion) {
    use colored::Colorize;

    c.bench_function("colorize_process_line", |b| {
        b.iter(|| {
            let line = format!(
                "{:>8} {:>8} {:>6} {} {}",
                "12345".blue().bold(),
                "1".dimmed(),
                "exec".green().bold(),
                "/usr/bin/process-monitor".cyan(),
                "[arg1, arg2]".dimmed()
            );
            black_box(line);
        });
    });
}

/// Benchmark: atomic counter operations (concurrent event counting)
fn bench_concurrent_counter(c: &mut Criterion) {
    use std::sync::atomic::{AtomicU64, Ordering};

    let counter = AtomicU64::new(0);

    c.bench_function("atomic_counter_inc", |b| {
        b.iter(|| {
            black_box(counter.fetch_add(1, Ordering::Relaxed));
        });
    });
}

criterion_group!(
    benches,
    bench_event_serialize,
    bench_event_filter,
    bench_tui_render,
    bench_concurrent_counter
);
criterion_main!(benches);
