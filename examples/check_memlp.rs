//! Score a checkpoint on the built-in behavioural anchors.
//!
//! Usage: cargo run --release --example check_memlp -- <checkpoint.json>
//!
//! Prints the class each anchor lands in, so a candidate trained offline can be
//! checked against the false-positive guards before it replaces the default.

use std::path::Path;

use talus_process_monitor::memlp::{MeMLP, N_FEATURES};

const ANCHORS: [[f32; N_FEATURES]; 11] = [
    [0.02, 0.00, 0.20, 0.00, 0.10, 0.00, 0.00, 0.30, 0.00, 0.00],
    [0.15, 0.10, 0.20, 0.00, 0.25, 0.10, 0.00, 0.20, 0.00, 0.05],
    [0.30, 0.10, 0.40, 0.00, 0.30, 0.10, 0.10, 0.40, 0.00, 0.10],
    [0.90, 0.10, 0.90, 0.80, 0.50, 0.60, 0.50, 0.90, 0.00, 0.00],
    [0.60, 0.00, 0.85, 0.50, 0.30, 0.40, 0.60, 0.90, 0.00, 0.00],
    [0.30, 0.00, 0.50, 0.00, 0.90, 0.10, 0.00, 0.80, 0.00, 0.00],
    [0.50, 0.40, 0.40, 0.10, 0.40, 0.30, 0.10, 0.50, 0.00, 0.60],
    [0.10, 0.80, 0.30, 0.00, 0.10, 0.05, 0.00, 0.20, 0.00, 0.90],
    [0.05, 0.05, 0.40, 0.00, 0.10, 0.50, 0.40, 0.50, 0.80, 0.00],
    [0.05, 0.30, 0.25, 0.00, 0.10, 0.00, 0.00, 0.20, 0.00, 0.80],
    [0.15, 0.00, 0.40, 0.00, 1.00, 0.10, 0.00, 0.30, 0.00, 0.00],
];

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "data/memlp/ransomware-v1.json".to_string());
    let model = MeMLP::load(Path::new(&path))?;
    println!(
        "checkpoint: {path} ({} parameters, {} training samples)",
        model.param_count(),
        model.training_samples
    );
    for (i, f) in ANCHORS.iter().enumerate() {
        let a = model.assess(f);
        println!("anchor {i:02}: {}", a.summary());
    }
    Ok(())
}
