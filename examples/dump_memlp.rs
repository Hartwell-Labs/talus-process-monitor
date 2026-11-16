//! Write the deterministic pre-fitted MeMLP baseline to a checkpoint.
//!
//! Used by the offline training/evaluation tooling; not part of the agent.
//!
//! ```text
//! cargo run --release --example dump_memlp -- /tmp/memlp-base.json
//! ```

use std::path::Path;

use talus_process_monitor::memlp::MeMLP;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "memlp-base.json".to_string());
    let model = MeMLP::new();
    model.save(Path::new(&path))?;
    println!("wrote {} ({} params)", path, model.param_count());
    Ok(())
}
