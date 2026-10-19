//! The MIT build of the Talus agent.
//!
//! Everything here is in the public repository: the eBPF probes, the scoring
//! and sweep detectors, the neural engine, the audit chain, the sandbox, the TUI
//! and the output formats. There is no commercial code in this binary, and
//! `--auto-kill` reaches a verdict and then does nothing, because
//! `NoResponse` is what a build with no responder installed gets.
//!
//! The Enterprise build is a separate binary in a separate, unpublished crate.
//! It is the same CLI with a responder and a sink list attached, which is why
//! the two cannot drift apart.

use talus_process_monitor::cli::{self, Hooks};

fn main() -> anyhow::Result<()> {
    cli::main_with(Hooks::default())
}
