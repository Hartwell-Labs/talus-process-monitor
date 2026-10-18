//! Talus Process Monitor — detection engine.
//!
//! This crate is the MIT half of the project: everything needed to *observe*
//! ransomware behaviour, and nothing that can end a process on its own.
//!
//! # What lives here
//!
//! The eBPF probes, the scoring and sweep detectors, the MeMLP engine, the
//! signed audit chain, the self-sandbox, the watchdog, the TUI and the output
//! formats are all in this crate and are MIT licensed. See the repository
//! `LICENSE`.
//!
//! # What does not
//!
//! Three things are absent by design and are built from a separate, private
//! crate:
//!
//!   * the automatic response path — terminating or suspending a process
//!   * the web dashboard, its REST API and WebSocket stream
//!   * the Kafka, ClickHouse and MemGraph exporters, and the C FFI library
//!
//! They are not feature-flagged here because a runtime flag is not a boundary:
//! the code would still be in this repository and still readable. The boundary
//! is that the source is not published.
//!
//! # Using it
//!
//! ```no_run
//! use talus_process_monitor::monitor::Monitor;
//! use std::path::Path;
//!
//! # fn main() -> anyhow::Result<()> {
//! let mut m = Monitor::start(Path::new("bpf/process_monitor_ebpf.o"), 500, false)?;
//! for _ in m.poll() {
//!     println!("up: {:?}", m.uptime());
//! }
//! # Ok(())
//! # }
//! ```

// `#![warn(missing_docs)]` is inherited from the crate root; the modules below
// each carry their own documentation and the lints apply to them as well.

pub mod audit;
pub mod license;
pub mod memlp;
pub mod monitor;
pub mod sandbox;
pub mod storage;
pub mod watchdog;
