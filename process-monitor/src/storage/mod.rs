// ── storage/mod.rs — Event storage backends ──────────────────────────────
//
// Provides pluggable storage backends for the event pipeline:
//   - Kafka:      event streaming to Kafka topics
//   - ClickHouse: columnar analytics storage
//   - MemGraph:   process relationship graph (Cypher)
//
// Each backend is feature-gated:
//   --features kafka      → Kafka producer
//   --features clickhouse → ClickHouse inserter
//   --features memgraph   → MemGraph Cypher client

use std::sync::Arc;

use crate::monitor::{Alert, RecordedEvent};

/// Unified event type for storage backends.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageEvent {
    pub ts: String,
    pub kind: String,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub file: Option<String>,
    pub extension: Option<String>,
    pub argv: Option<String>,
}

impl From<&RecordedEvent> for StorageEvent {
    fn from(ev: &RecordedEvent) -> Self {
        Self {
            ts: ev.ts.clone(),
            kind: format!("{:?}", ev.kind),
            pid: ev.pid,
            uid: ev.uid,
            comm: ev.comm.clone(),
            file: ev.file.clone(),
            extension: ev.extension.clone(),
            argv: ev.argv.clone(),
        }
    }
}

impl From<&Alert> for StorageEvent {
    fn from(al: &Alert) -> Self {
        Self {
            ts: al.ts.clone(),
            kind: "Alert".into(),
            pid: al.pid,
            uid: al.uid,
            comm: al.comm.clone(),
            file: None,
            extension: None,
            argv: None,
        }
    }
}

// ── Unified pipeline ─────────────────────────────────────────────────────

/// Unified storage pipeline that wraps all active backends.
/// Methods are always compiled — internally gated by #[cfg].
pub struct StoragePipeline {
    /// Registered destinations. Empty in the MIT build.
    ///
    /// A trait rather than three `Option<ConcreteType>` fields: the backends are
    /// built in the private crate and the pipeline that feeds them is part of
    /// the detector, so neither side can name the other concretely. Same seam
    /// as `Responder`, and for the same reason — a runtime feature flag is not
    /// a boundary.
    sinks: Vec<Arc<dyn EventSink>>,
}

/// A destination for pipeline events.
///
/// Implementations live in the private crate. A failing sink must not stop the
/// pipeline or the agent, so `accept` reports its own failures and returns
/// nothing.
pub trait EventSink: Send + Sync {
    /// Human-readable name, used in start-up logging.
    fn name(&self) -> &'static str;
    /// Take one event. Called from the monitor thread.
    fn accept(&self, event: &StorageEvent);
    /// Take a batch of detector outputs. Optional.
    fn accept_outputs(&self, _outputs: &[crate::monitor::Output]) {}
}

impl StoragePipeline {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    /// Register a destination.
    pub fn register_sink(&mut self, sink: Arc<dyn EventSink>) {
        self.sinks.push(sink);
    }

    /// Whether anything is listening.
    pub fn has_sinks(&self) -> bool {
        !self.sinks.is_empty()
    }

    /// Forward an event to every registered destination.
    pub fn forward_event(&self, event: &StorageEvent) {
        for sink in &self.sinks {
            sink.accept(event);
        }
    }

    /// Forward a list of outputs to all active backends.
    pub fn forward_outputs(&self, outputs: &[crate::monitor::Output]) {
        for sink in &self.sinks {
            sink.accept_outputs(outputs);
        }
    }
}
