//! MeMLP — **M**odular **e**mbedded **M**ulti-**L**ayer **P**erceptron Model.
//!
//! The neural-network stack embedded directly in the Talus agent, built from
//! scratch — no `ndarray`, no `tch`, no ONNX runtime. A few KB of Rust that
//! runs 100% on the CPU inside the agent process.
//!
//! * **Modular** — one model file contains several specialist MLP modules,
//!   each solving a single detection task (ransomware classification,
//!   lateral-movement scoring, persistence detection). Modules share nothing
//!   but the checkpoint file.
//! * **Embedded** — the whole stack is dependency-free, serialises to JSON
//!   checkpoints between runs and trains online from live eBPF traffic.
//! * **Multi-layer** — every module is a true multi-layer perceptron with
//!   ReLU hidden layers, a softmax output and online gradient-descent
//!   training (backprop + cross-entropy loss).
//!
//! Architecture of the default model ([`MeMLP::new`]):
//!
//! | Module        | Shape             | Task                                    |
//! |---------------|-------------------|-----------------------------------------|
//! | `ransomware`  | 10 → 24 → 16 → 3  | benign / suspicious / ransomware        |
//! | `lateral`     | 10 → 12 → 2       | normal / lateral-movement suspect       |
//! | `persistence` | 10 → 12 → 2       | normal / persistence suspect            |
//!
//! Every module consumes the same 10-feature behavioural embedding built
//! from the live eBPF event stream (see [`PidFeatures`]) — different heads,
//! one shared view of the process.
//!
//! # Design notes (light *and* strong)
//!
//! **Light**
//! * Inference and training run on fixed-size stack buffers — zero heap
//!   allocation per `assess` / `train` call.
//! * [`PidFeatures`] is a flat ~100-byte `Copy`-sized struct: distinct files
//!   and extensions are tracked with hash bitmaps instead of
//!   `HashSet<String>`, so the per-open hot path allocates nothing.
//! * Persistence-path matching is one pass over the path, not 12 substring
//!   scans per event.
//! * Checkpoints are compact JSON, written atomically, and skipped entirely
//!   when nothing was learned since the last save.
//!
//! **Strong**
//! * A fresh model is pre-fitted on a small set of behavioural anchors, so it
//!   gives sensible verdicts from the first event instead of random noise.
//! * Online training mixes in a replay of recent samples plus a rotating
//!   anchor, and uses a decaying learning rate — the net keeps learning from
//!   live alerts without forgetting what benign looks like.
//! * Backprop fix: gradients now flow through the weights *before* they are
//!   updated (the old code propagated through already-updated weights).
//! * He-style initialisation with a proper PRNG.
//! * Checkpoints are validated structurally on load (shapes, widths,
//!   finiteness) — a corrupt or tampered file is rejected instead of
//!   panicking inside the agent.
//! * Ransomware-extension matching is case-insensitive (`.LOCKED`).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Version of the MeMLP checkpoint format.
pub const MEMLP_VERSION: u32 = 1;

/// Ransomware module shape: 10 behavioural features → 3 verdict classes.
pub const RANSOMWARE_ARCH: [usize; 4] = [10, 24, 16, 3];
/// Lateral-movement module shape: 10 features → 2 classes.
pub const LATERAL_ARCH: [usize; 3] = [10, 12, 2];
/// Persistence module shape: 10 features → 2 classes.
pub const PERSISTENCE_ARCH: [usize; 3] = [10, 12, 2];

/// Output classes of the `ransomware` module (index = [`RANSOMWARE_ARCH`] output dim).
pub const RANSOMWARE_CLASSES: usize = 3;

/// Number of behavioural features fed to every head.
pub const N_FEATURES: usize = 10;

/// Widest layer a [`Mlp`] may have (stack buffers are sized from this).
const MAX_WIDTH: usize = 32;
/// Deepest network a [`Mlp`] may have, in weight layers.
const MAX_DEPTH: usize = 6;
/// Per-layer activation scratch space, living on the stack.
type Acts = [[f32; MAX_WIDTH]; MAX_DEPTH + 1];

/// Recent training samples kept for replay.
const REPLAY_LEN: usize = 16;
/// Epochs / learning rate used to pre-fit a fresh model on [`ANCHORS`].
const ANCHOR_EPOCHS: usize = 150;
const ANCHOR_LR: f32 = 0.1;
/// Deterministic synthetic samples (labelled by the heuristic teachers) used
/// to pre-fit a fresh model, and how many passes are made over them.
const SYNTH_SAMPLES: usize = 256;
const SYNTH_EPOCHS: usize = 20;
const SYNTH_LR: f32 = 0.05;

/* ================================================================ */
/*  Behavioural feature extraction                                   */
/* ================================================================ */

/// Sliding-window behavioural features for one PID.
///
/// The monitor feeds events in via `observe_*` and decays the window every
/// second (exponential half-life), so the embedding always reflects roughly
/// the last few seconds of activity — the same 1-second granularity as the
/// heuristic sliding window, but smoothed.
///
/// The struct is flat (no heap): distinct-file and distinct-extension sets are
/// hash bitmaps, which keeps the per-event path allocation-free.
#[derive(Debug, Clone, Default)]
pub struct PidFeatures {
    opens: f32,
    execs: f32,
    net: f32,
    fs: f32,
    destructive: f32,
    suspicious_ext: f32,
    persistence_hits: f32,
    entropy_sum: f32,
    entropy_n: u32,
    /// 64-bit bitmap of distinct extensions seen this second.
    ext_bits: u64,
    /// 256-bit bitmap of distinct file paths seen this second.
    file_bits: [u64; 4],
}

/// File extensions treated as ransomware markers when a process opens many
/// of them in a short window. Deliberately conservative — `.bak` or `.zip`
/// are legitimate tools too and stay out of the list. Matching is
/// case-insensitive.
pub const RANSOMWARE_EXTS: &[&str] = &[
    "enc",
    "crypt",
    "crypted",
    "locked",
    "encrypted",
    "ransom",
    "locky",
    "cerber",
    "wallet",
    "onion",
    "cryptolocker",
    "keepcalm",
    "restore",
    "lockbit",
    "akira",
    "wncry",
    "ryk",
    "zepto",
    "crypz",
];

/// Path fragments treated as autostart / persistence locations.
pub const PERSISTENCE_PATHS: &[&str] = &[
    "/etc/cron",
    "/etc/systemd",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/profile.d",
    "/etc/ld.so.preload",
    "/lib/systemd",
    "/usr/lib/systemd",
    "/var/spool/cron",
    "/.config/autostart",
    "/.bashrc",
    "/.bash_profile",
    "/.zshrc",
    "/.profile",
    "/.ssh/authorized_keys",
];

/// Features below this are treated as "no activity" (map-retention criterion).
const ACTIVITY_EPS: f32 = 0.02;
/// Counters under this snap to zero on decay (avoids denormal slow paths and
/// lets dead PIDs age out in ~6 s instead of lingering for minutes).
const SNAP_EPS: f32 = 1e-3;

/// FNV-1a over bytes, optionally ASCII-case-folded, followed by a finaliser so
/// the top bits are well mixed.
#[inline]
fn hash_bytes(bytes: &[u8], fold_case: bool) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        let b = if fold_case { b.to_ascii_lowercase() } else { b };
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^ (h >> 29)
}

/// Single-pass persistence-location matcher.
///
/// Equivalent to `PERSISTENCE_PATHS.iter().any(|p| path.contains(p))` (see the
/// `persistence_matcher_agrees_with_naive` test) but dispatches on the byte
/// after each `/`, so ordinary paths cost one scan instead of a dozen.
#[inline]
fn is_persistence_path(path: &str) -> bool {
    let b = path.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c != b'/' {
            continue;
        }
        // `i` indexes an ASCII '/', so it is always a char boundary.
        let rest = &path[i..];
        let hit = match b.get(i + 1) {
            Some(b'e') => {
                rest.starts_with("/etc/cron")
                    || rest.starts_with("/etc/systemd")
                    || rest.starts_with("/etc/init.d")
                    || rest.starts_with("/etc/rc.local")
                    || rest.starts_with("/etc/profile.d")
                    || rest.starts_with("/etc/ld.so.preload")
            }
            Some(b'l') => rest.starts_with("/lib/systemd"),
            Some(b'u') => rest.starts_with("/usr/lib/systemd"),
            Some(b'v') => rest.starts_with("/var/spool/cron"),
            Some(b'.') => {
                rest.starts_with("/.config/autostart")
                    || rest.starts_with("/.bashrc")
                    || rest.starts_with("/.bash_profile")
                    || rest.starts_with("/.zshrc")
                    || rest.starts_with("/.profile")
                    || rest.starts_with("/.ssh/authorized_keys")
            }
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

#[inline]
fn halve(v: &mut f32) {
    *v *= 0.5;
    if *v < SNAP_EPS {
        *v = 0.0;
    }
}

impl PidFeatures {
    /// Record one file-open. `entropy` is the normalised Shannon entropy of
    /// the filename (0.0–1.0, as computed by the monitor).
    pub fn observe_open(&mut self, path: &str, extension: Option<&str>, entropy: f64) {
        self.opens += 1.0;
        if entropy.is_finite() {
            self.entropy_sum += entropy.clamp(0.0, 1.0) as f32;
        }
        self.entropy_n = self.entropy_n.saturating_add(1);

        let bit = (hash_bytes(path.as_bytes(), false) >> 56) as usize; // 0..=255
        self.file_bits[bit >> 6] |= 1u64 << (bit & 63);

        if let Some(ext) = extension {
            if !ext.is_empty() {
                let bit = hash_bytes(ext.as_bytes(), true) >> 58; // 0..=63
                self.ext_bits |= 1u64 << bit;
                if RANSOMWARE_EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                    self.suspicious_ext += 1.0;
                }
            }
        }
        if is_persistence_path(path) {
            self.persistence_hits += 1.0;
        }
    }

    /// Record one execve. `network` marks network syscalls (connect/accept/
    /// sendto/recvfrom), which the monitor counts alongside execs.
    pub fn observe_exec(&mut self, network: bool) {
        self.execs += 1.0;
        if network {
            self.net += 1.0;
        }
    }

    /// Record one filesystem-mutation event (mkdir/unlink/chmod).
    /// `destructive` marks unlink/chmod — the delete-and-rename half of a
    /// ransomware damage pattern.
    pub fn observe_fs(&mut self, destructive: bool) {
        self.fs += 1.0;
        if destructive {
            self.destructive += 1.0;
        }
    }

    /// Halve every counter (1-second half-life) and drop the per-second
    /// distinct-file/-extension sets. Called once per monitor tick.
    pub fn decay(&mut self) {
        halve(&mut self.opens);
        halve(&mut self.execs);
        halve(&mut self.net);
        halve(&mut self.fs);
        halve(&mut self.destructive);
        halve(&mut self.suspicious_ext);
        halve(&mut self.persistence_hits);
        halve(&mut self.entropy_sum);
        self.entropy_n = (self.entropy_n / 2).max(1);
        self.file_bits = [0; 4];
        self.ext_bits = 0;
    }

    /// Whether this PID has generated enough signal to train on.
    /// Reserved for policy gating; exercised in unit tests.
    #[allow(dead_code)]
    pub fn is_trainable(&self) -> bool {
        self.opens >= 5.0
    }

    /// Whether this PID has any recent activity (map-retention criterion).
    pub fn has_activity(&self) -> bool {
        self.opens >= ACTIVITY_EPS || self.execs >= ACTIVITY_EPS || self.fs >= ACTIVITY_EPS
    }

    /// Estimated number of distinct files this second (linear counting over
    /// the 256-bit bitmap; saturates at ~1400, far above the useful range).
    fn distinct_files(&self) -> f32 {
        const M: f32 = 256.0;
        let ones: u32 = self.file_bits.iter().map(|w| w.count_ones()).sum();
        let zeros = 256 - ones;
        if zeros == 0 {
            M * M.ln()
        } else {
            -M * (zeros as f32 / M).ln()
        }
    }

    /// Build the 10-dimensional behavioural embedding (all values 0.0–1.0):
    ///
    /// | # | Feature                                        |
    /// |---|------------------------------------------------|
    /// | 0 | file-open rate (normalised to 100/s)           |
    /// | 1 | exec + network rate (normalised to 20/s)       |
    /// | 2 | mean filename Shannon entropy                  |
    /// | 3 | ransomware-marker extension fraction           |
    /// | 4 | extension diversity (normalised to 8)          |
    /// | 5 | filesystem-mutation rate (normalised to 50/s)  |
    /// | 6 | destructive fraction (unlink/chmod of fs ops)  |
    /// | 7 | distinct-file fraction (mass-encryption shape) |
    /// | 8 | persistence-path fraction                      |
    /// | 9 | network fraction of exec/net events            |
    pub fn features(&self) -> [f32; N_FEATURES] {
        let opens = self.opens.max(1.0);
        let execs = self.execs.max(1.0);
        let fs = self.fs.max(1.0);
        let entropy_mean = if self.entropy_n > 0 {
            self.entropy_sum / self.entropy_n as f32
        } else {
            0.0
        };
        let ext_div = self.ext_bits.count_ones() as f32;
        [
            (self.opens / 100.0).min(1.0),
            (self.execs / 20.0).min(1.0),
            entropy_mean.clamp(0.0, 1.0),
            (self.suspicious_ext / opens).min(1.0),
            (ext_div / 8.0).min(1.0),
            (self.fs / 50.0).min(1.0),
            (self.destructive / fs).min(1.0),
            (self.distinct_files() / opens).min(1.0),
            (self.persistence_hits / opens).min(1.0),
            (self.net / execs).min(1.0),
        ]
    }
}

/* ================================================================ */
/*  Heuristic teachers (transparent labels for online training)      */
/* ================================================================ */

/// Heuristic ransomware class from the 10-feature embedding.
///
/// Indexes match the `ransomware` module outputs: 0 benign, 1 suspicious,
/// 2 ransomware. The neural head trains against this teacher — the MLP
/// generalises it and keeps scoring between alerts.
pub fn ransomware_heuristic_target(f: &[f32; N_FEATURES]) -> usize {
    // Distinct-file spread only signals mass encryption when the open rate
    // is high too — a quiet process opening distinct files is just normal work.
    let mass_encryption = f[7] * f[0];
    let score =
        3.0 * f[0] + 2.0 * f[3] + 1.5 * mass_encryption + 1.0 * f[6] + 1.0 * f[2] + 0.5 * f[4];
    if score >= 2.0 {
        2
    } else if score >= 1.0 {
        1
    } else {
        0
    }
}

/// Heuristic lateral-movement class: 0 normal, 1 suspect. Weighs exec +
/// network rate and the network fraction of events.
pub fn lateral_heuristic_target(f: &[f32; N_FEATURES]) -> usize {
    let score = 2.0 * f[1] + 1.5 * f[9] + 0.5 * f[0];
    usize::from(score >= 1.0)
}

/// Heuristic persistence class: 0 normal, 1 suspect. Weighs autostart-path
/// hits, filesystem mutation and destructive ops.
pub fn persistence_heuristic_target(f: &[f32; N_FEATURES]) -> usize {
    let score = 2.5 * f[8] + 1.0 * f[5] + 0.5 * f[6];
    usize::from(score >= 1.0)
}

/// Behavioural prototypes labelled by the heuristic teachers. They pre-fit a
/// fresh model and are replayed during online training so the live stream
/// (which only produces *alert-time*, i.e. high-activity, samples) can never
/// make the net forget what quiet and benign look like.
const ANCHORS: [[f32; N_FEATURES]; 8] = [
    // idle desktop process
    [0.02, 0.0, 0.2, 0.0, 0.1, 0.0, 0.0, 0.3, 0.0, 0.0],
    // busy but benign (editor / indexer)
    [0.15, 0.1, 0.2, 0.0, 0.25, 0.1, 0.0, 0.2, 0.0, 0.05],
    // brisk, mixed activity — suspicious but not conclusive
    [0.3, 0.1, 0.4, 0.0, 0.3, 0.1, 0.1, 0.4, 0.0, 0.1],
    // mass encryption: fast, high-entropy names, marker extensions
    [0.9, 0.1, 0.9, 0.8, 0.5, 0.6, 0.5, 0.9, 0.0, 0.0],
    // slower encryption with delete-and-replace
    [0.6, 0.0, 0.85, 0.5, 0.3, 0.4, 0.6, 0.9, 0.0, 0.0],
    // exec + network heavy (lateral movement shape)
    [0.1, 0.8, 0.3, 0.0, 0.1, 0.05, 0.0, 0.2, 0.0, 0.9],
    // autostart / persistence writes
    [0.05, 0.05, 0.4, 0.0, 0.1, 0.5, 0.4, 0.5, 0.8, 0.0],
    // ordinary network client
    [0.05, 0.3, 0.25, 0.0, 0.1, 0.0, 0.0, 0.2, 0.0, 0.8],
];

/* ================================================================ */
/*  Mlp — a generic multi-layer perceptron                           */
/* ================================================================ */

/// A generic feed-forward multi-layer perceptron, hand-rolled on flat
/// `Vec<f32>` storage (row-major `weights[k][i * n_out + j]`).
///
/// * Hidden layers use ReLU; the output layer uses softmax.
/// * Training is online stochastic gradient descent (backpropagation)
///   with cross-entropy loss — exactly what a small embedded model needs.
/// * Initialisation is seeded and deterministic: two `new()` calls with the
///   same `arch` produce identical weights (reproducible tests).
/// * Widths are limited to 32 and depth to 6 weight layers so inference and
///   training run on stack buffers with no heap allocation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mlp {
    version: u32,
    arch: Vec<usize>,
    weights: Vec<Vec<f32>>,
    biases: Vec<Vec<f32>>,
}

/// Deterministic splitmix64 → uniform `f32` in `[0, 1)`.
fn rng_next(state: &mut u64) -> f32 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 40) as f32 / 16_777_216.0
}

impl Mlp {
    /// Create a deterministically-initialised network with the given layer sizes
    /// (He-uniform for ReLU layers, Glorot-uniform for the softmax layer).
    ///
    /// # Panics
    ///
    /// Panics if `arch` has fewer than two layers, more than 7 layers, or a
    /// layer wider than 32 units.
    pub fn new(arch: &[usize]) -> Self {
        assert!(
            arch.len() >= 2,
            "an MLP needs at least an input and output layer"
        );
        assert!(
            arch.len() <= MAX_DEPTH + 1 && arch.iter().all(|&w| (1..=MAX_WIDTH).contains(&w)),
            "MLP exceeds the embedded limits ({MAX_DEPTH} weight layers, width {MAX_WIDTH})"
        );
        let mut state: u64 = 0x5EED_5EED_0000_0001;
        let layers = arch.len() - 1;
        let mut weights = Vec::with_capacity(layers);
        let mut biases = Vec::with_capacity(layers);

        for k in 0..layers {
            let (n_in, n_out) = (arch[k], arch[k + 1]);
            let limit = if k == layers - 1 {
                (6.0 / (n_in + n_out) as f32).sqrt()
            } else {
                (6.0 / n_in as f32).sqrt()
            };
            let w: Vec<f32> = (0..n_in * n_out)
                .map(|_| (rng_next(&mut state) * 2.0 - 1.0) * limit)
                .collect();
            weights.push(w);
            biases.push(vec![0.0; n_out]);
        }

        Self {
            version: 1,
            arch: arch.to_vec(),
            weights,
            biases,
        }
    }

    /// Layer sizes, e.g. `[10, 24, 16, 3]`.
    /// Surfaced by the web REST API ([`crate::monitor::Monitor::memlp_summary`]).
    #[allow(dead_code)]
    pub fn arch(&self) -> &[usize] {
        &self.arch
    }

    /// Total number of trainable parameters.
    pub fn param_count(&self) -> usize {
        self.weights.iter().map(Vec::len).sum::<usize>()
            + self.biases.iter().map(Vec::len).sum::<usize>()
    }

    /// Structural check of a deserialised network: right shape, within the
    /// embedded limits, and consistent buffer sizes. Guarantees that no later
    /// `forward` / `train` call can index out of bounds.
    fn validate(&self, n_in: usize, n_out: usize, name: &str) -> anyhow::Result<()> {
        let a = &self.arch;
        anyhow::ensure!(
            a.len() >= 2 && a.len() <= MAX_DEPTH + 1,
            "{name}: unsupported depth {}",
            a.len()
        );
        anyhow::ensure!(
            a.iter().all(|&w| (1..=MAX_WIDTH).contains(&w)),
            "{name}: layer width outside 1..={MAX_WIDTH}"
        );
        anyhow::ensure!(
            a[0] == n_in && a[a.len() - 1] == n_out,
            "{name}: expected {n_in} inputs and {n_out} outputs, got {} and {}",
            a[0],
            a[a.len() - 1]
        );
        anyhow::ensure!(
            self.weights.len() == a.len() - 1 && self.biases.len() == a.len() - 1,
            "{name}: layer count does not match architecture"
        );
        for k in 0..a.len() - 1 {
            anyhow::ensure!(
                self.weights[k].len() == a[k] * a[k + 1] && self.biases[k].len() == a[k + 1],
                "{name}: layer {k} buffer size does not match architecture"
            );
        }
        Ok(())
    }

    fn all_finite(&self) -> bool {
        self.weights
            .iter()
            .chain(self.biases.iter())
            .all(|l| l.iter().all(|v| v.is_finite()))
    }

    /// Forward pass into caller-provided stack scratch. Returns the softmax
    /// output as a slice of `acts`. Allocation-free.
    #[inline]
    fn predict<'a>(&self, input: &[f32], acts: &'a mut Acts) -> &'a [f32] {
        let layers = self.weights.len();
        let n_in = self.arch[0];
        let n = input.len().min(n_in);
        acts[0][..n].copy_from_slice(&input[..n]);
        acts[0][n..n_in].fill(0.0);

        for k in 0..layers {
            let (n_i, n_o) = (self.arch[k], self.arch[k + 1]);
            let (lo, hi) = acts.split_at_mut(k + 1);
            let h = &lo[k][..n_i];
            let z = &mut hi[0][..n_o];
            z.copy_from_slice(&self.biases[k]);
            let w = &self.weights[k];
            for (i, &x) in h.iter().enumerate() {
                if x == 0.0 {
                    continue;
                }
                let row = &w[i * n_o..(i + 1) * n_o];
                for (zj, &r) in z.iter_mut().zip(row) {
                    *zj += x * r;
                }
            }
            if k == layers - 1 {
                softmax_in_place(z);
            } else {
                for v in z.iter_mut() {
                    if *v < 0.0 {
                        *v = 0.0;
                    }
                }
            }
        }
        &acts[layers][..self.arch[layers]]
    }

    /// Forward pass: `input` → probability distribution over outputs.
    pub fn forward(&self, input: &[f32]) -> Vec<f32> {
        let mut acts: Acts = [[0.0; MAX_WIDTH]; MAX_DEPTH + 1];
        self.predict(input, &mut acts).to_vec()
    }

    /// Replace any non-finite (NaN/Inf) weight with `0.0`.
    ///
    /// Recovers a model from a numerical blow-up instead of letting NaN
    /// poison the checkpoint file (serde_json serialises NaN as JSON
    /// `null`, which corrupts the file on reload).
    pub fn sanitize(&mut self) {
        for v in self
            .weights
            .iter_mut()
            .chain(self.biases.iter_mut())
            .flat_map(|l| l.iter_mut())
        {
            if !v.is_finite() {
                *v = 0.0;
            }
        }
    }

    /// One gradient-descent step on a single sample. Returns the
    /// cross-entropy loss before the update (lower = better fit).
    ///
    /// Numerically hardened: inputs are validated, gradients are clipped and
    /// weight updates are bounded, so a single extreme sample (or a long
    /// training run) can never explode the weights into NaN/Inf.
    /// Allocation-free.
    pub fn train(&mut self, input: &[f32], target: &[f32], learning_rate: f32) -> f32 {
        // Guard against poisoned inputs (NaN/Inf features or labels) — skip
        // the update entirely instead of propagating the poison.
        if !learning_rate.is_finite() || !input.iter().chain(target.iter()).all(|v| v.is_finite())
        {
            return f32::INFINITY;
        }

        let layers = self.weights.len();
        let n_last = self.arch[layers];
        let mut acts: Acts = [[0.0; MAX_WIDTH]; MAX_DEPTH + 1];
        self.predict(input, &mut acts);

        // Cross-entropy loss + softmax/CE gradient (p - t), clipped so a single
        // bad sample cannot explode the weights.
        let mut loss = 0.0f32;
        let mut delta = [0.0f32; MAX_WIDTH];
        for j in 0..n_last {
            let p = acts[layers][j];
            let t = target.get(j).copied().unwrap_or(0.0);
            loss -= t * p.max(1e-7).ln();
            delta[j] = (p - t).clamp(-5.0, 5.0);
        }

        // Backpropagation, layer by layer.
        for k in (0..layers).rev() {
            let (n_i, n_o) = (self.arch[k], self.arch[k + 1]);

            // 1) Propagate the error through the *current* weights (before they
            //    are touched), gated by the previous layer's ReLU.
            let mut next = [0.0f32; MAX_WIDTH];
            if k > 0 {
                let w = &self.weights[k];
                for i in 0..n_i {
                    if acts[k][i] > 0.0 {
                        let row = &w[i * n_o..(i + 1) * n_o];
                        next[i] = row.iter().zip(&delta[..n_o]).map(|(r, d)| r * d).sum();
                    }
                }
            }

            // 2) Update weights (bounded per-parameter step) and biases.
            let w = &mut self.weights[k];
            for (i, &hi) in acts[k][..n_i].iter().enumerate() {
                if hi == 0.0 {
                    continue;
                }
                let row = &mut w[i * n_o..(i + 1) * n_o];
                for (wij, &d) in row.iter_mut().zip(&delta[..n_o]) {
                    *wij -= (learning_rate * d * hi).clamp(-1.0, 1.0);
                }
            }
            for (b, &d) in self.biases[k].iter_mut().zip(&delta[..n_o]) {
                *b -= (learning_rate * d).clamp(-1.0, 1.0);
            }

            delta = next;
        }

        if !loss.is_finite() {
            // Numerical blow-up despite the clipping — reset the offending
            // weights instead of letting NaN poison the checkpoint.
            self.sanitize();
            return 0.0;
        }

        loss
    }
}

/* ================================================================ */
/*  MeMLP — the modular model container                              */
/* ================================================================ */

/// Ring of recent training samples, replayed alongside new ones.
#[derive(Clone, Debug, Default)]
struct Replay {
    buf: [[f32; N_FEATURES]; REPLAY_LEN],
    len: usize,
    head: usize,
    cursor: usize,
}

impl Replay {
    fn push(&mut self, f: [f32; N_FEATURES]) {
        if self.len < REPLAY_LEN {
            self.buf[self.len] = f;
            self.len += 1;
        } else {
            self.buf[self.head] = f;
            self.head = (self.head + 1) % REPLAY_LEN;
        }
    }

    /// Deterministic round-robin over the stored samples.
    fn next(&mut self) -> Option<[f32; N_FEATURES]> {
        if self.len == 0 {
            return None;
        }
        let f = self.buf[self.cursor % self.len];
        self.cursor = self.cursor.wrapping_add(1);
        Some(f)
    }
}

/// Remembers which `training_samples` value the on-disk checkpoint holds, so
/// autosave can skip identical writes. Atomic so the model stays `Sync`.
#[derive(Debug, Default)]
struct SavedMark(AtomicU64);

impl Clone for SavedMark {
    fn clone(&self) -> Self {
        Self(AtomicU64::new(self.0.load(Ordering::Relaxed)))
    }
}

/// The modular container: several specialist MLP heads sharing one
/// JSON checkpoint. Add a new capability by adding a new module here.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MeMLP {
    pub version: u32,
    pub ransomware: Mlp,
    pub lateral: Mlp,
    pub persistence: Mlp,
    /// Number of online training observations applied so far.
    #[serde(default)]
    pub training_samples: u64,
    #[serde(skip)]
    replay: Replay,
    #[serde(skip)]
    saved: SavedMark,
}

/// A single-module verdict attached to alerts and surfaced in the TUI,
/// JSON output and the web dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    /// Module name: "ransomware", "lateral" or "persistence".
    pub module: &'static str,
    /// Argmax class index of the module output.
    pub class: usize,
    /// Human-readable class label.
    pub label: &'static str,
    /// Probability of the winning class (0.0–1.0).
    pub confidence: f32,
}

/// One [`MeMLP::assess`] result: verdicts from every specialist module.
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub ransomware: Verdict,
    pub lateral: Verdict,
    pub persistence: Verdict,
}

impl Assessment {
    /// Compact one-line summary for logs, TUI and plain output, e.g.
    /// `R:ransomware 87% L:normal 99% P:normal 99%`.
    pub fn summary(&self) -> String {
        fn part(v: &Verdict, tag: &str) -> String {
            format!("{}:{} {:.0}%", tag, v.label, v.confidence * 100.0)
        }
        format!(
            "{} {} {}",
            part(&self.ransomware, "R:"),
            part(&self.lateral, "L:"),
            part(&self.persistence, "P:")
        )
    }

    /// True when any module flags its top suspicion class.
    pub fn is_threat(&self) -> bool {
        self.ransomware.class == 2 || self.lateral.class == 1 || self.persistence.class == 1
    }
}

/// Clamp a feature vector into the documented `[0, 1]` range; non-finite
/// values become `0.0`. Keeps one bad embedding from distorting training.
fn clean_features(f: &[f32; N_FEATURES]) -> [f32; N_FEATURES] {
    f.map(|v| if v.is_finite() { v.clamp(0.0, 1.0) } else { 0.0 })
}

/// A pseudo-random behavioural embedding spanning the feature space: half
/// skewed towards low values (like real, mostly-quiet processes), half
/// uniform, with occasional zeroed features.
fn synth_features(state: &mut u64) -> [f32; N_FEATURES] {
    let skewed = rng_next(state) < 0.5;
    let mut f = [0.0f32; N_FEATURES];
    for v in f.iter_mut() {
        let u = rng_next(state);
        *v = if rng_next(state) < 0.2 {
            0.0
        } else if skewed {
            u * u
        } else {
            u
        };
    }
    f
}

/// Learning-rate schedule: full rate for a fresh model, easing to a 25 %
/// floor as the net accumulates experience (keeps long-running agents stable).
fn lr_scale(samples: u64) -> f32 {
    (1.0 / (1.0 + samples as f32 / 2000.0)).max(0.25)
}

impl MeMLP {
    /// Replace every non-finite weight in every module with `0.0`.
    /// Recovery API — also exercised by unit tests after extreme-input training.
    #[allow(dead_code)]
    pub fn sanitize(&mut self) {
        self.ransomware.sanitize();
        self.lateral.sanitize();
        self.persistence.sanitize();
    }

    /// A blank model (deterministic init, no pre-fit). Mostly for tests.
    pub fn untrained() -> Self {
        Self {
            version: MEMLP_VERSION,
            ransomware: Mlp::new(&RANSOMWARE_ARCH),
            lateral: Mlp::new(&LATERAL_ARCH),
            persistence: Mlp::new(&PERSISTENCE_ARCH),
            training_samples: 0,
            replay: Replay::default(),
            saved: SavedMark::default(),
        }
    }

    /// A fresh model: deep ransomware net + lateral + persistence heads,
    /// pre-fitted on [`ANCHORS`] so verdicts are meaningful from the first
    /// event. Deterministic; costs about a millisecond.
    pub fn new() -> Self {
        let mut m = Self::untrained();
        m.prefit();
        m
    }

    /// Deterministic pre-fit: anchors first, then a pass over synthetic
    /// samples drawn across the whole feature space (teacher-labelled), then
    /// the anchors once more. Does not touch `training_samples`.
    fn prefit(&mut self) {
        for _ in 0..ANCHOR_EPOCHS {
            for a in &ANCHORS {
                self.step(a, ANCHOR_LR);
            }
        }
        let mut state = 0xA11C_E5ED_0000_0001u64;
        let synth: Vec<[f32; N_FEATURES]> = (0..SYNTH_SAMPLES)
            .map(|_| synth_features(&mut state))
            .collect();
        for e in 0..SYNTH_EPOCHS {
            let lr = SYNTH_LR * (1.0 - 0.8 * e as f32 / SYNTH_EPOCHS as f32);
            for f in &synth {
                self.step(f, lr);
            }
            for a in &ANCHORS {
                self.step(a, lr);
            }
        }
    }

    /// Load a checkpoint from disk. Returns a fresh model if the file is
    /// missing, and rejects (with an error) unreadable, structurally invalid
    /// or wrong-version checkpoints so a corrupted file never silently resets
    /// training and a tampered one can never crash the agent.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be parsed, fails shape
    /// validation, or if the checkpoint version differs from [`MEMLP_VERSION`].
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let raw = std::fs::read(path)
            .with_context(|| format!("failed to read MeMLP checkpoint {}", path.display()))?;
        Self::from_json_bytes(&raw, &path.display().to_string())
    }

    /// Parse and structurally validate a checkpoint from raw JSON bytes.
    ///
    /// This is the whole untrusted-input surface of checkpoint loading: it never
    /// panics on malformed, truncated or adversarial input and returns an error
    /// instead. `origin` is only used in error messages. Exposed so it can be
    /// fuzzed and unit-tested without touching the filesystem.
    pub fn from_json_bytes(raw: &[u8], origin: &str) -> anyhow::Result<Self> {
        let mut model: MeMLP = serde_json::from_slice(raw)
            .with_context(|| format!("failed to parse MeMLP checkpoint {origin}"))?;
        if model.version != MEMLP_VERSION {
            anyhow::bail!(
                "MeMLP checkpoint {origin} has version {}, expected {} — remove the file to retrain",
                model.version,
                MEMLP_VERSION
            );
        }
        let invalid = || format!("invalid MeMLP checkpoint {origin}");
        model
            .ransomware
            .validate(N_FEATURES, RANSOMWARE_CLASSES, "ransomware")
            .with_context(invalid)?;
        model
            .lateral
            .validate(N_FEATURES, 2, "lateral")
            .with_context(invalid)?;
        model
            .persistence
            .validate(N_FEATURES, 2, "persistence")
            .with_context(invalid)?;
        model.sanitize();
        // Memory now equals disk: the first autosave can be skipped if idle.
        model.saved = SavedMark(AtomicU64::new(model.training_samples.wrapping_add(1)));
        Ok(model)
    }

    /// Persist the checkpoint as compact JSON, atomically (write to a
    /// temporary file, then rename) so a crash mid-save can never leave a
    /// half-written checkpoint. A no-op when nothing was learned since the
    /// last successful save.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written, or if the model holds
    /// non-finite weights (refusing to write a corrupt checkpoint).
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let mark = self.training_samples.wrapping_add(1);
        if self.saved.0.load(Ordering::Relaxed) == mark && path.exists() {
            return Ok(());
        }
        anyhow::ensure!(
            self.ransomware.all_finite()
                && self.lateral.all_finite()
                && self.persistence.all_finite(),
            "refusing to save MeMLP checkpoint with non-finite weights"
        );
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }
        let json = serde_json::to_vec(self)?;
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        std::fs::write(&tmp, &json)
            .with_context(|| format!("failed to write MeMLP checkpoint {}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e).with_context(|| {
                format!("failed to replace MeMLP checkpoint {}", path.display())
            });
        }
        self.saved.0.store(mark, Ordering::Relaxed);
        Ok(())
    }

    /// Total trainable parameters across every module.
    pub fn param_count(&self) -> usize {
        self.ransomware.param_count() + self.lateral.param_count() + self.persistence.param_count()
    }

    /// Classify one behavioural embedding without training. Allocation-free.
    pub fn assess(&self, f: &[f32; N_FEATURES]) -> Assessment {
        let mut acts: Acts = [[0.0; MAX_WIDTH]; MAX_DEPTH + 1];
        Assessment {
            ransomware: ransomware_verdict(self.ransomware.predict(f, &mut acts)),
            lateral: lateral_verdict(self.lateral.predict(f, &mut acts)),
            persistence: persistence_verdict(self.persistence.predict(f, &mut acts)),
        }
    }

    /// One SGD step on all heads against the heuristic teachers.
    fn step(&mut self, f: &[f32; N_FEATURES], lr: f32) -> [f32; 3] {
        let r = self.ransomware.train(
            f,
            &one_hot_arr::<RANSOMWARE_CLASSES>(ransomware_heuristic_target(f)),
            lr,
        );
        let l = self
            .lateral
            .train(f, &one_hot_arr::<2>(lateral_heuristic_target(f)), lr);
        let p = self
            .persistence
            .train(f, &one_hot_arr::<2>(persistence_heuristic_target(f)), lr);
        [r, l, p]
    }

    /// One online training step for all modules against the heuristic
    /// teachers. Returns the per-module losses on the *new* sample (lower =
    /// better fit).
    ///
    /// Besides the new sample, each call also replays one recent sample at
    /// half rate and one rotating anchor at quarter rate, and the learning
    /// rate eases off with experience — so the stream of alert-time samples
    /// refines the model instead of overwriting it.
    pub fn train_observation(&mut self, f: &[f32; N_FEATURES], learning_rate: f32) -> [f32; 3] {
        let f = clean_features(f);
        let lr = learning_rate * lr_scale(self.training_samples);
        let losses = self.step(&f, lr);
        if let Some(old) = self.replay.next() {
            self.step(&old, lr * 0.5);
        }
        self.step(
            &ANCHORS[(self.training_samples as usize) % ANCHORS.len()],
            lr * 0.25,
        );
        self.replay.push(f);
        self.training_samples += 1;
        losses
    }
}

impl Default for MeMLP {
    fn default() -> Self {
        Self::new()
    }
}

/* ================================================================ */
/*  Verdict helpers                                                  */
/* ================================================================ */

const RANSOMWARE_LABELS: [&str; 3] = ["benign", "suspicious", "ransomware"];
const BINARY_LABELS: [&str; 2] = ["normal", "suspect"];

fn make_verdict(module: &'static str, labels: &'static [&'static str], probs: &[f32]) -> Verdict {
    let class = argmax(probs);
    Verdict {
        module,
        class,
        label: labels[class.min(labels.len() - 1)],
        confidence: probs.get(class).copied().unwrap_or(0.0),
    }
}

/// Build a `ransomware`-module verdict from its softmax output.
pub fn ransomware_verdict(probs: &[f32]) -> Verdict {
    make_verdict("ransomware", &RANSOMWARE_LABELS, probs)
}

/// Build a `lateral`-module verdict from its softmax output.
pub fn lateral_verdict(probs: &[f32]) -> Verdict {
    make_verdict("lateral", &BINARY_LABELS, probs)
}

/// Build a `persistence`-module verdict from its softmax output.
pub fn persistence_verdict(probs: &[f32]) -> Verdict {
    make_verdict("persistence", &BINARY_LABELS, probs)
}

/* ================================================================ */
/*  Helpers                                                          */
/* ================================================================ */

/// Numerically-stable softmax, in place. Falls back to a uniform
/// distribution if the input is non-finite.
fn softmax_in_place(x: &mut [f32]) {
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0f32;
    for v in x.iter_mut() {
        *v = (*v - max).exp();
        sum += *v;
    }
    if sum.is_finite() && sum > 0.0 {
        let inv = 1.0 / sum;
        for v in x.iter_mut() {
            *v *= inv;
        }
    } else {
        let u = 1.0 / x.len() as f32;
        x.fill(u);
    }
}

/// Index of the largest probability in a distribution. Ties resolve to the
/// *lowest* index (class 0 = benign / normal), so an uninformative uniform
/// output can never raise a threat verdict.
pub fn argmax(probs: &[f32]) -> usize {
    let mut best = 0;
    for (i, &p) in probs.iter().enumerate().skip(1) {
        if p > probs[best] {
            best = i;
        }
    }
    best
}

/// One-hot vector of length `n` for class `class`.
pub fn one_hot(class: usize, n: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; n];
    if class < n {
        v[class] = 1.0;
    }
    v
}

/// Stack-allocated one-hot.
#[inline]
fn one_hot_arr<const N: usize>(class: usize) -> [f32; N] {
    let mut v = [0.0f32; N];
    if class < N {
        v[class] = 1.0;
    }
    v
}

/* ================================================================ */
/*  Tests                                                            */
/* ================================================================ */

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("talus-memlp-{tag}-{}", std::process::id()))
    }

    #[test]
    fn mlp_forward_is_a_valid_distribution() {
        let mlp = Mlp::new(&RANSOMWARE_ARCH);
        let out = mlp.forward(&[0.5; 10]);
        assert_eq!(out.len(), 3);
        let sum: f32 = out.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4);
        assert!(out.iter().all(|&p| (0.0..=1.0).contains(&p)));
    }

    #[test]
    fn mlp_init_is_deterministic() {
        let a = Mlp::new(&LATERAL_ARCH);
        let b = Mlp::new(&LATERAL_ARCH);
        assert_eq!(a.param_count(), b.param_count());
        assert_eq!(
            a.weights, b.weights,
            "same arch must initialise identically"
        );
    }

    #[test]
    fn mlp_trains_and_loss_decreases() {
        let mut mlp = Mlp::new(&[2, 6, 4, 2]);
        let input = [1.0, 0.0];
        let target = [1.0, 0.0];
        let loss1 = mlp.train(&input, &target, 0.1);
        let loss2 = mlp.train(&input, &target, 0.1);
        assert!(
            loss2 <= loss1 * 1.05,
            "loss should decrease: {loss1} -> {loss2}"
        );
    }

    #[test]
    fn mlp_learns_a_simple_pattern() {
        let mut mlp = Mlp::new(&[2, 8, 4]);
        let (input, target) = ([0.9, 0.1], [0.0, 1.0, 0.0, 0.0]);
        let mut last = f32::MAX;
        for _ in 0..200 {
            last = mlp.train(&input, &target, 0.2);
        }
        assert!(
            last < 0.2,
            "model should fit the pattern, final loss {last}"
        );
        assert_eq!(argmax(&mlp.forward(&input)), 1);
    }

    #[test]
    fn mlp_learns_xor_through_hidden_layers() {
        // Needs a correct hidden-layer gradient: a linear model cannot do XOR.
        let mut mlp = Mlp::new(&[2, 8, 2]);
        let data = [
            ([0.0, 0.0], 0usize),
            ([0.0, 1.0], 1),
            ([1.0, 0.0], 1),
            ([1.0, 1.0], 0),
        ];
        for _ in 0..3000 {
            for (x, y) in &data {
                mlp.train(x, &one_hot(*y, 2), 0.1);
            }
        }
        for (x, y) in &data {
            assert_eq!(argmax(&mlp.forward(x)), *y, "XOR failed for {x:?}");
        }
    }

    #[test]
    fn forward_and_train_tolerate_wrong_input_length() {
        let mut mlp = Mlp::new(&LATERAL_ARCH);
        let short = mlp.forward(&[0.5; 3]);
        let long = mlp.forward(&[0.5; 40]);
        assert_eq!(short.len(), 2);
        assert_eq!(long.len(), 2);
        assert!(mlp.train(&[0.5; 3], &[1.0, 0.0], 0.05).is_finite());
    }

    #[test]
    fn memlp_json_roundtrip() {
        let mut model = MeMLP::new();
        for _ in 0..5 {
            model.train_observation(&[0.5; 10], 0.05);
        }
        let json = serde_json::to_string(&model).unwrap();
        let loaded: MeMLP = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, MEMLP_VERSION);
        assert_eq!(loaded.param_count(), model.param_count());
        assert_eq!(loaded.training_samples, model.training_samples);
        let feats = [0.3, 0.5, 0.6, 0.7, 0.2, 0.4, 0.8, 0.5, 0.1, 0.2];
        let a = loaded.ransomware.forward(&feats);
        let b = model.ransomware.forward(&feats);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert!((x - y).abs() < 1e-5, "roundtrip mismatch: {x} vs {y}");
        }
    }

    #[test]
    fn memlp_checkpoint_save_load_roundtrip() {
        let dir = temp_dir("rt");
        let path = dir.join("memlp.json");
        let mut model = MeMLP::new();
        model.train_observation(&[0.9, 0.9, 0.8, 0.5, 0.5, 0.4, 0.4, 0.9, 0.0, 0.1], 0.05);
        model.save(&path).unwrap();
        let loaded = MeMLP::load(&path).unwrap();
        assert_eq!(loaded.param_count(), model.param_count());
        assert_eq!(loaded.training_samples, model.training_samples);
        assert!(
            !dir.join("memlp.json.tmp").exists(),
            "temp file must be renamed away"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_is_skipped_when_nothing_changed() {
        let dir = temp_dir("skip");
        let path = dir.join("memlp.json");
        let mut model = MeMLP::new();
        model.save(&path).unwrap();
        let t1 = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        model.save(&path).unwrap();
        let t2 = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(t1, t2, "idle autosave must not rewrite the file");
        std::thread::sleep(std::time::Duration::from_millis(20));
        model.train_observation(&[0.5; 10], 0.05);
        model.save(&path).unwrap();
        let t3 = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert!(t3 > t2, "a changed model must be written");
        // A reloaded, untouched model is also idle.
        let reloaded = MeMLP::load(&path).unwrap();
        reloaded.save(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), t3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_recreates_a_deleted_checkpoint() {
        let dir = temp_dir("recreate");
        let path = dir.join("memlp.json");
        let model = MeMLP::new();
        model.save(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        model.save(&path).unwrap();
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn memlp_load_missing_file_returns_fresh_model() {
        let model = MeMLP::load(Path::new("/nonexistent/talus/memlp.json")).unwrap();
        assert_eq!(model.version, MEMLP_VERSION);
        assert_eq!(model.training_samples, 0);
    }

    #[test]
    fn load_rejects_structurally_invalid_checkpoints() {
        let dir = temp_dir("bad");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memlp.json");
        let good = serde_json::to_value(MeMLP::new()).unwrap();

        // Truncated weight buffer.
        let mut v = good.clone();
        v["ransomware"]["weights"][0].as_array_mut().unwrap().pop();
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(MeMLP::load(&path).is_err());

        // Wrong input width.
        let mut v = good.clone();
        v["lateral"]["arch"][0] = serde_json::json!(11);
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(MeMLP::load(&path).is_err());

        // Absurd layer width (would overflow stack scratch).
        let mut v = good.clone();
        v["persistence"]["arch"][1] = serde_json::json!(100_000);
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(MeMLP::load(&path).is_err());

        // Wrong version.
        let mut v = good;
        v["version"] = serde_json::json!(99);
        std::fs::write(&path, v.to_string()).unwrap();
        assert!(MeMLP::load(&path).is_err());

        // Garbage.
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(MeMLP::load(&path).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_pretty_checkpoint_still_loads() {
        // Old releases wrote pretty-printed JSON; the format must stay readable.
        let dir = temp_dir("legacy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memlp.json");
        let model = MeMLP::new();
        std::fs::write(&path, serde_json::to_string_pretty(&model).unwrap()).unwrap();
        let loaded = MeMLP::load(&path).unwrap();
        assert_eq!(loaded.param_count(), model.param_count());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn training_survives_extreme_inputs_without_nan() {
        let mut model = MeMLP::new();
        for _ in 0..50 {
            model.train_observation(
                &[1e6, -1e6, 1e5, -1e5, 1e4, -1e4, 1e3, -1e3, 1.0, 0.0],
                0.05,
            );
        }
        model.train_observation(&[f32::NAN; 10], 0.05);
        model.sanitize();
        let json = serde_json::to_string(&model).unwrap();
        assert!(
            !json.contains("null"),
            "NaN weights would serialise as null: {json}"
        );
        let loaded: MeMLP = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.param_count(), model.param_count());
    }

    #[test]
    fn training_skips_nan_inputs_without_touching_weights() {
        let mut mlp = Mlp::new(&[2, 4, 2]);
        let before = mlp.clone();
        let loss = mlp.train(&[f32::NAN, 0.5], &[1.0, 0.0], 0.1);
        assert!(loss.is_infinite(), "poisoned input must be rejected");
        assert_eq!(mlp.weights, before.weights, "weights must stay untouched");
    }

    #[test]
    fn sanitize_clears_nan_and_inf() {
        let mut mlp = Mlp::new(&[2, 4, 2]);
        mlp.weights[0][0] = f32::NAN;
        mlp.weights[1][1] = f32::INFINITY;
        mlp.biases[0][0] = f32::NEG_INFINITY;
        mlp.sanitize();
        assert!(mlp.weights.iter().all(|w| w.iter().all(|v| v.is_finite())));
        assert!(mlp.biases.iter().all(|b| b.iter().all(|v| v.is_finite())));
    }

    #[test]
    fn save_refuses_non_finite_model() {
        let dir = temp_dir("nan");
        let path = dir.join("memlp.json");
        let mut model = MeMLP::new();
        model.lateral.weights[0][0] = f32::NAN;
        assert!(model.save(&path).is_err());
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pid_features_embedding_stays_in_unit_range() {
        let mut pf = PidFeatures::default();
        for i in 0..120 {
            pf.observe_open(
                &format!("/tmp/file{i}.enc"),
                Some("enc"),
                1.5, // out-of-range entropy must be clamped
            );
            pf.observe_exec(i % 2 == 0);
            pf.observe_fs(i % 3 == 0);
        }
        pf.observe_open("/x", Some("enc"), f64::NAN); // must not poison
        let f = pf.features();
        assert_eq!(f.len(), 10);
        assert!(
            f.iter().all(|v| (0.0..=1.0).contains(v)),
            "features out of range: {f:?}"
        );
    }

    #[test]
    fn pid_features_flags_ransomware_and_persistence_shapes() {
        let mut pf = PidFeatures::default();
        for i in 0..50 {
            pf.observe_open(&format!("/home/u/docs/f{i}.locked"), Some("locked"), 0.9);
        }
        pf.observe_open("/etc/systemd/system/evil.service", Some("service"), 0.4);
        let f = pf.features();
        assert!(
            f[3] > 0.5,
            "ransomware-marker fraction should dominate: {}",
            f[3]
        );
        assert!(f[2] > 0.5, "high-entropy filenames expected: {}", f[2]);
        assert!(f[8] > 0.0, "persistence path should register: {}", f[8]);
        assert_eq!(
            ransomware_heuristic_target(&f),
            2,
            "should be flagged ransomware"
        );
    }

    #[test]
    fn ransomware_extension_match_is_case_insensitive() {
        let mut pf = PidFeatures::default();
        for i in 0..10 {
            pf.observe_open(&format!("/d/f{i}.LOCKED"), Some("LOCKED"), 0.5);
        }
        assert!(pf.features()[3] > 0.9);
    }

    #[test]
    fn pid_features_quiet_process_is_benign() {
        let mut pf = PidFeatures::default();
        for i in 0..6 {
            pf.observe_open(&format!("/home/u/notes/note{i}.txt"), Some("txt"), 0.2);
        }
        let f = pf.features();
        assert_eq!(
            ransomware_heuristic_target(&f),
            0,
            "quiet process must stay benign"
        );
        assert_eq!(persistence_heuristic_target(&f), 0);
        assert_eq!(lateral_heuristic_target(&f), 0);
    }

    #[test]
    fn pid_features_decay_halves_counters() {
        let mut pf = PidFeatures::default();
        for i in 0..10 {
            pf.observe_open(&format!("/tmp/f{i}.log"), Some("log"), 0.1);
        }
        pf.decay();
        assert!(
            (pf.opens - 5.0).abs() < 1e-6,
            "decay must halve opens: {}",
            pf.opens
        );
        assert_eq!(pf.file_bits, [0; 4]);
        assert_eq!(pf.ext_bits, 0);
    }

    #[test]
    fn idle_pids_age_out_of_the_map() {
        let mut pf = PidFeatures::default();
        pf.observe_open("/tmp/a", Some("txt"), 0.1);
        assert!(pf.has_activity());
        for _ in 0..8 {
            pf.decay();
        }
        assert!(!pf.has_activity(), "a lone event must age out within ~8 ticks");
    }

    #[test]
    fn distinct_file_estimate_is_close() {
        let mut pf = PidFeatures::default();
        for i in 0..60 {
            pf.observe_open(&format!("/data/file-{i}.txt"), Some("txt"), 0.3);
        }
        let est = pf.distinct_files();
        assert!(
            (45.0..=75.0).contains(&est),
            "estimate for 60 distinct files was {est}"
        );
        // Re-opening the same file must not inflate the count.
        let mut pf = PidFeatures::default();
        for _ in 0..60 {
            pf.observe_open("/data/same.txt", Some("txt"), 0.3);
        }
        assert!(pf.distinct_files() < 2.0);
    }

    #[test]
    fn persistence_matcher_agrees_with_naive() {
        let paths = [
            "/etc/cron.d/evil",
            "/etc/crontab",
            "/etc/systemd/system/x.service",
            "/usr/lib/systemd/system/x.service",
            "/lib/systemd/system/y",
            "/var/spool/cron/crontabs/root",
            "/home/u/.bashrc",
            "/home/u/.config/autostart/x.desktop",
            "/home/u/.ssh/authorized_keys",
            "/root/.zshrc",
            "/home/u/.profile",
            "/chroot/etc/rc.local",
            "/etc/ld.so.preload",
            "/home/u/docs/report.txt",
            "/usr/bin/ls",
            "/tmp/etcetera/cronos",
            "/home/ü/.bashrc",
            "/home/ü/文档/a.txt",
            "",
            "/",
            "relative/etc/cron",
        ];
        for p in paths {
            let naive = PERSISTENCE_PATHS.iter().any(|f| p.contains(f));
            assert_eq!(is_persistence_path(p), naive, "mismatch for {p:?}");
        }
    }

    #[test]
    fn heuristic_targets_stay_in_range() {
        for i in 0..500u32 {
            let feats = [
                (i as f32 / 500.0).fract(),
                (i as f32 * 0.37).fract() * 0.5,
                (i as f32 * 0.71).fract(),
                (i as f32 * 0.43).fract(),
                0.5,
                0.5,
                0.7,
                0.5,
                (i as f32 * 0.11).fract(),
                (i as f32 * 0.23).fract(),
            ];
            assert!(ransomware_heuristic_target(&feats) < RANSOMWARE_CLASSES);
            assert!(lateral_heuristic_target(&feats) < 2);
            assert!(persistence_heuristic_target(&feats) < 2);
        }
    }

    #[test]
    fn assess_produces_all_module_verdicts() {
        let model = MeMLP::new();
        let a = model.assess(&[0.5; 10]);
        assert_eq!(a.ransomware.module, "ransomware");
        assert_eq!(a.lateral.module, "lateral");
        assert_eq!(a.persistence.module, "persistence");
        assert!(a.ransomware.confidence >= 0.0 && a.ransomware.confidence <= 1.0);
    }

    #[test]
    fn param_count_matches_architectures() {
        let model = MeMLP::new();
        let expected = 10 * 24
            + 24
            + 24 * 16
            + 16
            + 16 * 3
            + 3
            + 10 * 12
            + 12
            + 12 * 2
            + 2
            + 10 * 12
            + 12
            + 12 * 2
            + 2;
        assert_eq!(model.param_count(), expected);
    }

    #[test]
    fn anchors_cover_every_class_of_every_head() {
        let mut r = [false; 3];
        let mut l = [false; 2];
        let mut p = [false; 2];
        for a in &ANCHORS {
            r[ransomware_heuristic_target(a)] = true;
            l[lateral_heuristic_target(a)] = true;
            p[persistence_heuristic_target(a)] = true;
        }
        assert!(r.iter().all(|&x| x), "ransomware classes missing: {r:?}");
        assert!(l.iter().all(|&x| x), "lateral classes missing: {l:?}");
        assert!(p.iter().all(|&x| x), "persistence classes missing: {p:?}");
    }

    #[test]
    fn fresh_model_is_useful_out_of_the_box() {
        let model = MeMLP::new();
        assert_eq!(model.training_samples, 0, "pre-fit must not count as live training");
        for a in &ANCHORS {
            let v = model.assess(a);
            assert_eq!(v.ransomware.class, ransomware_heuristic_target(a), "{a:?}");
            assert_eq!(v.lateral.class, lateral_heuristic_target(a), "{a:?}");
            assert_eq!(v.persistence.class, persistence_heuristic_target(a), "{a:?}");
        }
    }

    #[test]
    fn fresh_model_generalises_beyond_its_anchors() {
        // Agreement with the teachers on samples the model has never seen.
        let model = MeMLP::new();
        let mut state = 0xDEAD_BEEFu64;
        let (mut r, mut l, mut p) = (0usize, 0usize, 0usize);
        let n = 3000;
        for _ in 0..n {
            let f = synth_features(&mut state);
            let a = model.assess(&f);
            r += usize::from(a.ransomware.class == ransomware_heuristic_target(&f));
            l += usize::from(a.lateral.class == lateral_heuristic_target(&f));
            p += usize::from(a.persistence.class == persistence_heuristic_target(&f));
        }
        let rate = |x: usize| x as f32 / n as f32;
        println!("agreement: R {:.3} L {:.3} P {:.3}", rate(r), rate(l), rate(p));
        assert!(rate(r) > 0.85, "ransomware agreement only {:.3}", rate(r));
        assert!(rate(l) > 0.9, "lateral agreement only {:.3}", rate(l));
        assert!(rate(p) > 0.9, "persistence agreement only {:.3}", rate(p));
    }

    #[test]
    fn online_training_does_not_forget_benign() {
        let mut model = MeMLP::new();
        let ransom = [0.9, 0.1, 0.9, 0.8, 0.5, 0.6, 0.5, 0.9, 0.0, 0.0];
        for _ in 0..500 {
            model.train_observation(&ransom, 0.03);
        }
        assert_eq!(model.assess(&ransom).ransomware.class, 2);
        assert_eq!(
            model.assess(&ANCHORS[0]).ransomware.class,
            0,
            "an idle process must still read benign after a ransomware-only stream"
        );
        assert!(!model.assess(&ANCHORS[0]).is_threat());
    }

    #[test]
    fn uniform_output_never_raises_a_threat() {
        assert_eq!(argmax(&[1.0 / 3.0; 3]), 0);
        assert_eq!(ransomware_verdict(&[0.5, 0.5, 0.0]).label, "benign");
        let mut x = [f32::NAN, 1.0, 2.0];
        softmax_in_place(&mut x);
        assert!((x.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    }

    #[test]
    fn replay_ring_is_bounded_and_round_robin() {
        let mut r = Replay::default();
        assert!(r.next().is_none());
        for i in 0..(REPLAY_LEN * 2) {
            r.push([i as f32; N_FEATURES]);
        }
        assert_eq!(r.len, REPLAY_LEN);
        let seen: std::collections::HashSet<u32> =
            (0..REPLAY_LEN).map(|_| r.next().unwrap()[0] as u32).collect();
        assert_eq!(seen.len(), REPLAY_LEN);
    }

    #[test]
    fn checkpoint_roundtrips_through_json_bytes() {
        let model = MeMLP::new();
        let raw = serde_json::to_vec(&model).unwrap();
        let back = MeMLP::from_json_bytes(&raw, "test").unwrap();
        assert_eq!(back.training_samples, model.training_samples);
        assert_eq!(back.param_count(), model.param_count());
    }

    #[test]
    fn malformed_checkpoints_error_instead_of_panicking() {
        let good = serde_json::to_vec(&MeMLP::new()).unwrap();
        // Every truncation point must be a clean error, never a panic.
        for cut in (0..good.len()).step_by(997) {
            assert!(MeMLP::from_json_bytes(&good[..cut], "trunc").is_err());
        }
        let bad_inputs: [&[u8]; 6] = [b"", b"null", b"[]", b"{}", b"\xff\xfe\x00", b"{\"version\":1}"];
        for bad in bad_inputs {
            assert!(MeMLP::from_json_bytes(bad, "bad").is_err());
        }
    }

    #[test]
    fn checkpoint_with_wrong_shape_or_version_is_rejected() {
        let mut v: serde_json::Value = serde_json::to_value(MeMLP::new()).unwrap();
        v["version"] = serde_json::json!(MEMLP_VERSION + 1);
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(MeMLP::from_json_bytes(&raw, "ver").is_err());

        let mut v: serde_json::Value = serde_json::to_value(MeMLP::new()).unwrap();
        v["ransomware"]["arch"] = serde_json::json!([N_FEATURES, 1_000_000_000u64, RANSOMWARE_CLASSES]);
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(MeMLP::from_json_bytes(&raw, "huge").is_err(), "absurd widths must not allocate or pass");

        let mut v: serde_json::Value = serde_json::to_value(MeMLP::new()).unwrap();
        v["lateral"]["weights"] = serde_json::json!([[0.0]]);
        let raw = serde_json::to_vec(&v).unwrap();
        assert!(MeMLP::from_json_bytes(&raw, "short").is_err());
    }
}
