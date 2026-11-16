# MeMLP training data

This directory turns the public **CSU-Ransomware-Data** corpus into the same
10-feature vectors the live agent computes, then trains the `ransomware` head
of MeMLP from those vectors. The result is embedded in the binary as
`data/memlp/ransomware-v1.json` (18 KB, 1,031 parameters).

Nothing here downloads data automatically, and no raw corpus is committed.

## Files

| File | Size | What it is |
|---|---:|---|
| `prepare.py` | 11 KB | Deterministic 19-column → 10-feature window builder |
| `train.py` | 15 KB | Joint CSU + teacher-synthetic + anchor training |
| `csu-windows.jsonl` | 13.5 MiB | 48,040 derived windows (7 ransomware families + goodware), one JSON object per line |
| `manifest.json` | 3 KB | Source SHA-256, row/family counts, feature map, output hash |
| `report.json` | 4 KB | Held-out metrics, anchor check, per-family results |
| `../memlp/base-v1.json` | 12 KB | Rust pre-fit used as the training starting point |
| `../memlp/ransomware-v1.json` | 18 KB | Exported checkpoint embedded in the agent |

The whole derived set is ~13.6 MiB. The optional raw cache used here measured
873 MB (`du -sb`: 915,132,603 bytes), including CSU drift CSVs and the MLRan
ZIP/extract. Raw cache plus derived set stays under the 1 GB budget and the raw
files remain outside the repository.

## Reproduce

The CSU drift CSVs are expected in `../../.cache/mlran/` (override with
`--cache`). They are the `dataset/Drift-Anomaly-Versions/*.csv` files from
<https://github.com/CSCRC-SCREED/CSU-Ransomware-Data>.

```bash
python3 data/training/prepare.py
python3 data/training/train.py
cargo run --release --example check_memlp -- data/memlp/ransomware-v1.json
```

Both scripts use fixed seeds. The checked-in checkpoint and report were
produced by exactly these commands; `train.py` refuses to write a checkpoint if
any built-in anchor lands in the wrong class.

## What a record contains

```json
{"id":"…","family":"Medusa-<sha256>","family_name":"Medusa","label":2,
 "label_name":"ransomware","split":"train","phase":"drift_phase1",
 "window_rows":60,"window_seed":123456,
 "features":[0.53,0.04,0.61,0.03,0.41,0.38,0.57,0.31,0.0,0.0]}
```

The family hash is preserved in `family`; `family_name` strips it for
aggregation. Windows are sampled with a recorded seed, so the selection can be
replayed against the same CSV. Labels are `0` benign, `1` suspicious/mixed and
`2` ransomware. Twelve percent of windows deliberately blend a benign and a
ransomware window to populate the middle class.

| Feature | Live meaning | CSU projection |
|---|---|---|
| `f0` open rate | opens/s ÷ 100 | mean `file-related` |
| `f1` exec+network rate | execs/s ÷ 20 | `(process + network) / rows × 0.5` |
| `f2` name entropy | normalised Shannon entropy | `file_name_entropy / 5` |
| `f3` marker extensions | marker opens ÷ opens | `extension_similarity` |
| `f4` artefact diversity | distinct marker extensions / note hit | `File_Delete_archived` |
| `f5` fs mutation rate | fs events/s ÷ 50 | mean create+delete+time-change |
| `f6` destructive fraction | destructive ÷ fs events | `(delete + time_changed) / mutations` |
| `f7` distinct-file spread | distinct files ÷ opens | `directory_depth / 21` |
| `f8` persistence hits | autostart hits ÷ opens | `Registry_value_set` |
| `f9` network fraction | network events ÷ execs | `network-related` |

**This is a proxy, not an equivalence.** CSU is Windows ETW-derived; Talus
observes Linux syscalls. `f3`, `f4`, `f5`, `f7` and `f8` are the weakest
mappings. The model therefore learns a data-informed prior, while the
heuristically labelled anchors keep protecting quiet and ordinary processes.
No real Linux ransomware traces were available for this build.

The model is scored **on alerts**, not on every process. Bulk benign jobs
(compilers, indexers, backups) can share the high open-rate/distinct-file shape
of encryption and may read as ransomware; that is a limit of the rate features,
not something the CSU labels can fix. Keep such jobs in the monitor's ignore
list or tune the threshold for them. The held-out numbers below describe the
CSU windows, not a claim of zero false positives on every Linux workload.

## Training recipe

* Starting point: the deterministic Rust pre-fit (`base-v1.json`).
* CSU windows: all classes balanced to the largest class (39,690 rows).
* Synthetic feature-space samples: 12,000, labelled by the transparent teacher,
  weight `0.35`.
* Noisy anchor copies: 6,000 (σ = 0.04), weight `2.0`.
* Adam, 50 epochs, learning rate `0.001`, batch 256, seed `2026`.
* Only the ransomware head changes; lateral and persistence keep base weights.

## Measured result

Held-out **phase 3c**, 10,280 windows from seven base families (34 hashed
variants, including `goodware`), never used in training:

| Metric | Value |
|---|---:|
| Binary AUC | 0.9965 |
| Ransomware recall (class 2) | 90.31% |
| Benign false positives (class 2) | 0.00% |
| Threat recall (class 1 or 2) | 96.85% |
| Benign flagged suspicious or worse | 7.89% |
| 3-class accuracy | 90.59% |

Validation phase 3b: AUC 0.9995, ransomware recall 94.85%, benign FP 0.05%.
The built-in anchors match the teacher **11/11**. Anchor-perturbation accuracy
is 100% at σ ≤ 0.02, 99.5% at σ = 0.05 (4000 draws each; see `report.json`).

Weakest held-out families are Medusa (68.7% class-2 recall, 72.1% when the
suspicious class counts as a threat) and BlackBasta (73.4% class-2, 99.4%
threat). Per-family numbers are in `report.json`; do not quote the aggregate
without them. Coverage is only seven ransomware families (Akira, BlackBasta,
CyberVolk, LockBit, Lynx, Medusa, Meow) plus goodware; this is not a
64-family model and the report must not be read as one.

## Licence and shipping

CSU-Ransomware-Data's repository metadata has **no licence**. This directory
therefore ships derived aggregates, not raw rows, and the checkpoint is a
derivative. Confirm training and redistribution rights with the dataset authors
before commercial distribution. If that is not acceptable, retrain with a
licensed corpus; the pipeline and the anchor gate stay the same.

MLRan (<https://zenodo.org/records/23403681>, CC BY 4.0) was evaluated as a
second source: 4,880 samples, 64 families and 483 binary API/registry/file
features. It was **not** used for this checkpoint because mapping Windows API
presence onto the Linux syscall features is weaker than the CSU projection and
would add family names the 10-feature head cannot learn to separate. Its family
metadata remains useful for the Externum knowledge base, not as evidence that
this checkpoint covers 64 families.
