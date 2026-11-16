#!/usr/bin/env python3
"""Build the 10-feature MeMLP training records from CSU-Ransomware-Data.

The raw dataset is ETW-derived (Windows). Talus runs on Linux syscalls, so the
19 columns are projected onto the same ten [0,1] features the live monitor
computes. That projection is a proxy, not an equivalence: see README.md.

Output: csu-windows.jsonl, one JSON object per behavioural window:

    {"family": "...", "label": 2, "split": "train", "features": [...], ...}

The script is deterministic (fixed seeds) and keeps only derived features, not
raw event rows. It does not download anything.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

FEATURE_NAMES = [
    "open_rate",          # f0: file-related events per window / 100
    "exec_network_rate",  # f1: (process + network) events / window * 0.5
    "name_entropy",       # f2: mean file_name_entropy / 5
    "marker_ext_ratio",   # f3: extension_similarity (proxy)
    "artefact_diversity", # f4: delete-and-archive ratio (proxy)
    "fs_event_rate",      # f5: create+delete+time-change events / window
    "destructive_ratio",  # f6: (delete + time-change) / mutation events
    "file_diversity",     # f7: directory_depth / 21 (proxy for distinct files)
    "persistence_ratio",  # f8: registry writes / window (persistence proxy)
    "network_ratio",      # f9: network events / window
]

# Order matches the CSV columns used by the projection.
CSV_FEATURES = [
    "File_Delete_archived",
    "File_created",
    "File_creation_time_changed",
    "Pipe_Created",
    "Process_Create",
    "Registry_value_set",
    "process-related",
    "network-related",
    "file-related",
    "suspicious_path",
    "system_executable",
    "path_length",
    "directory_depth",
    "process_vs_parent_freq_ratio",
    "process_name_length",
    "executable_depth_diff",
    "parent_is_system_executable",
    "extension_similarity",
    "file_name_entropy",
]

PHASES = [
    ("drift_phase1.csv", "train"),
    ("drift_phase2.csv", "train"),
    ("drift_phase3a.csv", "train"),
    ("drift_phase3b.csv", "val"),
    ("drift_phase3c.csv", "test"),
]

HASH_SUFFIX = re.compile(r"-[0-9a-f]{64}$")
BASE_NAME = re.compile(r"^[A-Za-z0-9_.-]+")


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def family_base(name: str) -> str:
    """`Medusa-<sha256>` -> `Medusa`; `goodware` stays `goodware`."""
    return HASH_SUFFIX.sub("", name)


def load_groups(path: Path) -> dict[str, np.ndarray]:
    """Read one drift CSV into family -> float32 matrix of the 19 columns."""
    groups: dict[str, list[list[float]]] = defaultdict(list)
    with path.open(newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        required = set(CSV_FEATURES) | {"target-class-name"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"{path}: missing columns {sorted(missing)}")
        for row in reader:
            name = (row.get("target-class-name") or "").strip()
            if not name:
                continue
            try:
                values = [float(row[column]) for column in CSV_FEATURES]
            except (TypeError, ValueError):
                continue
            if not all(np.isfinite(values)):
                continue
            groups[name].append(values)
    return {
        name: np.asarray(rows, dtype=np.float32)
        for name, rows in groups.items()
        if rows
    }


def aggregate(rows: np.ndarray) -> list[float]:
    """Project 19 ETW count columns to the ten live features."""
    k = max(len(rows), 1)
    (
        deleted,
        created,
        time_changed,
        _pipe,
        process,
        registry,
        process_related,
        network,
        file_related,
        _suspicious,
        _system,
        _path_len,
        depth,
        _parent_freq,
        _name_len,
        _depth_diff,
        _parent_system,
        extension_similarity,
        entropy,
    ) = rows.T

    mutation = created + deleted + time_changed
    mutation_total = float(mutation.sum())
    return [
        float(file_related.mean()),
        float((process.sum() + network.sum()) / k * 0.5),
        float(entropy.mean() / 5.0),
        float(extension_similarity.mean()),
        float(deleted.mean()),
        float(mutation.mean()),
        float((deleted.sum() + time_changed.sum()) / max(mutation_total, 1.0)),
        float(depth.mean() / 21.0),
        float(registry.mean()),
        float(network.mean()),
    ]


def make_windows(
    groups: dict[str, np.ndarray],
    *,
    split: str,
    phase: str,
    per_family: int,
    per_good: int,
    seed: int,
    mixed_ratio: float,
) -> list[dict]:
    rng = np.random.default_rng(seed)
    records: list[dict] = []
    names = sorted(groups)
    for name in names:
        rows = groups[name]
        count = per_good if name == "goodware" else per_family
        for _ in range(count):
            window_seed = int(rng.integers(0, 2**31 - 1))
            local = np.random.default_rng(window_seed)
            k = int(local.choice([20, 30, 40, 60, 80, 100]))
            idx = local.integers(0, len(rows), k)
            features = aggregate(rows[idx])
            label = 0 if name == "goodware" else 2
            label_name = "benign" if label == 0 else "ransomware"

            # Mixed windows teach the model the suspicious middle class.
            if local.random() < mixed_ratio:
                opposite = [
                    other
                    for other, other_rows in groups.items()
                    if (other == "goodware") != (name == "goodware")
                ]
                if opposite:
                    other = opposite[int(local.integers(0, len(opposite)))]
                    other_rows = groups[other]
                    idx2 = local.integers(0, len(other_rows), k)
                    weight = float(local.uniform(0.25, 0.75))
                    features = [
                        round(a * (1.0 - weight) + b * weight, 6)
                        for a, b in zip(features, aggregate(other_rows[idx2]))
                    ]
                    label, label_name = 1, "suspicious"

            records.append(
                {
                    "id": stable_hash(f"{phase}:{name}:{window_seed}")[:16],
                    "family": name,
                    "family_name": family_base(name),
                    "label": label,
                    "label_name": label_name,
                    "split": split,
                    "phase": phase,
                    "window_rows": k,
                    "window_seed": window_seed,
                    "features": [round(v, 6) for v in features],
                }
            )
    return records


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache",
        type=Path,
        default=Path("../../.cache/mlran"),
        help="directory holding CSU-Ransomware-Data CSVs (default: ../../.cache/mlran)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/training/csu-windows.jsonl"),
        help="output JSONL path",
    )
    parser.add_argument("--per-family", type=int, default=160)
    parser.add_argument("--per-good", type=int, default=5000)
    parser.add_argument("--mixed-ratio", type=float, default=0.12)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    if not args.cache.is_dir():
        raise SystemExit(f"cache directory not found: {args.cache}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    all_records: list[dict] = []
    sources: list[dict] = []
    for index, (filename, split) in enumerate(PHASES):
        path = args.cache / filename
        if not path.is_file():
            raise SystemExit(f"missing source CSV: {path}")
        groups = load_groups(path)
        records = make_windows(
            groups,
            split=split,
            phase=filename.removesuffix(".csv"),
            per_family=args.per_family,
            per_good=args.per_good,
            seed=args.seed + index,
            mixed_ratio=args.mixed_ratio,
        )
        all_records.extend(records)
        sources.append(
            {
                "file": filename,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "rows": int(sum(len(rows) for rows in groups.values())),
                "families": len(groups),
                "split": split,
            }
        )
        print(f"{filename}: {len(groups)} families, {len(records)} windows -> {split}")

    with args.out.open("w", encoding="utf-8") as handle:
        for record in all_records:
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    counts = Counter(
        (record["split"], record["label_name"]) for record in all_records
    )
    family_counts = Counter(
        (record["split"], record["family_name"]) for record in all_records
    )
    manifest = {
        "dataset": "CSU-Ransomware-Data (drift-aware behavioural windows)",
        "source_url": "https://github.com/CSCRC-SCREED/CSU-Ransomware-Data",
        "license": "unknown (repository metadata has no licence)",
        "warning": (
            "Derived features only. Verify redistribution/training rights with "
            "the dataset authors before shipping this file or a model trained on it."
        ),
        "feature_names": FEATURE_NAMES,
        "feature_mapping": "19 ETW columns -> 10 live MeMLP features (proxy)",
        "split_strategy": "temporal drift: phase1/2/3a train, phase3b val, phase3c test",
        "seed": args.seed,
        "output": {
            "file": args.out.name,
            "bytes": args.out.stat().st_size,
            "sha256": sha256_file(args.out),
            "records": len(all_records),
        },
        "sources": sources,
        "unique_family_names": sorted(
            {record["family_name"] for record in all_records}
        ),
        "label_counts": {
            f"{split}/{label}": count
            for (split, label), count in sorted(counts.items())
        },
        "family_counts": {
            f"{split}/{family}": count
            for (split, family), count in sorted(family_counts.items())
        },
    }
    manifest_path = args.out.with_name("manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{args.out}: {len(all_records)} records, {args.out.stat().st_size} bytes")
    print(f"{manifest_path}: source hashes + counts")
    print("labels:", dict(counts))


if __name__ == "__main__":
    main()
