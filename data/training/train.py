#!/usr/bin/env python3
"""Train the ransomware head of MeMLP on CSU-derived windows.

Starting from the deterministic Rust pre-fit (base-v1.json), this mixes:

* CSU windows (real labels, family provenance) from prepare.py,
* synthetic feature-space samples labelled by Talus' transparent teacher,
* noisy copies of the built-in anchors, so the false-positive guards survive.

Only the 10->24->16->3 ransomware head is retrained. The lateral and
persistence heads stay at their base weights; the CSU columns are too weak a
proxy for those behaviours to justify changing them.

Dependencies: numpy only. Deterministic for a fixed seed and input file.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ANCHORS = np.array(
    [
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
    ],
    dtype=np.float32,
)


def teacher(features: np.ndarray) -> np.ndarray:
    score = (
        3.0 * features[:, 0]
        + 2.0 * features[:, 3]
        + 1.5 * features[:, 7] * features[:, 0]
        + features[:, 6]
        + features[:, 2]
        + 0.5 * features[:, 4]
    )
    return np.where(score >= 2.0, 2, np.where(score >= 1.0, 1, 0)).astype(int)


ANCHOR_LABELS = teacher(ANCHORS)


def forward(model: dict, features: np.ndarray) -> np.ndarray:
    hidden = features.copy()
    arch = model["arch"]
    for layer in range(len(arch) - 1):
        weights = np.asarray(model["weights"][layer], dtype=np.float32).reshape(
            arch[layer], arch[layer + 1]
        )
        biases = np.asarray(model["biases"][layer], dtype=np.float32)
        hidden = hidden @ weights + biases
        if layer == len(arch) - 2:
            hidden = np.exp(hidden - hidden.max(axis=1, keepdims=True))
            hidden /= hidden.sum(axis=1, keepdims=True)
        else:
            hidden = np.maximum(hidden, 0.0)
    return hidden


def one_hot(labels: np.ndarray, classes: int) -> np.ndarray:
    out = np.zeros((len(labels), classes), dtype=np.float32)
    out[np.arange(len(labels)), labels] = 1.0
    return out


def synth_features(count: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    features = []
    for _ in range(count):
        if rng.random() < 0.5:
            row = rng.random(10) ** 2
        else:
            row = rng.random(10)
        row[rng.random(10) < 0.2] = 0.0
        features.append(row)
    return np.array(features, dtype=np.float32)


def noisy_anchors(count: int, seed: int, sigma: float = 0.04) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    features = []
    labels = []
    for _ in range(count):
        index = int(rng.integers(len(ANCHORS)))
        row = np.clip(ANCHORS[index] + rng.normal(0.0, sigma, 10), 0.0, 1.0)
        features.append(row)
        labels.append(ANCHOR_LABELS[index])
    return np.array(features, dtype=np.float32), np.array(labels)


def balance(labels: np.ndarray, per_class: int, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    picks = []
    for label in np.unique(labels):
        indices = np.where(labels == label)[0]
        target = per_class if per_class > 0 else int((labels == label).sum())
        picks.append(rng.choice(indices, target, replace=len(indices) < target))
    return np.concatenate(picks)


def train_head(
    base: dict,
    features: np.ndarray,
    labels: np.ndarray,
    *,
    epochs: int,
    learning_rate: float,
    sample_weights: np.ndarray,
    seed: int,
    batch_size: int = 256,
) -> dict:
    head = base["ransomware"]
    arch = head["arch"]
    weights = [
        np.asarray(layer, dtype=np.float32).reshape(arch[i], arch[i + 1])
        for i, layer in enumerate(head["weights"])
    ]
    biases = [np.asarray(layer, dtype=np.float32) for layer in head["biases"]]
    m_w = [np.zeros_like(w) for w in weights]
    v_w = [np.zeros_like(w) for w in weights]
    m_b = [np.zeros_like(b) for b in biases]
    v_b = [np.zeros_like(b) for b in biases]
    step = 0
    rng = np.random.default_rng(seed)
    classes = arch[-1]

    for _epoch in range(epochs):
        order = rng.permutation(len(features))
        for start in range(0, len(order), batch_size):
            batch = order[start : start + batch_size]
            x = features[batch]
            y = labels[batch]
            w = sample_weights[batch]

            acts = [x]
            hidden = x
            for layer in range(len(arch) - 1):
                hidden = hidden @ weights[layer] + biases[layer]
                if layer == len(arch) - 2:
                    hidden = np.exp(hidden - hidden.max(axis=1, keepdims=True))
                    hidden /= hidden.sum(axis=1, keepdims=True)
                else:
                    hidden = np.maximum(hidden, 0.0)
                acts.append(hidden)

            target = one_hot(y, classes) * 0.93 + 0.07 / classes
            delta = (acts[-1] - target) * (w[:, None] / max(w.sum(), 1e-9))
            grad_w = [None] * len(weights)
            grad_b = [None] * len(biases)
            for layer in range(len(arch) - 2, -1, -1):
                grad_w[layer] = acts[layer].T @ delta
                grad_b[layer] = delta.sum(axis=0)
                if layer > 0:
                    delta = (delta @ weights[layer].T) * (acts[layer] > 0)

            step += 1
            for layer in range(len(weights)):
                m_w[layer] = 0.9 * m_w[layer] + 0.1 * grad_w[layer]
                v_w[layer] = 0.999 * v_w[layer] + 0.001 * grad_w[layer] ** 2
                weights[layer] -= learning_rate * (
                    m_w[layer] / (1.0 - 0.9**step)
                ) / (np.sqrt(v_w[layer] / (1.0 - 0.999**step)) + 1e-8)
                m_b[layer] = 0.9 * m_b[layer] + 0.1 * grad_b[layer]
                v_b[layer] = 0.999 * v_b[layer] + 0.001 * grad_b[layer] ** 2
                biases[layer] -= learning_rate * (
                    m_b[layer] / (1.0 - 0.9**step)
                ) / (np.sqrt(v_b[layer] / (1.0 - 0.999**step)) + 1e-8)

    return {
        "version": 1,
        "arch": arch,
        "weights": [layer.flatten().tolist() for layer in weights],
        "biases": [layer.flatten().tolist() for layer in biases],
    }


def binary_auc(prob: np.ndarray, positive: np.ndarray) -> float:
    order = np.argsort(prob, kind="mergesort")
    sorted_prob = prob[order]
    ranks = np.empty(len(prob), dtype=float)
    i = 0
    while i < len(prob):
        j = i + 1
        while j < len(prob) and sorted_prob[j] == sorted_prob[i]:
            j += 1
        ranks[order[i:j]] = (i + 1 + j) / 2.0
        i = j
    pos = positive.sum()
    neg = len(positive) - pos
    if pos == 0 or neg == 0:
        return 0.0
    return float((ranks[positive].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def metrics(model: dict, features: np.ndarray, labels: np.ndarray) -> dict:
    probability = forward(model, features)
    predicted = probability.argmax(axis=1)
    positive = labels == 2
    benign = labels == 0
    return {
        "windows": int(len(labels)),
        "auc": round(binary_auc(probability[:, 2], positive), 4),
        "ransomware_recall": round(float((predicted[positive] == 2).mean()), 4)
        if positive.any()
        else 0.0,
        "benign_false_positive": round(float((predicted[benign] == 2).mean()), 4)
        if benign.any()
        else 0.0,
        "threat_recall": round(float((predicted[positive] >= 1).mean()), 4)
        if positive.any()
        else 0.0,
        "benign_suspicious_or_worse": round(float((predicted[benign] >= 1).mean()), 4)
        if benign.any()
        else 0.0,
        "accuracy_3class": round(float((predicted == labels).mean()), 4),
    }


def per_family_metrics(
    model: dict, features: np.ndarray, labels: np.ndarray, families: list[str]
) -> dict:
    output = forward(model, features)
    probability = output[:, 2]
    predicted = output.argmax(axis=1)
    grouped: dict[str, list[int]] = defaultdict(list)
    for label, family in zip(labels, families):
        grouped[family].append(int(label))
    out = {}
    for family in sorted(grouped):
        indices = [i for i, name in enumerate(families) if name == family]
        idx = np.asarray(indices)
        ransomware = labels[idx] == 2
        benign = labels[idx] == 0
        out[family] = {
            "windows": int(len(idx)),
            "labels": dict(Counter(labels[idx].tolist())),
            "mean_ransomware_probability": round(float(probability[idx].mean()), 4),
            "ransomware_recall": round(float((predicted[idx][ransomware] == 2).mean()), 4)
            if ransomware.any()
            else None,
            "threat_recall": round(float((predicted[idx][ransomware] >= 1).mean()), 4)
            if ransomware.any()
            else None,
            "benign_false_positive": round(float((predicted[idx][benign] == 2).mean()), 4)
            if benign.any()
            else None,
        }
    return out


def anchor_check(model: dict) -> dict:
    predicted = forward(model, ANCHORS).argmax(axis=1)
    return {
        "expected": ANCHOR_LABELS.tolist(),
        "predicted": predicted.tolist(),
        "matches": int((predicted == ANCHOR_LABELS).sum()),
        "total": int(len(ANCHOR_LABELS)),
    }


def noise_check(model: dict, seed: int = 100) -> dict:
    out = {}
    for sigma in (0.01, 0.02, 0.05, 0.1):
        features, labels = noisy_anchors(4000, seed, sigma)
        predicted = forward(model, features).argmax(axis=1)
        out[str(sigma)] = {
            "accuracy": round(float((predicted == labels).mean()), 4),
            "ransomware_recall": round(float((predicted[labels == 2] == 2).mean()), 4),
            "benign_precision": round(float((predicted[labels == 0] == 0).mean()), 4),
        }
    return out


def load_split(path: Path) -> dict[str, tuple[np.ndarray, np.ndarray, list[str], list[str]]]:
    features: dict[str, list[list[float]]] = defaultdict(list)
    labels: dict[str, list[int]] = defaultdict(list)
    families: dict[str, list[str]] = defaultdict(list)
    ids: dict[str, list[str]] = defaultdict(list)
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            split = record["split"]
            features[split].append(record["features"])
            labels[split].append(record["label"])
            families[split].append(record["family_name"])
            ids[split].append(record["id"])
    return {
        split: (
            np.asarray(features[split], dtype=np.float32),
            np.asarray(labels[split], dtype=np.int64),
            families[split],
            ids[split],
        )
        for split in features
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/training/csu-windows.jsonl"))
    parser.add_argument("--base", type=Path, default=Path("data/memlp/base-v1.json"))
    parser.add_argument("--out", type=Path, default=Path("data/memlp/ransomware-v1.json"))
    parser.add_argument("--report", type=Path, default=Path("data/training/report.json"))
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--per-class", type=int, default=0, help="0 = use the largest class count")
    parser.add_argument("--synthetic", type=int, default=12000)
    parser.add_argument("--anchor-noise", type=int, default=6000)
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    base = json.loads(args.base.read_text(encoding="utf-8"))
    splits = load_split(args.data)
    train_x, train_y, _, _ = splits["train"]
    largest = int(max((train_y == label).sum() for label in (0, 1, 2)))
    picks = balance(train_y, args.per_class or largest, args.seed)
    csu_x, csu_y = train_x[picks], train_y[picks]

    synthetic_x = synth_features(args.synthetic, args.seed + 1)
    synthetic_y = teacher(synthetic_x)
    anchor_x, anchor_y = noisy_anchors(args.anchor_noise, args.seed + 2)

    features = np.concatenate([csu_x, synthetic_x, anchor_x])
    labels = np.concatenate([csu_y, synthetic_y, anchor_y])
    weights = np.concatenate(
        [
            np.ones(len(csu_x), dtype=np.float32),
            np.full(len(synthetic_x), 0.35, dtype=np.float32),
            np.full(len(anchor_x), 2.0, dtype=np.float32),
        ]
    )

    print(
        f"training rows: csu={len(csu_x)} synthetic={len(synthetic_x)} "
        f"anchors={len(anchor_x)} labels={np.bincount(labels).tolist()}"
    )
    model = train_head(
        base,
        features,
        labels,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        sample_weights=weights,
        seed=args.seed,
    )
    checkpoint = {
        "version": 1,
        "ransomware": model,
        "lateral": base["lateral"],
        "persistence": base["persistence"],
        "training_samples": 0,
    }

    report = {
        "dataset": str(args.data),
        "base": str(args.base),
        "seed": args.seed,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "training_rows": {
            "csu": int(len(csu_x)),
            "synthetic": int(len(synthetic_x)),
            "anchor_noise": int(len(anchor_x)),
        },
        "metrics": {
            split: metrics(model, values[0], values[1])
            for split, values in splits.items()
        },
        "anchors": anchor_check(model),
        "anchor_noise": noise_check(model, args.seed + 3),
        "test_per_family": per_family_metrics(
            model, splits["test"][0], splits["test"][1], splits["test"][2]
        ),
    }
    if report["anchors"]["matches"] != report["anchors"]["total"]:
        raise SystemExit(
            f"refusing to write checkpoint: anchors {report['anchors']['predicted']} "
            f"!= {report['anchors']['expected']}"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(checkpoint, separators=(",", ":")) + "\n", encoding="utf-8")
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["metrics"], indent=2))
    print("anchors:", report["anchors"]["predicted"])
    print(f"{args.out}: {args.out.stat().st_size} bytes")
    print(f"{args.report}: metrics + per-family test report")


if __name__ == "__main__":
    main()
