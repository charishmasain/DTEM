from __future__ import annotations

import csv
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dtem.evaluation.metrics import pr_auc


BACKTEST_PATH = Path("output/evaluation/historical_backtest_3way.json")
OUTPUT_PATH = Path("results/dtem2_redesign/incremental_indicator_experiments.csv")


def safe_float(value, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError):
        return default


def log_norm(value, cap: float = 14.0) -> float:
    value = safe_float(value)
    if value <= 0.0:
        return 0.0
    return min(100.0, 100.0 * math.log1p(value) / math.log1p(cap))


def count_growth(recent, previous, alpha: float = 1.0) -> float:
    recent = max(0.0, safe_float(recent))
    previous = max(0.0, safe_float(previous))
    alpha = max(1e-9, safe_float(alpha, 1.0))
    ratio = (recent + alpha) / (previous + alpha)
    if ratio <= 0.0:
        return 0.0
    return math.log(ratio)


def bounded_growth(raw_value) -> float:
    value = safe_float(raw_value)
    if value <= 0.0:
        return 0.0
    return min(100.0, max(0.0, 50.0 * (1.0 + math.tanh(value / 1.5))))


def diversity_score(value) -> float:
    value = safe_float(value)
    return max(0.0, min(100.0, 75.0 * value / 3.0))


def exploit_score(value) -> float:
    value = safe_float(value)
    return max(0.0, min(100.0, 100.0 * value))


def run() -> list[dict[str, float | str]]:
    report = json.loads(BACKTEST_PATH.read_text(encoding="utf-8"))
    predictions = report.get("predictions", [])
    labels = [int(row.get("label", 0)) for row in predictions]

    variants: dict[str, list[float]] = {}

    for row in predictions:
        features = row.get("features", {})
        frequency = log_norm(features.get("detection_frequency", features.get("frequency", 0.0)))
        recent = safe_float(features.get("recent_activity", features.get("recent_count", features.get("recent_events", 0.0))))
        previous = safe_float(features.get("previous_activity", features.get("previous_count", features.get("previous_events", 0.0))))
        growth = bounded_growth(count_growth(recent, previous, alpha=1.0))
        diversity = diversity_score(features.get("source_diversity", features.get("diversity", 0.0)))
        exploit = exploit_score(features.get("exploit_evidence_score", features.get("exploit", 0.0)))

        for name, value in {
            "frequency": frequency,
            "growth": growth,
            "diversity": diversity,
            "exploit": exploit,
        }.items():
            variants.setdefault(name, []).append(value)

        variants.setdefault("frequency_growth", []).append(0.5 * frequency + 0.5 * growth)
        variants.setdefault("frequency_diversity", []).append(0.5 * frequency + 0.5 * diversity)
        variants.setdefault("frequency_exploit", []).append(0.5 * frequency + 0.5 * exploit)
        variants.setdefault("growth_diversity", []).append(0.5 * growth + 0.5 * diversity)
        variants.setdefault("growth_exploit", []).append(0.5 * growth + 0.5 * exploit)
        variants.setdefault("diversity_exploit", []).append(0.5 * diversity + 0.5 * exploit)
        variants.setdefault("all_indicators", []).append(0.4 * frequency + 0.35 * growth + 0.15 * diversity + 0.10 * exploit)

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, float | str]] = []
    for name, scores in variants.items():
        metric = pr_auc(labels, scores)["pr_auc"]
        mean = sum(scores) / len(scores)
        sorted_scores = sorted(scores)
        median = sorted_scores[len(sorted_scores) // 2] if len(sorted_scores) % 2 else (sorted_scores[len(sorted_scores) // 2 - 1] + sorted_scores[len(sorted_scores) // 2]) / 2.0
        std = (sum((value - mean) ** 2 for value in scores) / len(scores)) ** 0.5
        rows.append({
            "variant": name,
            "pr_auc": float(metric),
            "mean_score": float(mean),
            "median_score": float(median),
            "std_score": float(std),
        })

    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["variant", "pr_auc", "mean_score", "median_score", "std_score"])
        writer.writeheader()
        writer.writerows(rows)

    return sorted(rows, key=lambda row: (-float(row["pr_auc"]), str(row["variant"])))


if __name__ == "__main__":
    for row in run():
        print(f"{row['variant']},{row['pr_auc']}")
