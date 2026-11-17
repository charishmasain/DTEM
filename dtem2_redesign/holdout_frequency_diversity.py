from __future__ import annotations

import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dtem.evaluation.metrics import pr_auc
from dtem.evaluation.split import partition_periods

BACKTEST_PATH = Path("output/evaluation/historical_backtest_3way.json")


def safe_float(value, default: float = 0.0) -> float:
    try:
        value = float(value)
        return value if math.isfinite(value) else default
    except (TypeError, ValueError):
        return default


def normalize_frequency(value: object) -> float:
    x = safe_float(value, 0.0)
    if x <= 0:
        return 0.0
    return min(100.0, 100.0 * math.log1p(x) / math.log1p(14.0))


def normalize_diversity(value: object) -> float:
    x = safe_float(value, 0.0)
    if x <= 0:
        return 0.0
    return min(100.0, 100.0 * x / 3.0)


def score_fd(row: dict, freq_w: float, div_w: float) -> float:
    features = row.get("features", {})
    frequency = normalize_frequency(features.get("detection_frequency", features.get("frequency", 0.0)))
    diversity = normalize_diversity(features.get("source_diversity", features.get("diversity", 0.0)))
    total = freq_w * frequency + div_w * diversity
    return float(max(0.0, min(100.0, total)))


def choose_weight_pair(rows: list[dict]) -> tuple[float, float, dict[str, float]]:
    candidates = [
        (0.5, 0.5),
        (0.6, 0.4),
        (0.7, 0.3),
        (0.8, 0.2),
        (0.9, 0.1),
        (0.4, 0.6),
    ]
    split = partition_periods(rows, dev_fraction=0.6, val_fraction=0.2)
    dev_rows = split["buckets"]["development"] if "development" in split["buckets"] else []
    val_rows = split["buckets"]["validation"] if "validation" in split["buckets"] else []
    if not dev_rows or not val_rows:
        raise ValueError(f"Split produced empty dev/validation buckets: {split}")

    best = None
    best_report = None
    for w_freq, w_div in candidates:
        dev_scores = [score_fd(row, w_freq, w_div) for row in dev_rows]
        val_scores = [score_fd(row, w_freq, w_div) for row in val_rows]
        dev_labels = [int(row["label"]) for row in dev_rows]
        val_labels = [int(row["label"]) for row in val_rows]
        dev_pr = pr_auc(dev_labels, dev_scores)["pr_auc"]
        val_pr = pr_auc(val_labels, val_scores)["pr_auc"]
        report = {"freq": w_freq, "div": w_div, "dev_pr_auc": dev_pr, "val_pr_auc": val_pr}
        if best is None or val_pr > best:
            best = val_pr
            best_report = report
    return best_report["freq"], best_report["div"], best_report


def main() -> None:
    report = json.loads(BACKTEST_PATH.read_text(encoding="utf-8"))
    rows = report["predictions"]
    split = partition_periods(rows, dev_fraction=0.6, val_fraction=0.2)
    if split["status"] != "computed":
        raise ValueError(f"Chronological split did not compute: {split}")

    train_rows = split["buckets"]["development"]
    val_rows = split["buckets"]["validation"]
    test_rows = split["buckets"]["test"]
    if not (train_rows and val_rows and test_rows):
        raise ValueError(f"Need dev/val/test buckets; got { {k: len(v) for k, v in split['periods'].items()} }")

    freq_w, div_w, selection = choose_weight_pair(rows)
    test_labels = [int(row["label"]) for row in test_rows]
    test_scores = [score_fd(row, freq_w, div_w) for row in test_rows]
    orig_scores = [float(row.get("score", 0.0)) for row in test_rows]

    fd_pr_auc = pr_auc(test_labels, test_scores)["pr_auc"]
    original_pr_auc = pr_auc(test_labels, orig_scores)["pr_auc"]
    print("selection", selection)
    print("selected_weight_pair", {"frequency_weight": freq_w, "diversity_weight": div_w})
    print("test_frequency_diversity_pr_auc", fd_pr_auc)
    print("test_original_dtem_pr_auc", original_pr_auc)
    print("improvement", fd_pr_auc - original_pr_auc)
    print("test_support", {"positive": sum(test_labels), "negative": len(test_labels) - sum(test_labels)})


if __name__ == "__main__":
    main()
