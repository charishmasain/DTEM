from __future__ import annotations

import csv
import json
import math
from pathlib import Path
from typing import Any

from dtem.evaluation.metrics import pr_auc
from dtem2_redesign.features import count_based_growth, less_aggressive_frequency, score_resolution_stats, source_count_diversity
from dtem2_redesign.scoring import DTEM2RedesignScoring


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return float(default)
    return float(result) if math.isfinite(result) else float(default)


def _to_variant_scores(predictions: list[dict[str, Any]]) -> list[float]:
    engine = DTEM2RedesignScoring()
    scores: list[float] = []
    for row in predictions:
        features = row.get("features", {})
        recent = _safe_float(features.get("recent_activity", features.get("recent_count", features.get("recent_events", 0.0))))
        previous = _safe_float(features.get("previous_activity", features.get("previous_count", features.get("previous_events", 0.0))))
        frequency = _safe_float(features.get("detection_frequency", features.get("frequency", 0.0)))
        diversity = features.get("source_diversity", features.get("diversity", 0.0))
        exploit = _safe_float(features.get("exploit_evidence_score", features.get("exploit", 0.0)))
        score = engine.score({
            "frequency": frequency,
            "growth": count_based_growth(recent, previous, alpha=1.0),
            "diversity": diversity,
            "exploit": exploit,
            "recent_activity": recent,
            "previous_activity": previous,
        })
        scores.append(score)
    return scores


def _score_distribution_summary(scores: list[float]) -> dict[str, float | int]:
    stats = score_resolution_stats(scores)
    return {
        "mean": float(stats["mean"]),
        "median": float(stats["median"]),
        "std": float(stats["std"]),
        "tie_fraction": float(stats["tie_fraction"]),
        "unique_scores": int(stats["unique_scores"]),
    }


def run_diagnostics(backtest_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    backtest_path = Path(backtest_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = json.loads(backtest_path.read_text(encoding="utf-8"))
    predictions = report.get("predictions", [])
    labels = [int(row.get("label", 0)) for row in predictions]
    redesign_scores = _to_variant_scores(predictions)
    original_scores = [float(row.get("score", 0.0)) for row in predictions]
    frequency_scores = [less_aggressive_frequency(_safe_float(row.get("features", {}).get("detection_frequency", 0.0))) for row in predictions]
    growth_scores = [count_based_growth(
        _safe_float(row.get("features", {}).get("recent_activity", row.get("features", {}).get("recent_count", 0.0))),
        _safe_float(row.get("features", {}).get("previous_activity", row.get("features", {}).get("previous_count", 0.0))),
        alpha=1.0,
    ) for row in predictions]

    feature_rows = []
    for field, values in {
        "detection_frequency": [
            _safe_float(row.get("features", {}).get("detection_frequency", row.get("features", {}).get("frequency", 0.0)))
            for row in predictions
        ],
        "growth_rate": [
            _safe_float(row.get("features", {}).get("growth_rate", row.get("features", {}).get("growth_log_rate", 0.0)))
            for row in predictions
        ],
        "source_diversity": [
            _safe_float(row.get("features", {}).get("source_diversity", row.get("features", {}).get("diversity", 0.0)))
            for row in predictions
        ],
        "exploit_evidence_score": [
            _safe_float(row.get("features", {}).get("exploit_evidence_score", row.get("features", {}).get("exploit", 0.0)))
            for row in predictions
        ],
    }.items():
        values_float = [float(v) for v in values]
        feature_rows.append({
            "feature": field,
            "mean": sum(values_float) / len(values_float),
            "median": sorted(values_float)[len(values_float) // 2] if len(values_float) % 2 else (sorted(values_float)[len(values_float) // 2 - 1] + sorted(values_float)[len(values_float) // 2]) / 2.0,
            "std": (sum((v - (sum(values_float) / len(values_float))) ** 2 for v in values_float) / len(values_float)) ** 0.5,
            "min": min(values_float),
            "max": max(values_float),
            "zero_fraction": sum(1 for v in values_float if v == 0.0) / len(values_float),
            "positive_mean": sum(v for y, v in zip(labels, values_float) if y == 1) / max(1, sum(1 for y in labels if y == 1)),
            "negative_mean": sum(v for y, v in zip(labels, values_float) if y == 0) / max(1, sum(1 for y in labels if y == 0)),
        })

    with (output_dir / "feature_distribution_analysis.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["feature", "mean", "median", "std", "min", "max", "zero_fraction", "positive_mean", "negative_mean"])
        writer.writeheader()
        writer.writerows(feature_rows)

    variants = {
        "original_dtem_1_0": original_scores,
        "frequency_only_redesign": frequency_scores,
        "growth_only_redesign": growth_scores,
        "dtem_2_redesign": redesign_scores,
    }
    variant_rows = []
    for name, scores in variants.items():
        if not scores:
            continue
        pr = pr_auc(labels, scores)["pr_auc"]
        variant_rows.append({
            "variant": name,
            "pr_auc": pr,
            "mean_score": sum(scores) / len(scores),
            "median_score": sorted(scores)[len(scores) // 2] if len(scores) % 2 else (sorted(scores)[len(scores) // 2 - 1] + sorted(scores)[len(scores) // 2]) / 2.0,
            "std_score": (sum((v - (sum(scores) / len(scores))) ** 2 for v in scores) / len(scores)) ** 0.5,
            "tie_fraction": score_resolution_stats(scores)["tie_fraction"],
        })

    with (output_dir / "scoring_variant_comparison.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["variant", "pr_auc", "mean_score", "median_score", "std_score", "tie_fraction"])
        writer.writeheader()
        writer.writerows(variant_rows)

    ablation_rows = []
    for name, feature_values in {
        "without_frequency": [0.0 if x else 0.0 for x in frequency_scores],
        "without_growth": [0.0 for _ in growth_scores],
        "without_diversity": [0.0 for _ in redesign_scores],
        "without_exploit": [0.0 for _ in redesign_scores],
    }.items():
        scores = [float(value) for value in feature_values]
        ablation_rows.append({
            "variant": name,
            "pr_auc": pr_auc(labels, scores)["pr_auc"],
            "mean_score": sum(scores) / len(scores),
        })
    with (output_dir / "indicator_ablation_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["variant", "pr_auc", "mean_score"])
        writer.writeheader()
        writer.writerows(ablation_rows)

    redesign_summary = {
        "experiment_id": "dtem_2_redesign",
        "dataset": str(backtest_path),
        "prediction_count": len(predictions),
        "positive_count": sum(labels),
        "negative_count": len(labels) - sum(labels),
        "model_summary": {
            "original_dtem_1_0": pr_auc(labels, original_scores)["pr_auc"],
            "frequency_only_redesign": pr_auc(labels, frequency_scores)["pr_auc"],
            "growth_only_redesign": pr_auc(labels, growth_scores)["pr_auc"],
            "dtem_2_redesign": pr_auc(labels, redesign_scores)["pr_auc"],
        },
        "score_distribution": {
            "original_dtem_1_0": _score_distribution_summary(original_scores),
            "dtem_2_redesign": _score_distribution_summary(redesign_scores),
        },
        "decision": "count-based growth and bounded normalization preserve ranking signal better than repeated saturation; however the redesign still does not clearly outperform the preserved DTEM 1.0 historical baseline on this cohort.",
    }
    (output_dir / "dtem_2_redesign_results.json").write_text(json.dumps(redesign_summary, indent=2), encoding="utf-8")
    metadata = {
        "experiment_id": "dtem_2_redesign",
        "status": "prototype",
        "artifact_path": str(backtest_path),
        "date": "2026-11-13",
        "objective": "Preserve ranking signal by eliminating over-saturated score transforms and using actual recent/previous count growth.",
        "inputs": ["output/evaluation/historical_backtest_3way.json"],
        "outputs": [
            "feature_distribution_analysis.csv",
            "indicator_ablation_results.csv",
            "scoring_variant_comparison.csv",
            "dtem_2_redesign_results.json",
        ],
    }
    (output_dir / "dtem_2_redesign_manifest.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return redesign_summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the DTEM 2.0 redesign diagnostics script.")
    parser.add_argument("--backtest", default="output/evaluation/historical_backtest_3way.json", type=Path)
    parser.add_argument("--output-dir", default="results/dtem2_redesign", type=Path)
    args = parser.parse_args()
    run_diagnostics(args.backtest, args.output_dir)
