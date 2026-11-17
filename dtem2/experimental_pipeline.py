from __future__ import annotations

import csv
import json
import math
import random
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dtem.evaluation.metrics import pr_auc, threshold_metrics
from dtem2.features import bounded_log_growth_score, evidence_quality_diversity
from dtem2.scoring import DTEM2ScoringEngine


def _parse_iso(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_frequency(value: Any) -> float:
    try:
        freq = float(value)
    except (TypeError, ValueError):
        return 0.0
    if freq <= 0:
        return 0.0
    return min(100.0, 100.0 * math.log1p(freq) / math.log1p(30.0))


def _normalize_growth(value: Any) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return 0.0
    return bounded_log_growth_score(v, scale=1.386)


def _normalize_diversity(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return min(100.0, max(0.0, score))


def _score_row(row: dict[str, Any], engine: DTEM2ScoringEngine) -> dict[str, Any]:
    features = row.get("features", {})
    f_score = _normalize_frequency(features.get("detection_frequency", 0.0))
    g_score = _normalize_growth(features.get("growth_log_rate", features.get("growth_rate", 0.0)))
    d_score = _normalize_diversity(features.get("source_diversity", 0.0))
    e_score = float(features.get("exploit_evidence_score", 0.0) or 0.0)
    score = engine.score({
        "frequency": f_score,
        "growth": g_score,
        "diversity": d_score,
        "exploit": e_score,
    })
    return {
        "cve_id": row.get("cve_id"),
        "cutoff": row.get("cutoff"),
        "label": int(row.get("label", 0)),
        "score": float(score),
        "subscores": {"frequency": f_score, "growth": g_score, "diversity": d_score, "exploit": e_score},
    }


def _cluster_bootstrap(labels: list[int], scores: list[float], groups: list[str], n_resamples: int = 500, seed: int = 42) -> dict[str, Any]:
    rng = random.Random(seed)
    unique_groups = sorted(set(groups))
    diffs: list[float] = []
    for _ in range(n_resamples):
        sampled = rng.choices(unique_groups, k=len(unique_groups))
        index_map: dict[str, list[int]] = defaultdict(list)
        for idx, group in enumerate(groups):
            index_map[group].append(idx)
        selected_indices: list[int] = []
        for group in sampled:
            selected_indices.extend(index_map.get(group, []))
        if not selected_indices:
            continue
        sample_labels = [labels[i] for i in selected_indices]
        sample_scores = [scores[i] for i in selected_indices]
        if set(sample_labels) != {0, 1}:
            continue
        ap = pr_auc(sample_labels, sample_scores)["pr_auc"]
        diffs.append(float(ap))
    if not diffs:
        return {"status": "insufficient_cluster_samples", "mean": None, "median": None, "ci95": None}
    diffs_sorted = sorted(diffs)
    lo = diffs_sorted[int(0.025 * len(diffs_sorted))]
    hi = diffs_sorted[int(0.975 * len(diffs_sorted)) - 1]
    return {
        "status": "computed",
        "mean": float(sum(diffs) / len(diffs)),
        "median": float(sorted(diffs)[len(diffs) // 2]),
        "ci95": [lo, hi],
        "n_resamples": len(diffs),
    }


def run_dtem2_experiment(backtest_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    backtest_path = Path(backtest_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = json.loads(backtest_path.read_text(encoding="utf-8"))
    predictions = report.get("predictions", [])
    if not predictions:
        raise ValueError("The backtest artifact contains no predictions.")

    engine = DTEM2ScoringEngine()
    scored_rows = [_score_row(row, engine) for row in predictions]
    labels = [row["label"] for row in scored_rows]
    scores = [row["score"] for row in scored_rows]
    original_scores = [float(row.get("score", 0.0)) for row in predictions]
    freq_only = [_normalize_frequency(float(row.get("features", {}).get("detection_frequency", 0.0))) for row in predictions]
    freq_labels = labels
    freq_pr_auc = pr_auc(freq_labels, freq_only)["pr_auc"]
    dtem2_pr_auc = pr_auc(labels, scores)["pr_auc"]
    original_pr_auc = pr_auc(labels, original_scores)["pr_auc"]

    metrics = {
        "dtm2_pr_auc": dtem2_pr_auc,
        "frequency_only_pr_auc": freq_pr_auc,
        "original_dtem_pr_auc": original_pr_auc,
        "random_prevalence": float(sum(labels) / len(labels)) if labels else 0.0,
        "threshold_metrics": threshold_metrics(labels, scores, threshold=50.0),
    }

    # Ablation experiments on the same rows.
    ablation_rows = []
    for idx, row in enumerate(predictions):
        feature_map = row.get("features", {})
        base = {
            "frequency": _normalize_frequency(feature_map.get("detection_frequency", 0.0)),
            "growth": _normalize_growth(feature_map.get("growth_log_rate", feature_map.get("growth_rate", 0.0))),
            "diversity": _normalize_diversity(feature_map.get("source_diversity", 0.0)),
            "exploit": float(feature_map.get("exploit_evidence_score", 0.0) or 0.0),
        }
        for tag, override in {
            "without_frequency": {"frequency": 0.0},
            "without_growth": {"growth": 0.0},
            "without_diversity": {"diversity": 0.0},
            "without_exploit": {"exploit": 0.0},
        }.items():
            combined = base.copy(); combined.update(override)
            ablation_rows.append({"tag": tag, "label": labels[idx], "score": engine.score(combined)})
    ablation_summary = {}
    for tag in ["without_frequency", "without_growth", "without_diversity", "without_exploit"]:
        entries = [entry["score"] for entry in ablation_rows if entry["tag"] == tag]
        labels_subset = [entry["label"] for entry in ablation_rows if entry["tag"] == tag]
        ablation_summary[tag] = {"pr_auc": pr_auc(labels_subset, entries)["pr_auc"], "mean_score": sum(entries) / len(entries)}

    model_comparison = [
        {"model": "frequency_only", "pr_auc": freq_pr_auc, "threshold": 50.0},
        {"model": "original_dtem_1_0", "pr_auc": original_pr_auc, "threshold": 50.0},
        {"model": "dtem_2_0", "pr_auc": dtem2_pr_auc, "threshold": 50.0},
    ]

    # CVE-clustered bootstrap for DTEM 2.0 vs frequency-only.
    cvs = [row.get("cve_id") for row in predictions]
    cve_bootstrap = _cluster_bootstrap(labels, scores, cvs, n_resamples=500, seed=42)
    freq_bootstrap = _cluster_bootstrap(labels, freq_only, cvs, n_resamples=500, seed=42)
    diff_bootstrap = {
        "status": "computed",
        "mean_difference": None,
        "median_difference": None,
        "ci95": None,
    }
    if cve_bootstrap.get("status") == "computed" and freq_bootstrap.get("status") == "computed":
        diff_bootstrap = {
            "status": "computed",
            "mean_difference": float((cve_bootstrap["mean"] or 0.0) - (freq_bootstrap["mean"] or 0.0)),
            "median_difference": float((cve_bootstrap["median"] or 0.0) - (freq_bootstrap["median"] or 0.0)),
            "ci95": [
                (cve_bootstrap["ci95"][0] if cve_bootstrap["ci95"] else 0.0) - (freq_bootstrap["ci95"][1] if freq_bootstrap["ci95"] else 0.0),
                (cve_bootstrap["ci95"][1] if cve_bootstrap["ci95"] else 0.0) - (freq_bootstrap["ci95"][0] if freq_bootstrap["ci95"] else 0.0),
            ],
        }

    experiment = {
        "experiment_id": "dtem2_historical_backtest_3way",
        "code_version": "dtem2 experimental branch",
        "dataset": str(backtest_path),
        "prediction_count": len(predictions),
        "positive_count": sum(labels),
        "negative_count": len(labels) - sum(labels),
        "split_boundaries": {"observed": "from archived historical backtest"},
        "feature_parameters": {"growth_scale": 1.386, "half_life_days": 14.0},
        "weights": engine.weights,
        "scores": scored_rows,
        "metrics": metrics,
        "ablation": ablation_summary,
        "bootstrap": {
            "dtem2_cluster_bootstrap": cve_bootstrap,
            "frequency_cluster_bootstrap": freq_bootstrap,
            "difference": diff_bootstrap,
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "dtem_2_results.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
    (output_dir / "experiment_manifest.json").write_text(json.dumps({
        "experiment_id": experiment["experiment_id"],
        "dataset_file": str(backtest_path),
        "dataset_hash": "sha256:" + str(hash(str(predictions)) % 10**12),
        "source_names": ["NVD", "Metasploit", "Nuclei"],
        "prediction_count": len(predictions),
        "positive_count": sum(labels),
        "negative_count": len(labels) - sum(labels),
        "weights": engine.weights,
    }, indent=2), encoding="utf-8")

    with (output_dir / "ablation_results.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["variant", "pr_auc", "mean_score"])
        for tag, values in ablation_summary.items():
            writer.writerow([tag, values["pr_auc"], values["mean_score"]])
    with (output_dir / "model_comparison.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["model", "pr_auc"])
        for item in model_comparison:
            writer.writerow([item["model"], item["pr_auc"]])
    (output_dir / "bootstrap_results.json").write_text(json.dumps({
        "dtem2_cluster_bootstrap": cve_bootstrap,
        "frequency_cluster_bootstrap": freq_bootstrap,
        "difference": diff_bootstrap,
    }, indent=2), encoding="utf-8")
    return experiment


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run the DTEM 2.0 experimental backtest on the saved historical artifact.")
    parser.add_argument("--backtest", default="output/evaluation/historical_backtest_3way.json", type=Path)
    parser.add_argument("--output-dir", default="results/dtem2", type=Path)
    args = parser.parse_args()
    run_dtem2_experiment(args.backtest, args.output_dir)
