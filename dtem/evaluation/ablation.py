"""
dtem.evaluation.ablation
~~~~~~~~~~~~~~~~~~~~~~~~

Leave-one-indicator-out, single-indicator-only, and parameter-sensitivity
analysis for the DTEM emergence score.

Each ablated model is re-evaluated against the *same* observation rows and the
*same* future-event labels as the full model, and the surviving indicator
weights are renormalized so every variant stays on a comparable 0-100 scale.
This isolates whether an indicator adds predictive information rather than
comparing models trained on different data.

Nothing here is evidence of real-world validity on its own. The result is only
as trustworthy as the input rows: they must come from genuine, leakage-safe,
cutoff-respecting observations that contain both classes. Curated prototype
fixtures may be passed for pipeline demonstration, but their output must be
labeled prototype-only and must not be reported as empirical performance.
"""
from __future__ import annotations

import math
from typing import Any, Callable, Iterable, Optional

from dtem.evaluation.metrics import pr_auc, threshold_metrics

INDICATORS: tuple[str, ...] = (
    "detection_frequency", "growth_rate", "source_diversity", "exploit_availability",
)


def _clip(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def compute_sub_scores(engine: Any, features: dict[str, Any],
                       growth_mode: Optional[str] = None) -> dict[str, float]:
    """Return the four normalized 0-100 indicator sub-scores for a feature dict.

    A growth indicator that is unavailable (``growth_rate`` missing/None) yields
    a 0 sub-score rather than an invented stable value, mirroring the production
    scoring path.
    """
    mode = growth_mode if growth_mode in {"legacy", "log"} else getattr(engine, "growth_mode", "legacy")
    freq = engine._normalize_frequency(features.get("detection_frequency", 0))
    growth_pct = features.get("growth_rate")
    if mode == "log":
        log_value = features.get("growth_log_rate")
        if growth_pct is not None and log_value is not None:
            growth = engine._normalize_log_growth(log_value, engine.log_growth_scale)
        else:
            growth = 0.0
    else:
        growth = engine._normalize_growth_rate(growth_pct) if growth_pct is not None else 0.0
    diversity = engine._normalize_source_diversity(features.get("source_diversity", 0))
    try:
        exploit_raw = float(features.get("exploit_evidence_score", 0.0))
    except (TypeError, ValueError):
        exploit_raw = float("nan")
    exploit = _clip(exploit_raw) if math.isfinite(exploit_raw) else 0.0
    return {
        "detection_frequency": freq,
        "growth_rate": growth,
        "source_diversity": diversity,
        "exploit_availability": exploit,
    }


def weighted_score(sub_scores: dict[str, float], weights: dict[str, float],
                   active: Iterable[str]) -> Optional[float]:
    """Renormalized weighted emergence score over the active indicator subset.

    Returns ``None`` only when no active indicator carries positive weight, so a
    degenerate ablation cannot masquerade as a zero score.
    """
    active = list(active)
    total_weight = sum(float(weights.get(name, 0.0)) for name in active)
    if total_weight <= 0:
        return None
    numerator = sum(float(weights.get(name, 0.0)) * float(sub_scores.get(name, 0.0)) for name in active)
    return _clip(numerator / total_weight)


def _rows_and_labels(rows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[int]]:
    usable = [row for row in rows if row.get("label") is not None]
    labels = [int(row["label"]) for row in usable]
    return usable, labels


def _evaluate(scores: list[float], labels: list[int], threshold: float) -> dict[str, Any]:
    ranking = pr_auc(labels, scores)
    return {
        "sample_count": len(scores),
        "pr_auc": ranking["pr_auc"],
        "pr_auc_status": ranking["status"],
        "threshold_metrics": threshold_metrics(labels, scores, threshold),
    }


def run_ablation(rows: list[dict[str, Any]], engine: Any, *, threshold: float = 50.0,
                 growth_mode: Optional[str] = None) -> dict[str, Any]:
    """Evaluate the full model, leave-one-out variants, and single-indicator models.

    ``rows`` must expose a ``features`` dict and a ``label`` (0/1) per entry, as
    produced by ``run_temporal_backtest``. Missing labels are skipped. A variant
    that produces no score for a row drops that row rather than substituting 0.
    """
    usable, labels = _rows_and_labels(rows)
    weights = engine.weights
    sub_scores = [compute_sub_scores(engine, row["features"], growth_mode) for row in usable]

    def scores_for(active: list[str]) -> tuple[list[float], list[int]]:
        kept_scores: list[float] = []
        kept_labels: list[int] = []
        for subs, label in zip(sub_scores, labels):
            value = weighted_score(subs, weights, active)
            if value is not None:
                kept_scores.append(value)
                kept_labels.append(label)
        return kept_scores, kept_labels

    full_scores, full_labels = scores_for(list(INDICATORS))
    result: dict[str, Any] = {
        "evaluation_note": "Ablation compares identical rows and labels; publishability "
                            "depends entirely on the input data being genuine and leakage-safe.",
        "threshold": threshold,
        "full_model": _evaluate(full_scores, full_labels, threshold),
    }

    leave_one_out: dict[str, Any] = {}
    for dropped in INDICATORS:
        active = [name for name in INDICATORS if name != dropped]
        scores, kept_labels = scores_for(active)
        variant = _evaluate(scores, kept_labels, threshold) if scores else {"sample_count": 0}
        if full_scores and variant.get("pr_auc") is not None and result["full_model"]["pr_auc"] is not None:
            variant["pr_auc_delta_vs_full"] = round(variant["pr_auc"] - result["full_model"]["pr_auc"], 6)
        leave_one_out[f"without_{dropped}"] = variant
    result["leave_one_out"] = leave_one_out

    single: dict[str, Any] = {}
    for name in INDICATORS:
        scores, kept_labels = scores_for([name])
        single[f"only_{name}"] = _evaluate(scores, kept_labels, threshold) if scores else {"sample_count": 0}
    result["single_indicator"] = single

    class_check = set(labels)
    result["class_support"] = {
        "positive": sum(labels), "negative": len(labels) - sum(labels),
        "two_class_present": class_check == {0, 1},
    }
    return result


def threshold_sensitivity(rows: list[dict[str, Any]], engine: Any,
                          thresholds: Iterable[float], *,
                          growth_mode: Optional[str] = None) -> list[dict[str, Any]]:
    """Report the full-model threshold metrics across a grid of decision cutoffs.

    The ranking metric (average precision) is threshold-independent, so it is
    computed once and repeated for context; only the confusion-matrix metrics
    change with the cutoff.
    """
    usable, labels = _rows_and_labels(rows)
    weights = engine.weights
    scores = []
    kept_labels = []
    for row, label in zip(usable, labels):
        subs = compute_sub_scores(engine, row["features"], growth_mode)
        value = weighted_score(subs, weights, list(INDICATORS))
        if value is not None:
            scores.append(value)
            kept_labels.append(label)
    ranking = pr_auc(kept_labels, scores)
    output = []
    for cutoff in thresholds:
        entry = {"threshold": cutoff, "pr_auc": ranking["pr_auc"],
                 "pr_auc_status": ranking["status"],
                 "threshold_metrics": threshold_metrics(kept_labels, scores, cutoff)}
        output.append(entry)
    return output


def growth_scale_sensitivity(rows: list[dict[str, Any]], engine: Any,
                             scales: Iterable[float], *, threshold: float = 50.0) -> list[dict[str, Any]]:
    """Test whether log-growth conclusions move when the scale constant varies.

    Uses the full model with the smoothed log-growth transform; every other
    indicator is unchanged. Reviewers asked whether parameter choices flip
    conclusions, so each scale's average precision and threshold metrics are
    reported rather than a single favored value.
    """
    usable, labels = _rows_and_labels(rows)
    weights = dict(engine.weights)
    rows_output = []
    for scale in scales:
        probe = _ScaleProbe(engine, float(scale))
        scores = []
        kept_labels = []
        for row, label in zip(usable, labels):
            subs = compute_sub_scores(probe, row["features"], "log")
            value = weighted_score(subs, weights, list(INDICATORS))
            if value is not None:
                scores.append(value)
                kept_labels.append(label)
        ranking = pr_auc(kept_labels, scores)
        rows_output.append({
            "log_growth_scale": float(scale),
            "pr_auc": ranking["pr_auc"], "pr_auc_status": ranking["status"],
            "threshold_metrics": threshold_metrics(kept_labels, scores, threshold) if scores else None,
        })
    return rows_output


class _ScaleProbe:
    """Lightweight adapter exposing the engine's normalizers at an alternate scale."""

    def __init__(self, engine: Any, scale: float) -> None:
        self._engine = engine
        self.log_growth_scale = float(scale)
        self.growth_mode = "log"

    def _normalize_frequency(self, freq: Any) -> float:
        return self._engine._normalize_frequency(freq)

    def _normalize_source_diversity(self, div: Any) -> float:
        return self._engine._normalize_source_diversity(div)

    def _normalize_growth_rate(self, growth_pct: Any) -> float:
        return self._engine._normalize_growth_rate(growth_pct)

    def _normalize_log_growth(self, log_growth: Any, scale: float) -> float:
        return self._engine._normalize_log_growth(log_growth, scale)
