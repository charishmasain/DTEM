"""
dtem.evaluation.metrics
~~~~~~~~~~~~~~~~~~~~~~~

Ranking and threshold metrics shared by the research evaluation modules.

These functions are intentionally dependency-light and make no claim that the
numbers they return describe real-world predictive validity. Whether a result
is publishable depends entirely on the input data being genuine, leakage-safe,
and large enough to contain both classes; callers are responsible for asserting
that precondition and for labeling prototype-only runs as such.
"""
from __future__ import annotations

import math
import random
from typing import Any, Sequence


def _validate(labels: Sequence[int], scores: Sequence[float]) -> None:
    if len(labels) != len(scores):
        raise ValueError("labels and scores must have the same length")
    for score in scores:
        try:
            value = float(score)
        except (TypeError, ValueError):
            raise ValueError("scores must be numeric") from None
        if not math.isfinite(value):
            raise ValueError("scores must be finite")


def threshold_metrics(labels: Sequence[int], scores: Sequence[float],
                      threshold: float) -> dict[str, Any]:
    """Confusion matrix, precision, recall, and F1 at a single decision cutoff.

    A metric that has no defined value (for example precision with no predicted
    positives) is reported as ``None`` and listed in ``undefined_metrics`` rather
    than silently coerced to zero, so a caller cannot mistake an undefined rate
    for a perfect one.
    """
    _validate(labels, scores)
    threshold = float(threshold)
    tp = sum(1 for y, s in zip(labels, scores) if int(y) == 1 and float(s) >= threshold)
    fp = sum(1 for y, s in zip(labels, scores) if int(y) == 0 and float(s) >= threshold)
    fn = sum(1 for y, s in zip(labels, scores) if int(y) == 1 and float(s) < threshold)
    tn = sum(1 for y, s in zip(labels, scores) if int(y) == 0 and float(s) < threshold)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    if precision is not None and recall is not None and (precision + recall):
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    undefined = [name for name, value in (("precision", precision), ("recall", recall), ("f1", f1))
                 if value is None]
    return {
        "threshold": threshold,
        "support": {"positive": tp + fn, "negative": fp + tn, "total": tp + fp + fn + tn},
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "accuracy": (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else None,
        "precision": precision, "recall": recall, "f1": f1,
        "undefined_metrics": undefined,
    }


def alert_budget_metrics(labels: Sequence[int], scores: Sequence[float], *,
                         top_k: int | None = None, budget_fraction: float | None = None,
                         ) -> dict[str, Any]:
    """Precision, recall, and false alerts within a fixed analyst alert budget.

    A prioritization tool is used under a finite review capacity, so ranking
    quality near the top matters more than a global threshold. The budget is the
    number of highest-scored items an analyst would actually inspect: ``top_k``
    items, or ``budget_fraction`` of the population when ``top_k`` is not given
    (default 10%). Items are ranked by descending score; ties are broken by the
    original row order so the result is deterministic, and ``n_ties_at_cutoff``
    reports how many scores sit exactly at the budget boundary so a reader can
    see when the ranking is being decided by tie-break rather than by score.
    Undefined values (for example recall when no positives exist) are reported as
    ``None`` and listed in ``undefined_metrics`` rather than coerced to zero.
    """
    _validate(labels, scores)
    total = len(labels)
    if total == 0:
        return {"status": "no_samples", "budget": 0, "sample_count": 0}
    if top_k is None:
        if budget_fraction is None:
            budget_fraction = 0.1
        if not 0 < budget_fraction <= 1:
            raise ValueError("budget_fraction must be in (0, 1]")
        k = max(1, math.ceil(budget_fraction * total))
    else:
        if top_k <= 0:
            raise ValueError("top_k must be positive")
        k = min(int(top_k), total)
    order = sorted(range(total), key=lambda i: (-float(scores[i]), i))
    selected = order[:k]
    positives = sum(1 for y in labels if int(y) == 1)
    hits = sum(1 for i in selected if int(labels[i]) == 1)
    false_alerts = k - hits
    precision = hits / k if k else None
    recall = hits / positives if positives else None
    boundary_score = float(scores[selected[-1]])
    n_ties = sum(1 for s in scores if float(s) == boundary_score)
    return {
        "status": "computed",
        "sample_count": total,
        "budget": k,
        "budget_basis": f"top-{k}" if top_k is not None else f"{budget_fraction:.0%} of {total}",
        "positives_in_population": positives,
        "positives_captured": hits,
        "false_alerts": false_alerts,
        "precision_at_budget": round(precision, 6) if precision is not None else None,
        "recall_at_budget": round(recall, 6) if recall is not None else None,
        "random_precision_baseline": round(positives / total, 6) if total else None,
        "n_ties_at_cutoff": n_ties,
        "undefined_metrics": [name for name, value in
                              (("recall", recall),) if value is None],
        "note": "Compare precision_at_budget against random_precision_baseline (prevalence); "
                "with ties the cutoff rows are decided by input order, which must be disclosed.",
    }


def pr_auc(labels: Sequence[int], scores: Sequence[float]) -> dict[str, Any]:
    """Average precision (the area under the precision-recall step curve).

    Ties are grouped so that equal scores are evaluated at a single operating
    point, matching the conventional sklearn definition. Average precision is
    returned only when both a positive and a negative example exist; otherwise
    the ranking is not informative and ``status`` reports the reason instead of
    a numeric value.
    """
    _validate(labels, scores)
    pairs = sorted(((int(y), float(s)) for y, s in zip(labels, scores)),
                   key=lambda item: item[1], reverse=True)
    positives = sum(y for y, _ in pairs)
    total = len(pairs)
    negatives = total - positives
    prevalence = positives / total if total else None
    if total == 0:
        return {"status": "no_samples", "pr_auc": None, "prevalence": None}
    if positives == 0 or negatives == 0:
        return {"status": "single_class", "pr_auc": None,
                "prevalence": prevalence,
                "reason": "Average precision is undefined when only one class is present."}
    ap = 0.0
    tp = fp = 0
    previous_recall = 0.0
    index = 0
    while index < total:
        score = pairs[index][1]
        group_end = index
        while group_end < total and pairs[group_end][1] == score:
            if pairs[group_end][0] == 1:
                tp += 1
            else:
                fp += 1
            group_end += 1
        precision = tp / (tp + fp)
        recall = tp / positives
        ap += precision * (recall - previous_recall)
        previous_recall = recall
        index = group_end
    return {"status": "computed", "pr_auc": round(ap, 6), "prevalence": round(prevalence, 6),
            "positive_count": positives, "negative_count": negatives,
            "random_baseline": round(prevalence, 6),
            "note": "Compare pr_auc against random_baseline (prevalence), not against 0.5."}


def bootstrap_pr_auc_ci(labels: Sequence[int], scores: Sequence[float], *,
                        n_resamples: int = 1000, seed: int = 0,
                        confidence: float = 0.95) -> dict[str, Any]:
    """Percentile bootstrap interval for average precision.

    Resamples (label, score) observation pairs with replacement. Each resample
    must contain both classes to contribute a value, so the effective resample
    count is reported. This quantifies sampling uncertainty only; it does not
    correct dataset bias, class imbalance, or leakage.
    """
    _validate(labels, scores)
    if n_resamples <= 0:
        raise ValueError("n_resamples must be positive")
    if not 0 < confidence < 1:
        raise ValueError("confidence must be in (0, 1)")
    base = pr_auc(labels, scores)
    if base["status"] != "computed":
        return {"status": base.get("status", "not_computable"), "point": base["pr_auc"],
                "confidence": confidence, "interval": None, "resamples_used": 0,
                "resamples_requested": n_resamples}
    pairs = list(zip((int(y) for y in labels), (float(s) for s in scores)))
    total = len(pairs)
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(n_resamples):
        sample = [pairs[rng.randrange(total)] for _ in range(total)]
        result = pr_auc([y for y, _ in sample], [s for _, s in sample])
        if result["status"] == "computed":
            values.append(result["pr_auc"])
    if len(values) < 2:
        return {"status": "insufficient_resamples", "point": base["pr_auc"],
                "confidence": confidence, "interval": None,
                "resamples_used": len(values), "resamples_requested": n_resamples}
    values.sort()
    tail = (1.0 - confidence) / 2.0
    lower = values[max(0, math.floor(tail * len(values)))]
    upper = values[min(len(values) - 1, math.floor((1.0 - tail) * len(values)))]
    return {"status": "computed", "point": base["pr_auc"], "confidence": confidence,
            "interval": [round(lower, 6), round(upper, 6)],
            "resamples_used": len(values), "resamples_requested": n_resamples}
