"""
dtem.evaluation.baselines
~~~~~~~~~~~~~~~~~~~~~~~~~

Simple and literature baselines evaluated against the *same* observation rows,
cutoffs, and future-event labels as DTEM, so a comparison is like-for-like.

Baselines:
  * historical-frequency  - detection volume alone (a pure popularity proxy)
  * growth-rate           - smoothed/legacy growth sub-score alone
  * source-diversity      - distinct source labels alone
  * exploit-availability  - exploit evidence tier alone
  * cvss-severity         - CVSS base score as a severity benchmark, not a
                            temporal forecaster
  * epss                  - date-matched FIRST EPSS probability, thresholded at
                            a documented value and used on its own [0, 1] scale

Every method is scored only from information available at that row's cutoff, and
the label is the same future-event outcome. As with ablation, a fair-looking
table is not evidence of real-world validity unless the underlying rows are
genuine, leakage-safe, and contain both classes.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from dtem.evaluation.ablation import compute_sub_scores
from dtem.evaluation.metrics import pr_auc, threshold_metrics

SUB_SCORE_BASELINES = {
    "historical_frequency": "detection_frequency",
    "growth_rate": "growth_rate",
    "source_diversity": "source_diversity",
    "exploit_availability": "exploit_availability",
}


def _usable(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("label") is not None]


def _evaluate(pairs: list[tuple[float, int]], threshold: float) -> dict[str, Any]:
    if not pairs:
        return {"sample_count": 0, "pr_auc": None, "pr_auc_status": "no_samples",
                "threshold_metrics": None}
    scores = [value for value, _ in pairs]
    labels = [label for _, label in pairs]
    ranking = pr_auc(labels, scores)
    return {
        "sample_count": len(pairs),
        "pr_auc": ranking["pr_auc"],
        "pr_auc_status": ranking["status"],
        "random_baseline": ranking.get("random_baseline"),
        "threshold_metrics": threshold_metrics(labels, scores, threshold),
    }


def run_baselines(rows: list[dict[str, Any]], engine: Any, *, threshold: float = 50.0,
                  epss_threshold: float = 0.1, dtem_scores: Optional[list[float]] = None,
                  growth_mode: Optional[str] = None) -> dict[str, Any]:
    """Score every baseline and (optionally) the full DTEM model on identical rows.

    ``dtem_scores`` is accepted so the caller can pass the exact production
    emergence scores already computed at each cutoff; if omitted, DTEM is
    recomputed from the stored features with weights held fixed.
    """
    usable = _usable(rows)
    sub_cache = [compute_sub_scores(engine, row["features"], growth_mode) for row in usable]

    output: dict[str, Any] = {
        "comparison_note": "All methods use identical rows, per-cutoff-available features, "
                           "and future-event labels; validity depends on the data, not this table.",
        "threshold": threshold,
        "methods": {},
    }

    for method, sub_name in SUB_SCORE_BASELINES.items():
        pairs = [(subs[sub_name], int(row["label"])) for subs, row in zip(sub_cache, usable)]
        output["methods"][method] = _evaluate(pairs, threshold)

    # CVSS severity benchmark: only rows carrying an explicit numeric CVSS.
    cvss_pairs: list[tuple[float, int]] = []
    for row in usable:
        cvss = row["features"].get("cvss_base_score")
        if cvss is None:
            continue
        try:
            value = float(cvss)
        except (TypeError, ValueError):
            continue
        if 0.0 <= value <= 10.0:
            cvss_pairs.append((value * 10.0, int(row["label"])))
    output["methods"]["cvss_severity"] = _evaluate(cvss_pairs, threshold)
    if cvss_pairs:
        output["methods"]["cvss_severity"]["interpretation"] = (
            "CVSS is a severity benchmark, not a temporal forecaster; a strong CVSS result "
            "would mainly show that KEV additions skew toward high-CVSS CVEs.")

    # EPSS baseline on its own probability scale, with a documented threshold.
    epss_pairs = [
        (float(row["epss"]), int(row["label"]))
        for row in usable
        if row.get("epss") is not None
    ]
    epss_eval = _evaluate(epss_pairs, epss_threshold)
    epss_eval["epss_threshold"] = epss_threshold
    epss_eval["score_semantics"] = "FIRST EPSS probability for exploitation in the following 30 days"
    output["methods"]["epss"] = epss_eval

    if dtem_scores is not None and len(dtem_scores) == len(usable):
        pairs = [(float(score), int(row["label"])) for score, row in zip(dtem_scores, usable)]
    else:
        weights = engine.weights
        pairs = []
        for subs, row in zip(sub_cache, usable):
            value = sum(float(weights[name]) * float(subs[name]) for name in SUB_SCORE_BASELINES.values())
            pairs.append((value, int(row["label"])))
    output["methods"]["dtem_full"] = _evaluate(pairs, threshold)

    labels = [int(row["label"]) for row in usable]
    output["class_support"] = {"positive": sum(labels), "negative": len(labels) - sum(labels),
                               "two_class_present": set(labels) == {0, 1}}
    return output
