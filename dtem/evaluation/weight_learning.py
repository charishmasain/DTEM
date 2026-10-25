"""
dtem.evaluation.weight_learning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Learn the DTEM indicator weights from data instead of assuming them, under a
strict leakage-safe protocol: **fit only on development, choose settings only on
validation, and evaluate the final model once on a later held-out test period.**

The composite score is a linear function of the four normalized sub-scores, so
learning weights is a linear ranking problem. Directly maximizing average
precision is non-smooth, so the fit minimizes a smooth pairwise logistic-ranking
loss on the development rows only: for every (positive, negative) pair it
penalizes cases where the negative is scored above the positive, the standard
RankNet objective. Weights are constrained to the probability simplex (non-negative,
summing to 1) by projected gradient descent, so a learned model stays on the same
interpretable 0-100 scale as the hand-set model and can be compared directly.

Nothing here manufactures a win. When development data has only one class, or when
the test period has too few positives, average precision and precision-at-budget are
undefined and are reported as such rather than coerced. Whether learned weights beat
frequency-only on the untouched test period is an empirical outcome, and this module
reports it honestly either way.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Optional

import numpy as np

from dtem.evaluation.ablation import INDICATORS
from dtem.evaluation.diagnostics import _sub_score_matrix, _usable_rows
from dtem.evaluation.metrics import alert_budget_metrics, pr_auc, threshold_metrics
from dtem.evaluation.split import partition_periods


def _project_onto_simplex(v: np.ndarray) -> np.ndarray:
    """Euclidean projection of ``v`` onto the simplex {w >= 0, sum(w) = 1}."""
    v = np.asarray(v, dtype=float)
    u = np.sort(v)[::-1]
    cssv = np.cumsum(u) - 1.0
    support = np.nonzero(u * np.arange(1, v.size + 1) > cssv)[0]
    if support.size == 0:
        return np.full_like(v, 1.0 / v.size)
    rho = support[-1]
    theta = cssv[rho] / (rho + 1.0)
    return np.maximum(v - theta, 0.0)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 0.5 * (1.0 + np.tanh(0.5 * z))


def _pairs(labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    pos = np.flatnonzero(labels == 1)
    neg = np.flatnonzero(labels == 0)
    if pos.size == 0 or neg.size == 0:
        return np.empty(0, dtype=int), np.empty(0, dtype=int)
    return np.repeat(pos, neg.size), np.tile(neg, pos.size)


def fit_weights(dev_rows: Iterable[dict[str, Any]], engine: Any, *,
                growth_mode: Optional[str] = None, n_iter: int = 400,
                lr: float = 0.5, temperature: float = 1.0,
                ridge_to_uniform: float = 0.0) -> dict[str, Any]:
    """Fit simplex-constrained weights on development rows by RankNet descent.

    Returns the learned weight vector, the development average precision under
    uniform-init vs learned weights, and diagnostics. With fewer than two rows or
    a single class the objective is undefined and the original weights are echoed
    back unchanged with a ``status`` explaining why, so a caller cannot silently
    report a "learned" model that never saw a positive example.
    """
    usable = _usable_rows(dev_rows)
    labels = np.array([int(row["label"]) for row in usable], dtype=int)
    if len(usable) < 2 or set(labels.tolist()) != {0, 1}:
        return {"status": "single_class_or_insufficient_rows",
                "row_count": len(usable),
                "positive": int(labels.sum()) if labels.size else 0,
                "weights": dict(engine.weights),
                "note": "Weights cannot be learned without both classes on development data; "
                        "the original weights are returned unchanged."}
    x = _sub_score_matrix(usable, engine, growth_mode)
    pos_idx, neg_idx = _pairs(labels)
    dim = len(INDICATORS)
    prior = np.array([float(engine.weights[name]) for name in INDICATORS])
    prior = prior / prior.sum() if prior.sum() > 0 else np.full(dim, 1.0 / dim)
    w = prior.copy()
    uniform_dev_ap = pr_auc(labels.tolist(), (x @ prior).tolist()).get("pr_auc")
    best_w = w.copy()
    best_ap = -math.inf
    step = float(lr)
    for _ in range(int(n_iter)):
        scores = x @ w
        margins = (scores[pos_idx] - scores[neg_idx]) / temperature
        g = _sigmoid(-margins) / temperature            # d loss / d margin
        coeff = np.zeros(len(labels))
        np.add.at(coeff, pos_idx, -g)
        np.add.at(coeff, neg_idx, g)
        grad = x.T @ coeff
        if ridge_to_uniform > 0:
            grad = grad + ridge_to_uniform * (w - prior)
        candidate = _project_onto_simplex(w - step * grad)
        if not np.all(np.isfinite(candidate)):
            break
        w = candidate
        ap = pr_auc(labels.tolist(), (x @ w).tolist()).get("pr_auc")
        if ap is not None and ap > best_ap:
            best_ap = ap
            best_w = w.copy()
    learned = {name: float(round(value, 6)) for name, value in zip(INDICATORS, best_w)}
    renorm = sum(learned.values())
    if renorm <= 0:
        return {"status": "degenerate_zero_weights", "weights": dict(engine.weights),
                "note": "Learning collapsed to all-zero weights; original weights retained."}
    learned = {name: round(value / renorm, 6) for name, value in learned.items()}
    return {
        "status": "fit",
        "row_count": len(usable),
        "positive": int(labels.sum()),
        "temperature": temperature, "learning_rate": lr, "n_iter": n_iter,
        "ridge_to_uniform": ridge_to_uniform,
        "dev_pr_auc_uniform": uniform_dev_ap,
        "dev_pr_auc_learned": round(best_ap, 6) if best_ap != -math.inf else None,
        "weights": learned,
    }


def _score_rows(rows: list[dict[str, Any]], engine: Any, weights: dict[str, float],
                growth_mode: Optional[str]) -> tuple[list[float], list[int]]:
    scores: list[float] = []
    labels: list[int] = []
    for row in rows:
        subs = _sub_score_matrix([row], engine, growth_mode)[0]
        value = float(sum(float(weights[name]) * float(subs[i]) for i, name in enumerate(INDICATORS)))
        scores.append(value)
        labels.append(int(row["label"]))
    return scores, labels


def _period_metrics(rows: list[dict[str, Any]], engine: Any, weights: dict[str, float], *,
                    growth_mode: Optional[str], threshold: float,
                    budget_fraction: float) -> dict[str, Any]:
    usable = _usable_rows(rows)
    if not usable:
        return {"sample_count": 0, "pr_auc": None, "pr_auc_status": "no_rows",
                "alert_budget": None, "threshold_metrics": None}
    scores, labels = _score_rows(usable, engine, weights, growth_mode)
    ranking = pr_auc(labels, scores)
    return {
        "sample_count": len(usable),
        "positive": sum(labels),
        "pr_auc": ranking.get("pr_auc"),
        "pr_auc_status": ranking.get("status"),
        "random_baseline": ranking.get("random_baseline"),
        "alert_budget": alert_budget_metrics(labels, scores, budget_fraction=budget_fraction),
        "threshold_metrics": threshold_metrics(labels, scores, threshold),
    }


def run_weight_learning(rows: list[dict[str, Any]], engine: Any, *,
                        dev_fraction: float = 0.6, val_fraction: float = 0.2,
                        threshold: float = 50.0, growth_mode: Optional[str] = None,
                        budget_fraction: float = 0.1,
                        temperatures: Iterable[float] = (0.5, 1.0, 2.0)) -> dict[str, Any]:
    """Fit on development, pick a setting on validation, evaluate once on test.

    Compares three models on identical rows/labels in every period: the original
    hand-set DTEM weights, the data-learned DTEM weights, and the frequency-only
    baseline (the bar the critique says the model must clear). The headline result
    is the held-out **test** comparison between learned DTEM and frequency-only,
    reported with average precision and precision-at-alert-budget. A learned model
    that does not beat frequency-only on test is reported as such, not hidden.
    """
    partition = partition_periods(rows, dev_fraction=dev_fraction, val_fraction=val_fraction)
    if partition["status"] != "computed":
        return {"status": partition["status"], "note": "Need dated cutoffs to split periods."}
    buckets = partition["buckets"]
    original = {name: float(engine.weights[name]) for name in INDICATORS}
    frequency_only = {"detection_frequency": 1.0, "growth_rate": 0.0,
                      "source_diversity": 0.0, "exploit_availability": 0.0}

    candidates = []
    for temp in temperatures:
        fit = fit_weights(buckets["development"], engine, growth_mode=growth_mode,
                          temperature=float(temp))
        candidates.append({"temperature": float(temp), "fit": fit})

    two_class_dev = all(c["fit"]["status"] == "fit" for c in candidates)
    # Select the setting on validation only (never on test).
    selected = None
    if two_class_dev:
        val_scores = []
        for cand in candidates:
            val = _period_metrics(buckets["validation"], engine, cand["fit"]["weights"],
                                  growth_mode=growth_mode, threshold=threshold,
                                  budget_fraction=budget_fraction)
            val_scores.append((val.get("pr_auc") if val["pr_auc"] is not None else -1.0,
                               val.get("alert_budget", {}).get("precision_at_budget")
                               if val.get("alert_budget") else -1.0, cand))
        val_scores.sort(key=lambda item: (item[0], item[1]), reverse=True)
        selected = val_scores[0][2]

    learned_weights = selected["fit"]["weights"] if selected else original
    result: dict[str, Any] = {
        "protocol": "fit on development, select setting on validation, evaluate once on test",
        "boundaries": partition["boundaries"],
        "period_counts": {name: len(_usable_rows(items)) for name, items in buckets.items()},
        "weights": {
            "original": original,
            "learned": learned_weights,
            "selection_temperature": selected["temperature"] if selected else None,
        },
        "learning_eligible": two_class_dev,
        "models": {
            "original_dtem": {},
            "learned_dtem": {},
            "frequency_only": {},
        },
    }
    if not two_class_dev:
        result["status"] = "development_lacks_both_classes"
        result["note"] = ("Development has no positive (or no negative) examples, so weights cannot be "
                          "learned; original and learned columns are identical and no superiority claim "
                          "is supported.")
    else:
        result["status"] = "computed"

    for name, items in buckets.items():
        result["models"]["original_dtem"][name] = _period_metrics(
            items, engine, original, growth_mode=growth_mode, threshold=threshold,
            budget_fraction=budget_fraction)
        result["models"]["learned_dtem"][name] = _period_metrics(
            items, engine, learned_weights, growth_mode=growth_mode, threshold=threshold,
            budget_fraction=budget_fraction)
        result["models"]["frequency_only"][name] = _period_metrics(
            items, engine, frequency_only, growth_mode=growth_mode, threshold=threshold,
            budget_fraction=budget_fraction)

    # Headline acceptance check on the untouched test period only.
    learned_test = result["models"]["learned_dtem"]["test"]
    freq_test = result["models"]["frequency_only"]["test"]
    result["test_comparison"] = _test_comparison(learned_test, freq_test, two_class_dev)
    result["caveats"] = [
        "Learned weights are fit on development only; validation selects the setting; test is read once.",
        "With few positives, average precision and precision-at-budget can be undefined; absence of a "
        "number is not a zero and not evidence of failure.",
        "Recurring CVEs across periods break sample independence; treat intervals as optimistic.",
    ]
    return result


def _test_comparison(learned_test: dict[str, Any], freq_test: dict[str, Any],
                    learned_eligible: bool) -> dict[str, Any]:
    """Summarize learned-DTEM vs frequency-only on the held-out test period."""
    def delta(key: str) -> Optional[float]:
        a, b = learned_test.get(key), freq_test.get(key)
        if a is None or b is None:
            return None
        return round(a - b, 6)

    learned_lap = (learned_test.get("alert_budget") or {}).get("precision_at_budget")
    freq_lap = (freq_test.get("alert_budget") or {}).get("precision_at_budget")
    ap_delta = delta("pr_auc")
    lap_delta = None
    if learned_lap is not None and freq_lap is not None:
        lap_delta = round(learned_lap - freq_lap, 6)
    if not learned_eligible:
        verdict = "not_testable_development_lacks_both_classes"
    elif learned_test.get("pr_auc") is None or freq_test.get("pr_auc") is None:
        verdict = "undefined_on_test_single_class_or_empty"
    elif (ap_delta or 0) > 0 and (lap_delta or 0) >= 0:
        verdict = "learned_beats_frequency_only"
    elif (ap_delta or 0) < 0 or (lap_delta is not None and lap_delta < 0):
        verdict = "frequency_only_matches_or_beats_learned"
    else:
        verdict = "tie"
    return {
        "pr_auc_delta": ap_delta,
        "precision_at_budget_delta": lap_delta,
        "learned_beats_frequency_only_on_test": verdict == "learned_beats_frequency_only",
        "verdict": verdict,
        "note": "This is the pre-registered acceptance signal; it must be judged on the untouched "
                "test period and must survive the independence caveat before any superiority claim.",
    }
