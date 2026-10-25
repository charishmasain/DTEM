"""
dtem.evaluation.diagnostics
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Data-quality and redundancy diagnostics that answer *whether the indicators can
plausibly add information* before any claim that the composite score helps.

Two questions drive this module, both raised in the research critique:

  * Do the four indicators carry independent signal, or is one mostly a copy of
    another? Frequency and smoothed growth can be near-collinear, in which case a
    weighted combination of both buys little. ``feature_correlation`` quantifies
    Pearson and Spearman agreement between the normalized indicator sub-scores on
    the exact rows used by the evaluation and flags near-duplicate pairs.

  * Does "source diversity" reflect genuinely independent corroboration, or many
    records copied from one origin? ``source_independence_audit`` reports the
    distinct source labels actually present and an effective-independent-source
    estimate from near-duplicate content clustering. When a cohort collapses to a
    single source, diversity cannot contribute and this module says so plainly.

These are diagnostics, not performance metrics. A high correlation or a one-source
cohort is evidence about the *data*, and it constrains what any result on that data
can mean; it does not by itself prove or disprove DTEM.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Iterable, Optional

import numpy as np

from dtem.evaluation.ablation import INDICATORS, compute_sub_scores

# A pair of indicators above this absolute rank correlation is treated as
# near-duplicate for interpretation purposes; it is a reporting heuristic, not a
# statistical test, and must be disclosed rather than silently thresholded.
COLLINEAR_PAIR_THRESHOLD = 0.80


def _usable_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("label") is not None and row.get("features") is not None]


def _sub_score_matrix(rows: list[dict[str, Any]], engine: Any,
                      growth_mode: Optional[str]) -> np.ndarray:
    matrix = np.empty((len(rows), len(INDICATORS)), dtype=float)
    for i, row in enumerate(rows):
        subs = compute_sub_scores(engine, row["features"], growth_mode)
        matrix[i] = [float(subs[name]) for name in INDICATORS]
    return matrix


def _pearson(a: np.ndarray, b: np.ndarray) -> Optional[float]:
    if a.size < 2:
        return None
    if np.allclose(a, a[0]) or np.allclose(b, b[0]):
        # A constant column has undefined correlation, not zero correlation.
        return None
    coeff = np.corrcoef(a, b)[0, 1]
    if not math.isfinite(coeff):
        return None
    return float(coeff)


def _rankdata(values: np.ndarray) -> np.ndarray:
    """Average ranks with mid-rank handling for ties (Spearman prerequisite)."""
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(values.size, dtype=float)
    i = 0
    while i < values.size:
        j = i
        while j + 1 < values.size and values[order[j + 1]] == values[order[i]]:
            j += 1
        average = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = average
        i = j + 1
    return ranks


def feature_correlation(rows: list[dict[str, Any]], engine: Any, *,
                        growth_mode: Optional[str] = None,
                        threshold: float = COLLINEAR_PAIR_THRESHOLD) -> dict[str, Any]:
    """Correlate the four indicator sub-scores across the evaluation rows.

    Returns Pearson and Spearman matrices keyed by indicator name, plus a list of
    near-collinear pairs whose absolute rank correlation reaches ``threshold``.
    Undefined correlations (constant columns, fewer than two rows) are reported as
    ``None`` rather than 0, so a degenerate cohort is not mistaken for independence.
    """
    usable = _usable_rows(rows)
    if len(usable) < 2:
        return {"status": "insufficient_rows", "row_count": len(usable),
                "pearson": {}, "spearman": {}, "near_collinear_pairs": [],
                "note": "Correlation needs at least two labeled rows."}
    matrix = _sub_score_matrix(usable, engine, growth_mode)
    pearson: dict[str, dict[str, Optional[float]]] = {}
    spearman: dict[str, dict[str, Optional[float]]] = {}
    ranked = np.column_stack([_rankdata(matrix[:, col]) for col in range(matrix.shape[1])])
    for i, name_i in enumerate(INDICATORS):
        pearson[name_i] = {}
        spearman[name_i] = {}
        for j, name_j in enumerate(INDICATORS):
            pearson[name_i][name_j] = _round_or_none(_pearson(matrix[:, i], matrix[:, j]))
            spearman[name_i][name_j] = _round_or_none(_pearson(ranked[:, i], ranked[:, j]))

    near_collinear: list[dict[str, Any]] = []
    for i in range(len(INDICATORS)):
        for j in range(i + 1, len(INDICATORS)):
            rho = spearman[INDICATORS[i]][INDICATORS[j]]
            if rho is not None and abs(rho) >= threshold:
                near_collinear.append({
                    "pair": [INDICATORS[i], INDICATORS[j]],
                    "spearman": rho,
                    "interpretation": "These indicators rank the rows almost identically; "
                                      "the composite adds little over either alone.",
                })
    constant = [INDICATORS[c] for c in range(matrix.shape[1]) if np.allclose(matrix[:, c], matrix[0, c])]
    return {
        "status": "computed",
        "row_count": len(usable),
        "pearson": pearson,
        "spearman": spearman,
        "near_collinear_pairs": near_collinear,
        "constant_indicators": constant,
        "threshold": threshold,
        "note": "Correlation is measured on the same rows used for evaluation; it describes the "
                "data, and a near-duplicate pair limits what weighting that pair can accomplish.",
    }


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).strip().casefold())


def _content_signature(record: dict[str, Any]) -> str:
    body = _normalize_text(f"{record.get('title', '')} {record.get('content', '')}")
    return hashlib.sha1(body.encode("utf-8", "replace")).hexdigest() if body else ""


def source_independence_audit(observations: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Estimate how many genuinely independent sources back a cohort.

    Counts distinct ``source`` labels and clusters near-identical titles/bodies so
    a set of re-published copies is not mistaken for independent corroboration.
    ``effective_independent_sources`` is the count of distinct source labels after
    collapsing duplicate content; when it is 1, the diversity indicator cannot
    distinguish cases and any diversity-driven weighting is operating on noise.
    """
    records = [rec for rec in observations if isinstance(rec, dict)]
    if not records:
        return {"status": "no_records", "record_count": 0, "distinct_sources": 0,
                "effective_independent_sources": 0}
    source_counts: dict[str, int] = {}
    signatures_by_source: dict[str, set[str]] = {}
    all_signatures: set[str] = set()
    for rec in records:
        source = str(rec.get("source") or "unknown").strip() or "unknown"
        source_counts[source] = source_counts.get(source, 0) + 1
        sig = _content_signature(rec)
        if sig:
            signatures_by_source.setdefault(source, set()).add(sig)
            all_signatures.add(sig)
    distinct_sources = len(source_counts)
    unique_content = len(all_signatures)
    return {
        "status": "computed",
        "record_count": len(records),
        "source_counts": source_counts,
        "distinct_sources": distinct_sources,
        "unique_content_signatures": unique_content,
        "duplicate_content_records": len(records) - unique_content,
        "effective_independent_sources": distinct_sources,
        "single_source_cohort": distinct_sources <= 1,
        "warning": ("Cohort has a single source label; the source-diversity indicator cannot add "
                    "independent corroborating signal and should be treated as uninformative here."
                    if distinct_sources <= 1 else
                    "Multiple source labels present; source labels alone do not prove editorial "
                    "independence, and duplicate-content records were not removed from scoring."),
    }


def _round_or_none(value: Optional[float], digits: int = 4) -> Optional[float]:
    return round(value, digits) if value is not None else None
