"""
dtem.evaluation.split
~~~~~~~~~~~~~~~~~~~~~

Chronological development / validation / held-out-test partitioning for DTEM
evaluation rows.

Weight and threshold selection must use development data only; validation is for
one round of model selection; the final test period is touched once. Splitting by
prediction cutoff time (never randomly, and never by CVE) keeps later information
out of earlier fitting, which a random split would leak. Rows carry a ``cutoff``
timestamp and a ``label``.

A CVE that recurs across cutoffs will appear in more than one period. That is not
a temporal leak, but it violates the independent-samples assumption behind the
confidence intervals, so it is counted and reported rather than hidden.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dtem.evaluation.metrics import pr_auc, threshold_metrics

PERIODS: tuple[str, ...] = ("development", "validation", "test")


def _parse_cutoff(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def chronological_split(rows: list[dict[str, Any]], *, dev_fraction: float = 0.6,
                        val_fraction: float = 0.2, threshold: float = 50.0,
                        dtem_score_key: str = "score") -> dict[str, Any]:
    """Partition rows into time-ordered periods and summarize each period.

    ``dev_fraction`` and ``val_fraction`` are proportions of the *distinct cutoff
    timestamps*, so every cutoff for a given moment lands in the same period. The
    remainder becomes the held-out test period.
    """
    if dev_fraction <= 0 or val_fraction <= 0 or dev_fraction + val_fraction >= 1:
        raise ValueError("dev_fraction and val_fraction must be positive and sum to less than 1")
    usable = [row for row in rows if _parse_cutoff(row.get("cutoff")) is not None]
    ordered_cutoffs = sorted({row["cutoff"] for row in usable},
                             key=lambda value: _parse_cutoff(value))
    if not ordered_cutoffs:
        return {"status": "no_dated_cutoffs", "periods": {}, "leakage": {},
                "recommendation": "Provide rows with an ISO 'cutoff' timestamp before splitting."}

    n = len(ordered_cutoffs)
    dev_end = ordered_cutoffs[max(0, int(round(dev_fraction * n)) - 1)]
    val_end = ordered_cutoffs[min(n - 1, int(round((dev_fraction + val_fraction) * n)) - 1)]
    dev_key = _parse_cutoff(dev_end)
    val_key = _parse_cutoff(val_end)

    buckets: dict[str, list[dict[str, Any]]] = {name: [] for name in PERIODS}
    for row in usable:
        moment = _parse_cutoff(row["cutoff"])
        if moment <= dev_key:
            buckets["development"].append(row)
        elif moment <= val_key:
            buckets["validation"].append(row)
        else:
            buckets["test"].append(row)

    periods: dict[str, Any] = {}
    for name, items in buckets.items():
        labels = [int(row["label"]) for row in items if row.get("label") is not None]
        scores = [float(row[dtem_score_key]) for row in items
                  if row.get("label") is not None and row.get(dtem_score_key) is not None]
        ranking = pr_auc(labels, scores) if scores else {"pr_auc": None, "status": "no_scores"}
        periods[name] = {
            "row_count": len(items),
            "distinct_cutoffs": len({row["cutoff"] for row in items}),
            "distinct_cves": len({row.get("cve_id") for row in items}),
            "class_support": {"positive": sum(labels), "negative": len(labels) - sum(labels)},
            "pr_auc": ranking.get("pr_auc"),
            "pr_auc_status": ranking.get("status"),
            "threshold_metrics": threshold_metrics(labels, scores, threshold) if scores else None,
        }

    # Cross-period CVE recurrence (independence, not temporal leakage).
    cve_periods: dict[str, set[str]] = {}
    for name, items in buckets.items():
        for row in items:
            cve = row.get("cve_id")
            if cve:
                cve_periods.setdefault(cve, set()).add(name)
    recurring = sum(1 for periods_seen in cve_periods.values() if len(periods_seen) > 1)

    return {
        "status": "computed",
        "boundaries": {"development_through": dev_end, "validation_through": val_end,
                       "test_after": val_end},
        "periods": periods,
        "leakage": {
            "temporal_leakage_prevented": True,
            "split_basis": "distinct prediction cutoff timestamps, ordered chronologically",
            "cves_spanning_multiple_periods": recurring,
            "note": "Recurring CVEs across periods break sample independence; report confidence "
                    "intervals with this caveat, and never fit weights or thresholds outside development.",
        },
        "recommendation": "Select weights/thresholds on development, confirm on validation, and "
                          "evaluate the final model once on the held-out test period.",
    }
