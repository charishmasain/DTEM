from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Iterable


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class HistoricalFeatureGuard:
    """Tight historical eligibility checks for DTEM 2.0 features."""

    @staticmethod
    def is_eligible(record: dict[str, Any], cutoff: Any) -> bool:
        cutoff_dt = _parse_timestamp(cutoff)
        if cutoff_dt is None:
            return False
        available = _parse_timestamp(record.get("available_at") or record.get("collected_at"))
        published = _parse_timestamp(record.get("published_at"))
        if available is None or published is None:
            return False
        if available > cutoff_dt or published > cutoff_dt:
            return False
        source = str(record.get("source") or "").lower()
        if source in {"darkweb", "dark-web", "dark web"} and record.get("historical_capture") is not True:
            return False
        return True

    @classmethod
    def filter_records(cls, records: Iterable[dict[str, Any]], cutoff: Any) -> list[dict[str, Any]]:
        return [record for record in records if cls.is_eligible(record, cutoff)]


def recency_weighted_frequency(events: Iterable[dict[str, Any]], cutoff: Any, half_life_days: float = 14.0) -> float:
    """Return a bounded 0..100 recency-weighted activity score.

    The score is the sum of exp(-lambda * age_days) with a logarithmic saturation.
    """
    cutoff_dt = _parse_timestamp(cutoff)
    if cutoff_dt is None:
        return 0.0
    half_life = float(half_life_days)
    if not math.isfinite(half_life) or half_life <= 0:
        raise ValueError("half_life_days must be positive and finite")
    total = 0.0
    for event in events:
        ts = _parse_timestamp(event.get("timestamp") or event.get("published_at") or event.get("available_at"))
        if ts is None:
            continue
        age_days = max(0.0, (cutoff_dt - ts).total_seconds() / 86400.0)
        total += math.exp(-math.log(2.0) * age_days / half_life)
    # Saturation constant matches the historical normalisation behaviour but keeps
    # the score in a bounded and interpretable range.
    return float(min(100.0, 100.0 * math.log1p(total) / math.log1p(30.0)))


def smoothed_log_growth(recent: float, previous: float, alpha: float = 1.0) -> float:
    """Compute the smoothed log growth ratio G = log((R + alpha)/(P + alpha))."""
    try:
        recent_n = float(recent)
        previous_n = float(previous)
        alpha_n = float(alpha)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(recent_n) or not math.isfinite(previous_n) or not math.isfinite(alpha_n):
        return 0.0
    if alpha_n <= 0:
        raise ValueError("alpha must be positive")
    if previous_n < 0:
        previous_n = 0.0
    if recent_n < 0:
        recent_n = 0.0
    ratio = (recent_n + alpha_n) / (previous_n + alpha_n)
    if ratio <= 0:
        return 0.0
    return math.log(ratio)


def bounded_log_growth_score(log_growth: float, scale: float = 1.386) -> float:
    """Map smoothed log growth into a bounded 0..100 score."""
    try:
        value = float(log_growth)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(value):
        return 0.0
    if scale <= 0:
        raise ValueError("scale must be positive")
    return float(min(100.0, max(0.0, 50.0 * (1.0 + math.tanh(value / scale)))))


def evidence_quality_diversity(records: Iterable[dict[str, Any]]) -> float:
    """Weighted source diversity that discounts duplicate or overlapping evidence."""
    reliability = {
        "nvd": 0.7,
        "metasploit": 0.9,
        "nuclei": 0.8,
        "otx": 0.75,
        "alienvault": 0.75,
        "github": 0.6,
    }
    seen: set[tuple[str, str, str]] = set()
    weighted_total = 0.0
    for record in records:
        source = str(record.get("source") or "unknown").strip().lower()
        event_id = str(record.get("event_id") or record.get("id") or record.get("url") or record.get("title") or "").strip()
        if not source and not event_id:
            continue
        dedupe_key = (source, event_id, str(record.get("published_at") or record.get("available_at") or "").strip())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        weighted_total += reliability.get(source, 0.55)
    # Normalize as an interpretable 0..100 score with a 3-source ceiling.
    return float(min(100.0, max(0.0, 100.0 * weighted_total / 3.0)))
