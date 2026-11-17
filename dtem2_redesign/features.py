from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Sequence


def _clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    return max(lower, min(upper, float(value)))


def count_based_growth(recent: Any, previous: Any, alpha: float = 1.0) -> float:
    """Compute a log-ratio growth signal using actual recent and previous counts.

    This keeps the instability of the raw signal, but prevents the explosion that
    occurs when one uses a generic bounded transform without the underlying count
    data. The alpha term makes the score finite in sparse time windows.
    """
    try:
        recent_value = float(recent)
        previous_value = float(previous)
        alpha_value = float(alpha)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(recent_value) or not math.isfinite(previous_value) or not math.isfinite(alpha_value):
        return 0.0
    if alpha_value <= 0:
        raise ValueError("alpha must be positive")
    recent_value = max(0.0, recent_value)
    previous_value = max(0.0, previous_value)
    ratio = (recent_value + alpha_value) / (previous_value + alpha_value)
    if ratio <= 0.0:
        return 0.0
    return math.log(ratio)


def less_aggressive_frequency(value: Any, cap: float = 8.0) -> float:
    """Map raw frequencies to a 0..100 scale without collapsing all mid-range values."""
    try:
        frequency = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(frequency):
        return 0.0
    if frequency <= 0:
        return 0.0
    if cap <= 0:
        raise ValueError("cap must be positive")
    return _clamp(100.0 * math.log1p(frequency) / math.log1p(cap))


def source_count_diversity(sources: Any) -> float:
    """Keep source diversity interpretable while avoiding a hard 3-source collapse."""
    if sources is None:
        return 0.0
    if isinstance(sources, (int, float)):
        count = float(sources)
        return _clamp(75.0 * count / 3.0)
    if isinstance(sources, str):
        parts = [item.strip().lower() for item in sources.split(",") if item.strip()]
        unique = len(set(parts))
        return _clamp(75.0 * unique / 3.0)
    if isinstance(sources, Iterable):
        unique = {str(item).strip().lower() for item in sources if str(item).strip()}
        return _clamp(75.0 * len(unique) / 3.0)
    return 0.0


def score_resolution_stats(scores: Sequence[float]) -> dict[str, float | int]:
    """Report how much of the score distribution is tied, which diagnoses rank collapse."""
    sequence = [float(score) for score in scores]
    if not sequence:
        return {"n_scores": 0, "unique_scores": 0, "tie_fraction": 0.0, "mean": 0.0, "median": 0.0, "std": 0.0}
    counts = Counter(sequence)
    ties = sum(count for count in counts.values() if count > 1)
    unique_scores = len(counts)
    sorted_scores = sorted(sequence)
    median = sorted_scores[len(sorted_scores) // 2] if len(sorted_scores) % 2 else (sorted_scores[len(sorted_scores) // 2 - 1] + sorted_scores[len(sorted_scores) // 2]) / 2.0
    mean_value = sum(sorted_scores) / len(sorted_scores)
    variance = sum((v - mean_value) ** 2 for v in sorted_scores) / len(sorted_scores)
    return {
        "n_scores": len(sequence),
        "unique_scores": unique_scores,
        "tie_fraction": ties / len(sequence),
        "mean": mean_value,
        "median": median,
        "std": math.sqrt(variance),
    }
