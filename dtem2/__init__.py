"""DTEM 2.0 experimental package.

This package keeps the original DTEM 1.0 code untouched and introduces a
separate, leakage-aware experimental stack for improved historical feature
engineering and scoring.
"""

from .features import HistoricalFeatureGuard, evidence_quality_diversity, recency_weighted_frequency, smoothed_log_growth
from .scoring import DTEM2ScoringEngine

__all__ = [
    "HistoricalFeatureGuard",
    "DTEM2ScoringEngine",
    "evidence_quality_diversity",
    "recency_weighted_frequency",
    "smoothed_log_growth",
]
