import math

import pytest

from dtem2.features import (
    HistoricalFeatureGuard,
    evidence_quality_diversity,
    recency_weighted_frequency,
    smoothed_log_growth,
)
from dtem2.scoring import DTEM2ScoringEngine


class TestDTEM2Core:
    def test_recency_weighted_frequency_is_numeric(self):
        events = [
            {"timestamp": "2025-01-01T00:00:00Z"},
            {"timestamp": "2025-01-05T00:00:00Z"},
        ]
        score = recency_weighted_frequency(events, cutoff="2025-01-10T00:00:00Z", half_life_days=14)
        assert score >= 0.0
        assert score <= 100.0

    def test_log_growth_handles_zero_previous_window(self):
        growth = smoothed_log_growth(
            recent=3,
            previous=0,
            alpha=1.0,
        )
        assert math.isfinite(growth)
        assert growth > 0.0

    def test_diversity_reduces_duplicate_overlap(self):
        rows = [
            {"source": "NVD", "event_id": "e1", "timestamp": "2025-01-01T00:00:00Z"},
            {"source": "NVD", "event_id": "e1", "timestamp": "2025-01-01T00:00:00Z"},
            {"source": "Metasploit", "event_id": "e2", "timestamp": "2025-01-03T00:00:00Z"},
            {"source": "Nuclei", "event_id": "e3", "timestamp": "2025-01-04T00:00:00Z"},
        ]
        score = evidence_quality_diversity(rows)
        assert 0.0 <= score <= 100.0

    def test_guard_rejects_future_data(self):
        guard = HistoricalFeatureGuard()
        row = {"available_at": "2025-02-10T00:00:00Z", "published_at": "2025-02-20T00:00:00Z"}
        assert guard.is_eligible(row, cutoff="2025-02-15T00:00:00Z") is False

    def test_dtem2_scoring_is_bounded(self):
        engine = DTEM2ScoringEngine()
        score = engine.score({
            "frequency": 80.0,
            "growth": 60.0,
            "diversity": 70.0,
            "exploit": 90.0,
        })
        assert 0.0 <= score <= 100.0
