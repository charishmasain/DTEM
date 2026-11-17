import math

from dtem2_redesign.features import (
    count_based_growth,
    less_aggressive_frequency,
    source_count_diversity,
    score_resolution_stats,
)
from dtem2_redesign.scoring import DTEM2RedesignScoring


class TestDTEM2Redesign:
    def test_count_based_growth_uses_recent_and_previous_counts(self):
        growth = count_based_growth(8, 2, alpha=1.0)
        assert math.isfinite(growth)
        assert growth > 0.0

    def test_less_aggressive_frequency_keeps_rank_signal(self):
        score = less_aggressive_frequency(14)
        assert 0.0 <= score <= 100.0
        assert less_aggressive_frequency(1) < less_aggressive_frequency(14)

    def test_source_count_diversity_is_not_heavily_saturated(self):
        score = source_count_diversity(["NVD", "Metasploit", "Nuclei"])
        assert 0.0 <= score <= 100.0
        assert score < 100.0

    def test_score_resolution_stats_measures_ties(self):
        stats = score_resolution_stats([10, 10, 20, 30, 30])
        assert "tie_fraction" in stats
        assert stats["tie_fraction"] > 0.0

    def test_redesign_scoring_keeps_variance(self):
        engine = DTEM2RedesignScoring()
        score_a = engine.score({"frequency": 10, "growth": 3.0, "diversity": 2, "exploit": 0.0})
        score_b = engine.score({"frequency": 1, "growth": 0.1, "diversity": 1, "exploit": 0.0})
        assert score_a > score_b
