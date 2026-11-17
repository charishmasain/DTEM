from __future__ import annotations

import math
from typing import Any

from dtem2_redesign.features import count_based_growth, less_aggressive_frequency, source_count_diversity


class DTEM2RedesignScoring:
    """A targeted redesign that preserves ordering information by using actual counts."""

    def __init__(self, weights: dict[str, float] | None = None, growth_scale: float = 1.0) -> None:
        self.weights = weights or {
            "frequency": 0.40,
            "growth": 0.35,
            "diversity": 0.15,
            "exploit": 0.10,
        }
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-9:
            self.weights = {k: v / total for k, v in self.weights.items()}
        self.growth_scale = float(growth_scale)
        if self.growth_scale <= 0:
            raise ValueError("growth_scale must be positive")

    @staticmethod
    def _normalize_growth(value: Any) -> float:
        try:
            growth = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(growth):
            return 0.0
        return float(max(0.0, min(100.0, 50.0 * (1.0 + math.tanh(growth / 1.5)))))

    @staticmethod
    def _normalize_exploit(value: Any) -> float:
        try:
            exploit = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(exploit):
            return 0.0
        if exploit <= 0:
            return 0.0
        return float(max(0.0, min(100.0, 100.0 * exploit)))

    def score(self, features: dict[str, Any]) -> float:
        frequency_value = features.get("frequency", features.get("detection_frequency", 0.0))
        growth_value = features.get("growth")
        if growth_value is None:
            growth_value = features.get("growth_rate", 0.0)
        if "recent_activity" in features or "previous_activity" in features:
            recent_activity = features.get("recent_activity", 0.0)
            previous_activity = features.get("previous_activity", 0.0)
            growth_value = count_based_growth(recent_activity, previous_activity, alpha=1.0)
        if isinstance(growth_value, str):
            try:
                growth_value = float(growth_value)
            except ValueError:
                growth_value = 0.0
        frequency_score = less_aggressive_frequency(frequency_value)
        if isinstance(growth_value, (int, float)):
            growth_score = self._normalize_growth(growth_value)
        else:
            growth_score = 0.0
        diversity_value = features.get("diversity", features.get("source_diversity", 0.0))
        diversity_score = source_count_diversity(diversity_value)
        exploit_score = self._normalize_exploit(features.get("exploit", features.get("exploit_evidence_score", 0.0)))

        weighted = (
            self.weights["frequency"] * frequency_score +
            self.weights["growth"] * growth_score +
            self.weights["diversity"] * diversity_score +
            self.weights["exploit"] * exploit_score
        )
        return float(max(0.0, min(100.0, weighted)))

    def explain(self, features: dict[str, Any]) -> dict[str, Any]:
        frequency_value = features.get("frequency", features.get("detection_frequency", 0.0))
        growth_value = features.get("growth")
        if growth_value is None:
            growth_value = features.get("growth_rate", 0.0)
        diversity_value = features.get("diversity", features.get("source_diversity", 0.0))
        exploit_value = features.get("exploit", features.get("exploit_evidence_score", 0.0))
        return {
            "score": self.score(features),
            "weights": self.weights,
            "subscores": {
                "frequency": less_aggressive_frequency(frequency_value),
                "growth": self._normalize_growth(growth_value),
                "diversity": source_count_diversity(diversity_value),
                "exploit": self._normalize_exploit(exploit_value),
            },
        }
