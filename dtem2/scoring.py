from __future__ import annotations

import math
from typing import Any

from dtem2.features import bounded_log_growth_score


class DTEM2ScoringEngine:
    """Separate experimental emulator for improved DTEM features and weighting."""

    def __init__(self, weights: dict[str, float] | None = None, growth_scale: float = 1.386) -> None:
        self.weights = weights or {
            "frequency": 0.30,
            "growth": 0.25,
            "diversity": 0.20,
            "exploit": 0.25,
        }
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-9:
            self.weights = {k: v / total for k, v in self.weights.items()}
        self.growth_scale = float(growth_scale)
        if self.growth_scale <= 0:
            raise ValueError("growth_scale must be positive")

    @staticmethod
    def _normalize_frequency(value: Any) -> float:
        try:
            freq = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(freq):
            return 0.0
        if freq <= 0:
            return 0.0
        return min(100.0, 100.0 * math.log1p(freq) / math.log1p(30.0))

    @staticmethod
    def _normalize_diversity(value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(score):
            return 0.0
        return min(100.0, max(0.0, score))

    @staticmethod
    def _normalize_exploit(value: Any) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        if not math.isfinite(score):
            return 0.0
        return min(100.0, max(0.0, score))

    def score(self, features: dict[str, Any]) -> float:
        frequency_score = self._normalize_frequency(features.get("frequency", features.get("detection_frequency", 0.0)))
        growth_value = features.get("growth")
        if growth_value is None:
            growth_value = features.get("growth_rate", 0.0)
        if isinstance(growth_value, str):
            try:
                growth_value = float(growth_value)
            except ValueError:
                growth_value = 0.0
        if isinstance(growth_value, (int, float)):
            growth_score = bounded_log_growth_score(float(growth_value), scale=self.growth_scale)
        else:
            growth_score = 0.0
        diversity_score = self._normalize_diversity(features.get("diversity", features.get("source_diversity", 0.0)))
        exploit_score = self._normalize_exploit(features.get("exploit", features.get("exploit_evidence_score", 0.0)))
        weighted = (
            self.weights["frequency"] * frequency_score +
            self.weights["growth"] * growth_score +
            self.weights["diversity"] * diversity_score +
            self.weights["exploit"] * exploit_score
        )
        return float(min(100.0, max(0.0, weighted)))

    def explain(self, features: dict[str, Any]) -> dict[str, Any]:
        score = self.score(features)
        return {
            "score": score,
            "weights": self.weights,
            "subscores": {
                "frequency": self._normalize_frequency(features.get("frequency", features.get("detection_frequency", 0.0))),
                "growth": bounded_log_growth_score(float(features.get("growth", features.get("growth_rate", 0.0)) or 0.0), scale=self.growth_scale),
                "diversity": self._normalize_diversity(features.get("diversity", features.get("source_diversity", 0.0))),
                "exploit": self._normalize_exploit(features.get("exploit", features.get("exploit_evidence_score", 0.0))),
            },
        }
