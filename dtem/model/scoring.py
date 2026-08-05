"""
dtem.model.scoring
~~~~~~~~~~~~~~~~~~

Dynamic Threat Emergence Model (DTEM) Scoring Engine.

Computes a configurable, weighted Emergence Score (0–100) and maps it
to an Emergence Stage (Dormant, Growing, Emerging, Escalating).

Weights and stage thresholds are loaded dynamically from `config.json`
to avoid hardcoded magic numbers.
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional

import numpy as np

from dtem.extractor.features import ThreatInfoExtractor

logger = logging.getLogger(__name__)

# Config path resolution
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


def load_model_config() -> dict[str, Any]:
    """Load scoring weights and stage thresholds from config.json."""
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        config = json.load(fh)
    return config.get("emergence_model", {})


class DTEMScoringEngine:
    """
    Modular scoring engine for DTEM emergence calculation.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        cfg_path = config_path or _CONFIG_PATH
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh).get("emergence_model", {})

        self.weights: dict[str, float] = cfg.get("weights", {
            "detection_frequency": 0.25,
            "growth_rate": 0.30,
            "source_diversity": 0.20,
            "exploit_availability": 0.25,
        })

        self.stages_cfg: dict[str, dict[str, int]] = cfg.get("stages", {
            "dormant": {"min": 0, "max": 25},
            "growing": {"min": 26, "max": 50},
            "emerging": {"min": 51, "max": 75},
            "escalating": {"min": 76, "max": 100},
        })

    def calculate_emergence(self, extracted_features: dict[str, Any]) -> dict[str, Any]:
        """
        Compute Emergence Score and Stage from extracted features.

        Args:
            extracted_features: Dictionary output from ThreatInfoExtractor.

        Returns:
            Dictionary containing:
                - emergence_score (float, 0-100)
                - emergence_stage (str) — Dormant, Growing, Emerging, Escalating
                - sub_scores (dict) — normalized 0-100 values for each indicator
                - weights_used (dict) — configured weights used for computation
                - explainable_reasoning (list[str]) — narrative bullet points
        """
        raw_freq = extracted_features.get("detection_frequency", 0)
        raw_growth = extracted_features.get("growth_rate", 0.0)
        raw_div = extracted_features.get("source_diversity", 0)
        has_exploit = extracted_features.get("exploit_availability", False)
        exploit_ratio = extracted_features.get("breakdown", {}).get("exploit_ratio", 0.0)

        # 1. Normalize individual indicators to [0, 100] sub-scores
        sub_freq = self._normalize_frequency(raw_freq)
        sub_growth = self._normalize_growth_rate(raw_growth)
        sub_div = self._normalize_source_diversity(raw_div)
        sub_exploit = self._normalize_exploit_availability(has_exploit, exploit_ratio)

        sub_scores = {
            "detection_frequency": round(sub_freq, 2),
            "growth_rate": round(sub_growth, 2),
            "source_diversity": round(sub_div, 2),
            "exploit_availability": round(sub_exploit, 2),
        }

        # 2. Compute Weighted Emergence Score
        emergence_score = (
            self.weights["detection_frequency"] * sub_freq +
            self.weights["growth_rate"] * sub_growth +
            self.weights["source_diversity"] * sub_div +
            self.weights["exploit_availability"] * sub_exploit
        )
        emergence_score = float(np.clip(emergence_score, 0.0, 100.0))
        emergence_score = round(emergence_score, 2)

        # 3. Determine Emergence Stage
        emergence_stage = self._map_emergence_stage(emergence_score)

        # 4. Generate Explainable Reasoning
        reasoning = self._generate_reasoning(
            extracted_features, sub_scores, emergence_score, emergence_stage
        )

        return {
            "keyword": extracted_features.get("keyword", ""),
            "emergence_score": emergence_score,
            "emergence_stage": emergence_stage,
            "sub_scores": sub_scores,
            "weights_used": self.weights,
            "extracted_features": extracted_features,
            "explainable_reasoning": reasoning,
        }

    # ------------------------------------------------------------------ #
    # Normalization Helpers (0-100 scale)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalize_frequency(freq: int) -> float:
        """
        Logarithmic normalization of detection frequency.
        30+ reports saturates near 100.
        """
        if freq <= 0:
            return 0.0
        # Saturation point = 30 reports
        val = (np.log1p(freq) / np.log1p(30)) * 100.0
        return float(np.clip(val, 0.0, 100.0))

    @staticmethod
    def _normalize_growth_rate(growth_pct: float) -> float:
        """
        Normalizes growth rate percentage (-100% to +200%+) to [0, 100].
          - -100% (dead) -> 0
          - 0% (stable) -> 35
          - +50% (growing) -> 65
          - +150%+ (surging) -> 100
        """
        if growth_pct <= -100.0:
            return 0.0
        elif growth_pct <= 0:
            # -100 to 0 maps to 0 to 35
            return float((growth_pct + 100.0) / 100.0 * 35.0)
        elif growth_pct <= 150.0:
            # 0 to 150 maps to 35 to 90
            return float(35.0 + (growth_pct / 150.0) * 55.0)
        else:
            # > 150% caps at 100
            val = 90.0 + ((growth_pct - 150.0) / 150.0) * 10.0
            return float(np.clip(val, 90.0, 100.0))

    @staticmethod
    def _normalize_source_diversity(div_count: int) -> float:
        """
        Normalizes source diversity count.
        1 source = 25, 2 sources = 50, 3 sources = 75, 4+ sources = 100.
        """
        if div_count <= 0:
            return 0.0
        val = (div_count / 4.0) * 100.0
        return float(np.clip(val, 0.0, 100.0))

    @staticmethod
    def _normalize_exploit_availability(has_exploit: bool, exploit_ratio: float) -> float:
        """
        Normalizes exploit availability.
        If no exploit = 0.
        If exploit present = base 70 + (30 * exploit_ratio).
        """
        if not has_exploit:
            return 0.0
        val = 70.0 + (30.0 * np.clip(exploit_ratio, 0.0, 1.0))
        return float(np.clip(val, 70.0, 100.0))

    # ------------------------------------------------------------------ #
    # Stage Mapping
    # ------------------------------------------------------------------ #

    def _map_emergence_stage(self, score: float) -> str:
        """Map numeric score (0-100) to qualitative stage label."""
        for stage, bounds in self.stages_cfg.items():
            if bounds["min"] <= score <= bounds["max"]:
                return stage.capitalize()

        if score > 100:
            return "Escalating"
        return "Dormant"

    # ------------------------------------------------------------------ #
    # Explainable Reasoning Generator
    # ------------------------------------------------------------------ #

    def _generate_reasoning(
        self,
        features: dict[str, Any],
        sub_scores: dict[str, float],
        total_score: float,
        stage: str,
    ) -> list[str]:
        """
        Generate clear narrative reasoning explaining why the score was generated.
        """
        kw = features.get("keyword", "The threat")
        reasons = []

        # Overall stage statement
        reasons.append(
            f"'{kw}' has been evaluated at the **{stage.upper()}** stage with a DTEM Emergence Score of **{total_score}/100**."
        )

        # Growth Rate reasoning
        growth = features.get("growth_rate", 0.0)
        trend = features.get("growth_trend", "stable")
        recent = features.get("breakdown", {}).get("recent_reports", 0)
        if growth > 50:
            reasons.append(
                f"**Rapid Velocity**: High growth rate (+{growth:.1f}%) observed with {recent} reports in the last 14 days, signaling a surging temporal trend."
            )
        elif growth > 0:
            reasons.append(
                f"**Moderate Velocity**: Positive growth rate (+{growth:.1f}%) indicates expanding discussion across security feeds."
            )
        else:
            reasons.append(
                f"**Stable/Declining Velocity**: Growth rate of {growth:.1f}% indicates steady or diminishing report volume."
            )

        # Source Diversity reasoning
        div = features.get("source_diversity", 0)
        sources = ", ".join(features.get("sources_list", []))
        if div >= 4:
            reasons.append(
                f"**High Multi-Source Cross-Validation**: Intelligence corroborated across {div} distinct independent channels ({sources})."
            )
        elif div > 1:
            reasons.append(
                f"**Moderate Cross-Validation**: Reported across {div} sources ({sources})."
            )
        else:
            reasons.append(
                f"**Single-Source Detection**: Activity currently confined to 1 source."
            )

        # Exploit Availability reasoning
        has_exp = features.get("exploit_availability", False)
        exp_cnt = features.get("exploit_count", 0)
        if has_exp:
            reasons.append(
                f"**Active Exploit Ecosystem**: Public exploit code or functional builder discussions detected in {exp_cnt} reports (+{sub_scores['exploit_availability']:.0f} sub-score contribution)."
            )
        else:
            reasons.append(
                "**No Public Exploit Detected**: No functional exploit code or PoC discussions found in collected records."
            )

        return reasons
