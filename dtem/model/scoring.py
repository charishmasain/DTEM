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
import math
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
        required = {"detection_frequency", "growth_rate", "source_diversity", "exploit_availability"}
        if set(self.weights) != required:
            raise ValueError(f"weights must contain exactly {sorted(required)}")
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0
               for v in self.weights.values()):
            raise ValueError("weights must be finite and non-negative")
        if not math.isclose(sum(self.weights.values()), 1.0, abs_tol=1e-9):
            raise ValueError("emergence weights must sum to 1")

        self.stages_cfg: dict[str, dict[str, int]] = cfg.get("stages", {
            "dormant": {"min": 0, "max": 25},
            "growing": {"min": 26, "max": 50},
            "emerging": {"min": 51, "max": 75},
            "escalating": {"min": 76, "max": 100},
        })

        # Growth transform is a documented design choice, not an empirically
        # selected parameter. "legacy" keeps the historical percentage curve;
        # "log" uses the bounded smoothed log-growth sub-score. Because no
        # development dataset exists yet, the default stays "legacy" so the
        # candidate transform is not silently promoted to production.
        self.growth_mode: str = str(cfg.get("growth_mode", "legacy")).casefold()
        if self.growth_mode not in {"legacy", "log"}:
            raise ValueError("growth_mode must be 'legacy' or 'log'")
        scale = cfg.get("log_growth_scale", math.log(4.0))
        try:
            scale = float(scale)
        except (TypeError, ValueError):
            raise ValueError("log_growth_scale must be finite and positive") from None
        if not math.isfinite(scale) or scale <= 0:
            raise ValueError("log_growth_scale must be finite and positive")
        self.log_growth_scale: float = scale

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
        exploit_evidence_score = extracted_features.get("exploit_evidence_score")

        # An empty evidence set is not a measured zero-growth trajectory.
        # In particular, mapping a missing growth observation to the stable
        # 35-point sub-score would create a non-zero result from no evidence.
        try:
            evidence_count = int(extracted_features.get("total_records", raw_freq) or 0)
        except (TypeError, ValueError, OverflowError):
            evidence_count = 0
        has_evidence = evidence_count > 0

        # 1. Normalize individual indicators to [0, 100] sub-scores
        sub_freq = self._normalize_frequency(raw_freq)
        growth_is_available = "growth_rate" in extracted_features and extracted_features.get("growth_rate") is not None
        if self.growth_mode == "log":
            raw_log_growth = extracted_features.get("growth_log_rate")
            log_available = raw_log_growth is not None and growth_is_available
            sub_growth = self._normalize_log_growth(raw_log_growth, self.log_growth_scale) if (has_evidence and log_available) else 0.0
        else:
            sub_growth = self._normalize_growth_rate(raw_growth) if has_evidence and growth_is_available else 0.0
        sub_div = self._normalize_source_diversity(raw_div)
        try:
            evidence_score = float(exploit_evidence_score)
        except (TypeError, ValueError, OverflowError):
            evidence_score = float("nan")
        if exploit_evidence_score is None:
            sub_exploit = self._normalize_exploit_availability(has_exploit, exploit_ratio)
        elif math.isfinite(evidence_score):
            sub_exploit = float(np.clip(evidence_score, 0.0, 100.0))
        else:
            sub_exploit = 0.0

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
        emergence_stage = self._map_emergence_stage(emergence_score) if has_evidence else "Unavailable"

        # 4. Generate Explainable Reasoning
        reasoning = (self._generate_reasoning(
            extracted_features, sub_scores, emergence_score, emergence_stage
        ) if has_evidence else [
            "No eligible CTI evidence is available for this query. An emergence score and risk estimate cannot be assessed."
        ])

        return {
            "keyword": extracted_features.get("keyword", ""),
            "emergence_score": emergence_score if has_evidence else None,
            "emergence_stage": emergence_stage,
            "score_status": "scored" if has_evidence else "insufficient_data",
            "sub_scores": sub_scores,
            "weights_used": self.weights,
            "growth_mode": self.growth_mode,
            "log_growth_scale": self.log_growth_scale,
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
        try:
            freq = float(freq)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if not math.isfinite(freq) or freq <= 0:
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
        try:
            growth_pct = float(growth_pct)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if math.isnan(growth_pct):
            return 0.0
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
    def _normalize_log_growth(log_growth: Optional[float], scale: float) -> float:
        """Map smoothed log-growth ``G = ln((R+a)/(P+a))`` to a bounded [0, 100].

        The transform is ``50 * (1 + tanh(G / scale))``. It is symmetric and
        monotonic: ``G = 0`` (no net change) maps to 50, growth saturates toward
        100, and decline saturates toward 0. ``scale`` sets the log-growth value
        at which the sub-score is approximately 88 (``tanh(1)``); it is a design
        constant, not a fitted parameter. ``None`` or non-finite input maps to 0,
        matching the treatment of an unavailable growth indicator.
        """
        if log_growth is None:
            return 0.0
        try:
            value = float(log_growth)
            scale = float(scale)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if not math.isfinite(scale) or scale <= 0:
            raise ValueError("log_growth_scale must be finite and positive")
        if math.isnan(value):
            return 0.0
        if value == float("inf"):
            return 100.0
        if value == float("-inf"):
            return 0.0
        val = 50.0 * (1.0 + math.tanh(value / scale))
        return float(np.clip(val, 0.0, 100.0))

    @staticmethod
    def _normalize_source_diversity(div_count: int) -> float:
        """
        Normalizes source diversity count.
        1 source = 25, 2 sources = 50, 3 sources = 75, 4+ sources = 100.
        """
        try:
            div_count = float(div_count)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if not math.isfinite(div_count) or div_count <= 0:
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
        try:
            exploit_ratio = float(exploit_ratio)
        except (TypeError, ValueError, OverflowError):
            exploit_ratio = 0.0
        if not math.isfinite(exploit_ratio):
            exploit_ratio = 0.0
        val = 70.0 + (30.0 * np.clip(exploit_ratio, 0.0, 1.0))
        return float(np.clip(val, 70.0, 100.0))

    # ------------------------------------------------------------------ #
    # Stage Mapping
    # ------------------------------------------------------------------ #

    def _map_emergence_stage(self, score: float) -> str:
        """Map a continuous 0-100 score using configured upper cutoffs.

        Treat each configured ``max`` as an inclusive cutoff. This removes
        fractional gaps created by integer-style min/max ranges (for example
        25 < score < 26) while preserving the configured stage thresholds.
        """
        for stage, bounds in self.stages_cfg.items():
            if score <= bounds["max"]:
                return stage.capitalize()
        return next(reversed(self.stages_cfg)).capitalize()

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
        if growth is None:
            reasons.append("**Growth Rate Unavailable**: No dated reports fell within the two comparison windows; the growth sub-score is set to 0.")
        elif growth > 50:
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
                f"**Multiple Labeled Sources**: Reports appear under {div} distinct source labels ({sources}); source independence has not been verified."
            )
        elif div > 1:
            reasons.append(
                f"**Multiple Labeled Sources**: Reported under {div} source labels ({sources}); independence has not been verified."
            )
        elif div == 1:
            reasons.append(
                f"**Single-Source Detection**: Activity currently confined to 1 source."
            )
        else:
            reasons.append("**No Labeled Sources**: No eligible source labels were available for this query.")

        # Exploit Availability reasoning
        has_exp = features.get("exploit_availability", False)
        exp_cnt = features.get("exploit_count", 0)
        evidence_level = features.get("exploit_evidence_level", "legacy_unspecified")
        if has_exp:
            reasons.append(
                f"**Exploit-Related Evidence**: {exp_cnt} reports matched; highest evidence tier is '{evidence_level}' (+{sub_scores['exploit_availability']:.0f} sub-score). A mention alone does not establish verified code or in-wild exploitation."
            )
        else:
            reasons.append(
                "**No Exploit-Related Evidence Observed**: No matching exploit or PoC references were found in collected records; this is not proof that none exist."
            )

        return reasons
