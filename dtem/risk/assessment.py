"""
dtem.risk.assessment
~~~~~~~~~~~~~~~~~~~~

Module 4: Risk Assessment & Early Warning Engine for DTEM.

Combines the DTEM Emergence Score with inherent technical severity
to compute:
  1. Severity Score (0-100)
  2. Composite Risk Score (0-100)
  3. Qualitative Risk Level (Low, Medium, High, Critical)
  4. Threat Priority (P1 Urgent to P5 Info)
  5. Actionable Early Warning Alert Message
  6. Recommended Countermeasures & Mitigation Guidelines
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

import numpy as np

from dtem.model.scoring import DTEMScoringEngine
from dtem.extractor.features import ThreatInfoExtractor

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


class RiskAssessmentEngine:
    """
    Assesses overall cyber risk by synthesizing DTEM Emergence Scores
    with technical severity information.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        cfg_path = config_path or _CONFIG_PATH
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh).get("risk_assessment", {})

        self.severity_weight: float = cfg.get("severity_weight", 0.40)
        self.emergence_weight: float = cfg.get("emergence_weight", 0.60)
        self.risk_levels_cfg: dict[str, dict[str, int]] = cfg.get("levels", {
            "low": {"min": 0, "max": 25},
            "medium": {"min": 26, "max": 50},
            "high": {"min": 51, "max": 75},
            "critical": {"min": 76, "max": 100},
        })

    def assess_risk(self, emergence_result: dict[str, Any]) -> dict[str, Any]:
        """
        Calculates composite risk score, threat priority, and generates an early warning.

        Args:
            emergence_result: Output dict from DTEMScoringEngine.calculate_emergence().

        Returns:
            Dictionary containing complete risk analysis and early warning advisory.
        """
        keyword = emergence_result.get("keyword", "")
        emergence_score = emergence_result.get("emergence_score", 0.0)
        emergence_stage = emergence_result.get("emergence_stage", "Dormant")
        extracted = emergence_result.get("extracted_features", {})

        # 1. Calculate Technical Severity Score (0-100)
        severity_score, severity_label = self._calculate_severity_score(extracted)

        # 2. Compute Composite Risk Score (0-100)
        composite_risk = (
            self.emergence_weight * emergence_score +
            self.severity_weight * severity_score
        )
        composite_risk = float(np.clip(composite_risk, 0.0, 100.0))
        composite_risk = round(composite_risk, 2)

        # 3. Determine Qualitative Risk Level
        risk_level = self._map_risk_level(composite_risk)

        # 4. Assign Threat Priority (P1 to P5)
        threat_priority = self._determine_threat_priority(composite_risk, emergence_stage, risk_level)

        # 5. Generate Early Warning Advisory Message
        early_warning = self._generate_early_warning(
            keyword, composite_risk, risk_level, threat_priority, emergence_stage, extracted
        )

        # 6. Generate Recommendations
        recommendations = self._generate_recommendations(
            keyword, risk_level, threat_priority, extracted.get("exploit_availability", False)
        )

        return {
            "keyword": keyword,
            "risk_score": composite_risk,
            "risk_level": risk_level,
            "threat_priority": threat_priority,
            "severity_score": severity_score,
            "severity_label": severity_label,
            "emergence_score": emergence_score,
            "emergence_stage": emergence_stage,
            "early_warning_message": early_warning,
            "recommendations": recommendations,
            "emergence_details": emergence_result,
        }

    # ------------------------------------------------------------------ #
    # Technical Severity Calculation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _calculate_severity_score(extracted: dict[str, Any]) -> tuple[float, str]:
        """
        Extracts technical severity across collected records.
        Returns (numeric_score_0_100, qualitative_label).
        """
        # If exploit availability is true and frequency high, baseline severity is elevated
        has_exploit = extracted.get("exploit_availability", False)

        # Default heuristic score if explicit labels missing
        base_score = 60.0 if has_exploit else 40.0

        # We can also check breakdown exploit ratio
        exploit_ratio = extracted.get("breakdown", {}).get("exploit_ratio", 0.0)
        if exploit_ratio > 0.5:
            base_score = max(base_score, 85.0)

        # Map to label
        if base_score >= 75:
            label = "Critical"
        elif base_score >= 50:
            label = "High"
        elif base_score >= 25:
            label = "Medium"
        else:
            label = "Low"

        return round(base_score, 2), label

    # ------------------------------------------------------------------ #
    # Risk Level Mapping
    # ------------------------------------------------------------------ #

    def _map_risk_level(self, risk_score: float) -> str:
        """Map numeric risk score (0-100) to Low, Medium, High, Critical."""
        for level, bounds in self.risk_levels_cfg.items():
            if bounds["min"] <= risk_score <= bounds["max"]:
                return level.capitalize()

        if risk_score > 100:
            return "Critical"
        return "Low"

    # ------------------------------------------------------------------ #
    # Threat Priority Assignment
    # ------------------------------------------------------------------ #

    @staticmethod
    def _determine_threat_priority(
        risk_score: float, emergence_stage: str, risk_level: str
    ) -> str:
        """
        Assigns priority levels:
            P1 - Urgent (Immediate containment required)
            P2 - High (Action within 24 hours)
            P3 - Moderate (Enhanced monitoring)
            P4 - Low (Routine surveillance)
            P5 - Info (No immediate risk)
        """
        if risk_score >= 80 or (risk_level == "Critical" and emergence_stage in ["Escalating", "Emerging"]):
            return "P1 - Urgent"
        elif risk_score >= 65:
            return "P2 - High"
        elif risk_score >= 45:
            return "P3 - Moderate"
        elif risk_score >= 25:
            return "P4 - Low"
        else:
            return "P5 - Info"

    # ------------------------------------------------------------------ #
    # Early Warning Advisory Generator
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_early_warning(
        keyword: str,
        risk_score: float,
        risk_level: str,
        priority: str,
        stage: str,
        extracted: dict[str, Any],
    ) -> str:
        """Generates a structured natural-language early warning alert."""
        freq = extracted.get("detection_frequency", 0)
        growth = extracted.get("growth_rate", 0.0)
        sources = extracted.get("source_diversity", 0)
        has_exploit = extracted.get("exploit_availability", False)

        header = f"⚠️ DTEM EARLY WARNING ALERT [{priority.upper()}] — {keyword.upper()}"

        if risk_level == "Critical" or stage == "Escalating":
            body = (
                f"{header}\n"
                f"Threat '{keyword}' has reached an ESCALATING emergence trajectory with a Critical Risk Score of {risk_score}/100. "
                f"Dark web discussions and public CTI feeds indicate high velocity growth (+{growth:.1f}%) across {sources} independent sources. "
                f"{'ACTIVE EXPLOIT MATERIAL IS PUBLICLY AVAILABLE.' if has_exploit else 'No public exploit code verified yet.'} "
                f"Immediate defensive intervention is recommended."
            )
        elif risk_level == "High" or stage == "Emerging":
            body = (
                f"{header}\n"
                f"Threat '{keyword}' displays significant growth ({stage} stage, Risk Score: {risk_score}/100). "
                f"Monitored across {sources} sources with {freq} detection events. "
                f"{'Exploit discussions detected on dark web forums.' if has_exploit else 'Exploit status: inactive.'} "
                f"Heightened surveillance and proactive patching recommended."
            )
        else:
            body = (
                f"ℹ️ DTEM ADVISORY [{priority}] — {keyword.upper()}\n"
                f"Threat '{keyword}' is currently classified as {stage} (Risk Score: {risk_score}/100). "
                f"Normal monitoring protocols apply."
            )

        return body

    # ------------------------------------------------------------------ #
    # Recommendation Generator
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_recommendations(
        keyword: str, risk_level: str, priority: str, has_exploit: bool
    ) -> list[str]:
        """Generates actionable mitigation and response guidelines."""
        recs = []

        if "P1" in priority or risk_level == "Critical":
            recs.append(f"Execute emergency threat hunt for IOCs related to '{keyword}'.")
            if has_exploit:
                recs.append("Prioritize zero-day / critical patch deployment for affected infrastructure immediately.")
            recs.append("Block known C2 IP addresses and malicious domains at perimeter firewalls and EDR filters.")
            recs.append("Alert SOC team and initiate P1 Incident Response protocol.")
        elif "P2" in priority or risk_level == "High":
            recs.append(f"Audit internal assets for exposure to '{keyword}'.")
            if has_exploit:
                recs.append("Apply vendor security updates within 24-48 hours.")
            recs.append("Enhance dark web and telegram channel monitoring for credential/access sales.")
        else:
            recs.append(f"Maintain routine threat intelligence logging for '{keyword}'.")
            recs.append("Verify endpoint detection signatures are up to date.")

        return recs
