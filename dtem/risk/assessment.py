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
        if (isinstance(self.severity_weight, bool) or isinstance(self.emergence_weight, bool)
                or not isinstance(self.severity_weight, (int, float))
                or not isinstance(self.emergence_weight, (int, float))
                or not np.isfinite(self.severity_weight) or not np.isfinite(self.emergence_weight)
                or self.severity_weight < 0 or self.emergence_weight < 0
                or not np.isclose(self.severity_weight + self.emergence_weight, 1.0)):
            raise ValueError("risk weights must be finite, non-negative, and sum to 1")
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

        if emergence_result.get("score_status") == "insufficient_data":
            return {
                "keyword": keyword,
                "risk_score": None,
                "risk_level": "Unavailable",
                "threat_priority": "Not assessed",
                "severity_score": severity_score,
                "severity_label": severity_label,
                "severity_basis": "CVSS" if severity_score is not None else "unavailable",
                "emergence_score": None,
                "emergence_stage": "Unavailable",
                "assessment_status": "insufficient_data",
                "early_warning_message": (
                    f"No eligible evidence was found for '{keyword}'. No emergence or risk estimate can be assessed."
                ),
                "recommendations": [
                    "Verify the identifier and data-source availability, then run the analysis again."
                ],
                "emergence_details": emergence_result,
            }

        # 2. Compute Composite Risk Score (0-100)
        if severity_score is None:
            # Missing CVSS is not interpreted as zero severity. For the
            # prototype API, report emergence alone when CVSS is unavailable.
            composite_risk = emergence_score
        else:
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
            keyword, risk_level, threat_priority, extracted.get("exploit_availability", False),
            extracted.get("exploit_evidence_level", "none"), extracted.get("cvss_base_score"),
        )

        return {
            "keyword": keyword,
            "risk_score": composite_risk,
            "risk_level": risk_level,
            "threat_priority": threat_priority,
            "severity_score": severity_score,
            "severity_label": severity_label,
            "severity_basis": "CVSS" if severity_score is not None else "unavailable",
            "emergence_score": emergence_score,
            "emergence_stage": emergence_stage,
            "assessment_status": "scored",
            "early_warning_message": early_warning,
            "recommendations": recommendations,
            "emergence_details": emergence_result,
        }

    # ------------------------------------------------------------------ #
    # Technical Severity Calculation
    # ------------------------------------------------------------------ #

    @staticmethod
    def _calculate_severity_score(extracted: dict[str, Any]) -> tuple[Optional[float], str]:
        """
        Extracts technical severity across collected records.
        Returns (numeric_score_0_100, qualitative_label).
        """
        keyword = extracted.get("keyword", "")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(keyword).strip(), re.IGNORECASE):
            return None, "Not applicable"
        cvss = extracted.get("cvss_base_score")
        base_score = float(cvss) * 10 if cvss is not None and 0 <= float(cvss) <= 10 else None
        if base_score is None:
            return None, "Unavailable"

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
        """Map a continuous 0-100 score using configured inclusive cutoffs."""
        for level, bounds in self.risk_levels_cfg.items():
            if risk_score <= bounds["max"]:
                return level.capitalize()
        return next(reversed(self.risk_levels_cfg)).capitalize()

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
        growth = extracted.get("growth_rate")
        growth_text = f"{growth:+.1f}%" if growth is not None else "unavailable"
        sources = extracted.get("source_diversity", 0)
        has_exploit = extracted.get("exploit_availability", False)
        exploit_level = extracted.get("exploit_evidence_level", "legacy_unspecified")
        evidence_text = (
            f"Exploit-related evidence tier: {exploit_level}; mentions alone do not verify code or exploitation in the wild."
            if has_exploit else
            "No exploit-related evidence was observed in collected records; absence here does not prove none exists."
        )

        header = f"⚠️ DTEM EARLY WARNING ALERT [{priority.upper()}] — {keyword.upper()}"

        if risk_level == "Critical" or stage == "Escalating":
            body = (
                f"{header}\n"
                f"Threat '{keyword}' has reached an ESCALATING emergence trajectory with a Critical Risk Score of {risk_score}/100. "
                f"Collected CTI reports indicate growth {growth_text} across {sources} labeled sources. "
                f"{evidence_text} "
                f"Immediate defensive intervention is recommended."
            )
        elif risk_level == "High" or stage == "Emerging":
            body = (
                f"{header}\n"
                f"Threat '{keyword}' displays significant growth ({stage} stage, Risk Score: {risk_score}/100). "
                f"Monitored across {sources} sources with {freq} detection events. "
                f"{evidence_text} "
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
        keyword: str, risk_level: str, priority: str, has_exploit: bool,
        exploit_level: str = "none", cvss_base_score: Optional[float] = None,
    ) -> list[str]:
        """Return conservative actions supported by threat type and evidence."""
        recs = []
        is_cve = bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", keyword.strip(), re.IGNORECASE))
        if is_cve:
            recs.append(f"Check the affected product and version against authoritative vendor advisories for {keyword}.")
            if cvss_base_score is not None:
                recs.append(f"Use the available CVSS base score ({cvss_base_score}) as a severity input; confirm local exposure before prioritizing remediation.")
            if exploit_level == "in_wild":
                recs.append("An input record is heuristically classified as in-wild exploitation; verify its source, then assess exposure and incident telemetry promptly.")
            elif has_exploit:
                recs.append(f"Review the collected {exploit_level.replace('_', ' ')} reference; this rule-based label does not verify exploit functionality or active use.")
            else:
                recs.append("No exploit evidence was identified in collected records; continue vulnerability and vendor-advisory monitoring.")
        elif has_exploit:
            recs.append(f"Review collected exploit-related references for '{keyword}' and validate them with trusted incident-response sources.")
            recs.append("Use applicable detection telemetry and asset exposure to decide whether investigation is warranted.")
        else:
            recs.append(f"Review the cited public-source records for '{keyword}' and verify relevance to your environment.")
        if risk_level in {"High", "Critical"} or priority in {"P1 - Urgent", "P2 - High"}:
            recs.append("Prioritize analyst review based on this score together with local exposure and operational context.")
        else:
            recs.append("Continue routine monitoring; the score alone does not establish an active incident.")
        return recs
