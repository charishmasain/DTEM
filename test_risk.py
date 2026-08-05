"""
test_risk.py
~~~~~~~~~~~~

Verification script for Module 4: Risk Assessment Engine.

Tests:
  - End-to-end pipeline: Extractor -> DTEM Scoring Engine -> Risk Assessment
  - Risk Score calculation
  - Risk Level classification (Low, Medium, High, Critical)
  - Threat Priority assignment (P1 to P5)
  - Early Warning message generation
  - Recommended countermeasures

Run:
    python test_risk.py
"""

import json
import logging
import sys
import io
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.risk.assessment import RiskAssessmentEngine
from dtem.data.seed_data import seed_database

logging.basicConfig(level=logging.INFO)


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_risk_assessment() -> None:
    separator("DTEM Module 4 -- Risk Assessment Test Suite")

    seed_database(force=False)

    extractor = ThreatInfoExtractor(recent_window_days=14)
    scoring_engine = DTEMScoringEngine()
    risk_engine = RiskAssessmentEngine()

    test_keywords = ["lockbit", "blacklock", "cve-2025-12345", "apt29", "scattered spider"]

    for kw in test_keywords:
        print(f"\n---> Assessing Risk for: '{kw}'")
        features = extractor.extract_features(kw, auto_collect=True)
        emergence = scoring_engine.calculate_emergence(features)
        risk_result = risk_engine.assess_risk(emergence)

        print(f"  Emergence Score : {risk_result['emergence_score']} ({risk_result['emergence_stage']})")
        print(f"  Severity Score  : {risk_result['severity_score']} ({risk_result['severity_label']})")
        print(f"  Composite Risk  : {risk_result['risk_score']} / 100")
        print(f"  Risk Level      : [{risk_result['risk_level'].upper()}]")
        print(f"  Threat Priority : {risk_result['threat_priority']}")
        print(f"\n  Early Warning Message:\n  {risk_result['early_warning_message']}")
        print(f"\n  Recommendations:")
        for rec in risk_result['recommendations']:
            print(f"    - {rec}")

        # Assertions
        assert 0.0 <= risk_result['risk_score'] <= 100.0, f"Risk score out of bounds for {kw}"
        assert risk_result['risk_level'] in ["Low", "Medium", "High", "Critical"], f"Invalid risk level for {kw}"
        assert "P" in risk_result['threat_priority'], f"Invalid priority for {kw}"

    separator("ALL MODULE 4 TESTS PASSED")
    print("  Risk Assessment Engine is verified successfully.\n")


if __name__ == "__main__":
    test_risk_assessment()
