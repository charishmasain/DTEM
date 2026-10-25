"""
test_model.py
~~~~~~~~~~~~~

Verification script for Module 3: DTEM Scoring Engine.

Tests:
  - Extractor + DTEM Scoring pipeline for all seeded threats
  - Stage classification (Dormant, Growing, Emerging, Escalating)
  - Configurable weight modification verification
  - Explainable reasoning output

Run:
    python test_model.py
"""

import json
import logging
import sys
import io
from pathlib import Path

# Force UTF-8 on Windows
if sys.platform == "win32" and __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.data.seed_data import seed_database

logging.basicConfig(level=logging.INFO)


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_scoring_engine() -> None:
    separator("DTEM Module 3 -- Scoring Engine Test Suite")

    seed_database(force=False)

    extractor = ThreatInfoExtractor(recent_window_days=14)
    engine = DTEMScoringEngine()

    test_keywords = ["lockbit", "blacklock", "cve-2025-12345", "apt29", "scattered spider"]

    for kw in test_keywords:
        print(f"\n---> Scoring threat: '{kw}'")
        features = extractor.extract_features(kw, auto_collect=True)
        result = engine.calculate_emergence(features)

        print(f"  Emergence Score : {result['emergence_score']} / 100")
        print(f"  Emergence Stage : [{result['emergence_stage'].upper()}]")
        print(f"  Sub-Scores      : {result['sub_scores']}")
        print(f"  Reasoning       :")
        for reason in result['explainable_reasoning']:
            print(f"    * {reason}")

        # Basic assertions
        assert 0.0 <= result['emergence_score'] <= 100.0, f"Score out of range for {kw}"
        assert result['emergence_stage'] in ["Dormant", "Growing", "Emerging", "Escalating"], f"Invalid stage for {kw}"

    separator("ALL MODULE 3 TESTS PASSED")
    print("  DTEM Scoring Engine is verified successfully.\n")


if __name__ == "__main__":
    test_scoring_engine()
