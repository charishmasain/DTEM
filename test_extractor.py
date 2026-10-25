"""
test_extractor.py
~~~~~~~~~~~~~~~~~

Verification script for Module 2: Threat Information Extractor.

Tests indicator calculations for:
  - lockbit
  - blacklock
  - cve-2025-12345
  - apt29
  - scattered spider

Run:
    python test_extractor.py
"""

import json
import logging
import sys
import io
from pathlib import Path

# Force UTF-8 stdout on Windows
if sys.platform == "win32" and __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from dtem.extractor.features import ThreatInfoExtractor
from dtem.data.seed_data import seed_database

logging.basicConfig(level=logging.INFO)


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_extraction() -> None:
    separator("DTEM Module 2 -- Indicator Extraction Test Suite")

    # Ensure DB is seeded
    seed_database(force=False)

    extractor = ThreatInfoExtractor(recent_window_days=14)
    test_keywords = ["lockbit", "blacklock", "cve-2025-12345", "apt29", "scattered spider"]

    for kw in test_keywords:
        print(f"\n---> Extracting indicators for: '{kw}'")
        features = extractor.extract_features(kw, auto_collect=True)

        print(f"  Detection Frequency : {features['detection_frequency']} reports")
        print(f"  Growth Rate         : {features['growth_rate']}% ({features['growth_trend'].upper()})")
        print(f"  Source Diversity    : {features['source_diversity']} sources -> {features['sources_list']}")
        print(f"  Exploit Availability: {features['exploit_availability']} ({features['exploit_count']} exploit mentions)")
        print(f"  Breakdown           : {features['breakdown']}")

        # Assertions
        assert features["detection_frequency"] > 0, f"Frequency must be > 0 for {kw}"
        assert features["source_diversity"] > 0, f"Diversity must be > 0 for {kw}"
        assert isinstance(features["exploit_availability"], bool), f"Exploit availability must be bool for {kw}"

    separator("ALL MODULE 2 TESTS PASSED")
    print("  Threat Information Extractor is verified successfully.\n")


if __name__ == "__main__":
    test_extraction()
