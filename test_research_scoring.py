"""Regression checks for the scoring and evidence hierarchy (project deps required)."""

import json
import math
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine


class GrowthAndScoringTests(unittest.TestCase):
    def setUp(self):
        self.extractor = ThreatInfoExtractor(recent_window_days=14)
        self.as_of = datetime(2026, 2, 1, tzinfo=timezone.utc)

    def test_smoothed_log_growth_empty_and_zero_windows(self):
        self.assertEqual(self.extractor.calculate_smoothed_log_growth([], self.as_of), (0.0, 0, 0))
        old = [{"published_at": "2025-12-01T00:00:00Z"}]
        growth, recent, previous = self.extractor.calculate_smoothed_log_growth(old, self.as_of)
        self.assertEqual((recent, previous), (0, 0))
        self.assertEqual(growth, 0.0)
        for invalid_alpha in (0, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                self.extractor.calculate_smoothed_log_growth([], self.as_of, alpha=invalid_alpha)

    def test_smoothed_log_growth_zero_prior_negative_and_extreme(self):
        records = [
            {"published_at": "2026-01-31T00:00:00Z"},
            {"published_at": "2026-01-30T00:00:00Z"},
            {"published_at": "2026-01-10T00:00:00Z"},
            {"published_at": "2026-01-09T00:00:00Z"},
        ]
        growth, recent, previous = self.extractor.calculate_smoothed_log_growth(records, self.as_of)
        self.assertEqual((recent, previous), (2, 2))
        self.assertEqual(growth, 0.0)
        falling = [{"published_at": "2026-01-10T00:00:00Z"}]
        decline, recent, previous = self.extractor.calculate_smoothed_log_growth(falling, self.as_of)
        self.assertEqual((recent, previous), (0, 1))
        self.assertLess(decline, 0)
        surge = [{"published_at": "2026-01-31T00:00:00Z"}] * 10000
        surge_growth, _, _ = self.extractor.calculate_smoothed_log_growth(surge, self.as_of)
        self.assertTrue(math.isfinite(surge_growth))

    def test_legacy_growth_zero_prior_and_decline_boundaries(self):
        self.assertEqual(self.extractor.calculate_growth_rate([]), (0.0, "stable", 0, 0))
        one_recent = [{"published_at": "2026-01-31T00:00:00Z"}]
        self.assertEqual(self.extractor.calculate_growth_rate(one_recent, self.as_of), (100.0, "surging", 1, 0))
        prior_only = [
            {"published_at": "2026-01-10T00:00:00Z"},
            {"published_at": "2026-01-09T00:00:00Z"},
        ]
        rate, trend, recent, previous = self.extractor.calculate_growth_rate(prior_only, self.as_of)
        self.assertEqual((rate, trend, recent, previous), (-100.0, "declining", 0, 2))

    def test_old_records_are_not_treated_as_recent_growth_in_live_features(self):
        from unittest.mock import patch

        records = [{
            "source": "OTX", "title": "CVE-2021-44228 log4j reference",
            "content": "Historical reference", "published_at": "2021-12-10T00:00:00Z",
        }]
        with patch("dtem.extractor.features.fetch_intel_for_keyword", return_value=records):
            features = self.extractor.extract_features("CVE-2021-44228", auto_collect=False,
                                                       include_prototype=False)
        self.assertEqual(features["total_records"], 1)
        self.assertIsNone(features["growth_rate"])
        self.assertFalse(features["growth_data_available"])

    def test_growth_window_edges_and_future_records(self):
        records = [
            {"published_at": "2026-01-18T00:00:00Z"},  # recent window start, included
            {"published_at": "2026-01-04T00:00:00Z"},  # previous window start, included
            {"published_at": "2026-02-01T00:00:00Z"},  # as_of, included by legacy formula
            {"published_at": "2026-02-01T00:00:01Z"},  # after as_of, excluded
        ]
        rate, _, recent, previous = self.extractor.calculate_growth_rate(records, self.as_of)
        self.assertEqual((recent, previous), (2, 1))
        self.assertEqual(rate, 100.0)

    def test_growth_normalization_boundaries(self):
        normalize = DTEMScoringEngine._normalize_growth_rate
        self.assertEqual(normalize(-100), 0)
        self.assertEqual(normalize(-101), 0)
        self.assertEqual(normalize(0), 35)
        self.assertAlmostEqual(normalize(150), 90)
        self.assertEqual(normalize(100000), 100)
        self.assertEqual(normalize(float("inf")), 100)
        self.assertEqual(normalize(float("-inf")), 0)
        self.assertAlmostEqual(normalize(-50), 17.5)
        self.assertEqual(normalize(float("nan")), 0)

    def test_non_finite_frequency_and_diversity_are_safe(self):
        self.assertEqual(DTEMScoringEngine._normalize_frequency(float("nan")), 0)
        self.assertEqual(DTEMScoringEngine._normalize_frequency(float("inf")), 0)
        self.assertEqual(DTEMScoringEngine._normalize_frequency(-1), 0)
        self.assertEqual(DTEMScoringEngine._normalize_source_diversity(float("nan")), 0)
        self.assertEqual(DTEMScoringEngine._normalize_source_diversity(float("inf")), 0)

    def test_empty_evidence_is_not_reported_as_a_scored_zero_growth_case(self):
        from dtem.risk.assessment import RiskAssessmentEngine

        features = ThreatInfoExtractor._empty_features("CVE-2026-12345")
        emergence = DTEMScoringEngine().calculate_emergence(features)
        risk = RiskAssessmentEngine().assess_risk(emergence)
        self.assertEqual(emergence["score_status"], "insufficient_data")
        self.assertEqual(emergence["emergence_stage"], "Unavailable")
        self.assertIsNone(emergence["emergence_score"])
        self.assertTrue(all(value == 0 for value in emergence["sub_scores"].values()))
        self.assertIsNone(risk["risk_score"])
        self.assertEqual(risk["risk_level"], "Unavailable")
        self.assertEqual(risk["assessment_status"], "insufficient_data")
        self.assertTrue(any("No eligible CTI evidence" in item for item in emergence["explainable_reasoning"]))

    def test_lifecycle_stages_have_no_decimal_gaps(self):
        engine = DTEMScoringEngine()
        self.assertEqual(engine._map_emergence_stage(25), "Dormant")
        self.assertEqual(engine._map_emergence_stage(25.01), "Growing")
        self.assertEqual(engine._map_emergence_stage(50.5), "Emerging")
        self.assertEqual(engine._map_emergence_stage(75.5), "Escalating")
        self.assertEqual(engine._map_emergence_stage(100), "Escalating")
        from dtem.risk.assessment import RiskAssessmentEngine
        risk = RiskAssessmentEngine()
        self.assertEqual(risk._map_risk_level(25.5), "Medium")
        self.assertEqual(risk._map_risk_level(50.5), "High")
        self.assertEqual(risk._map_risk_level(75.5), "Critical")

    def test_timeline_uses_main_exploit_evidence_score(self):
        from dtem.evaluation.backtester import _compute_timeline

        record = {
            "source": "NVD", "title": "Generic exploit discussion",
            "published_at": "2026-01-31T00:00:00Z", "exploit_mentioned": 1,
        }
        timeline = _compute_timeline([record], self.as_of)
        timeline_score = timeline[-1]["dtem"]
        main_score = DTEMScoringEngine().calculate_emergence({
            "keyword": "CVE-2026-1234", "detection_frequency": 1,
            "growth_rate": 100.0, "source_diversity": 1,
            "exploit_availability": True, "exploit_evidence_score": 25.0,
            "breakdown": {"exploit_ratio": 1.0},
        })["emergence_score"]
        self.assertEqual(timeline_score, main_score)

    def test_empty_timeline_windows_are_missing_not_zero_score(self):
        from dtem.evaluation.backtester import _compute_timeline

        timeline = _compute_timeline([], self.as_of)
        self.assertTrue(all(row["dtem"] is None for row in timeline))

    def test_duplicate_records_do_not_inflate_frequency(self):
        record = {"source": "NVD", "title": "same item", "url": "https://example.invalid/1",
                  "published_at": "2026-01-01T00:00:00Z"}
        self.assertEqual(ThreatInfoExtractor.calculate_detection_frequency([record, dict(record)]), 1)

    def test_source_label_whitespace_and_case_do_not_inflate_diversity(self):
        count, labels = ThreatInfoExtractor.calculate_source_diversity([
            {"source": "NVD"}, {"source": " nvd "}, {"source": "OTX"}, {"source": ""}
        ])
        self.assertEqual(count, 2)
        self.assertEqual(labels, ["NVD", "OTX"])

    def test_exploit_hierarchy_and_negative_context(self):
        classify = ThreatInfoExtractor.classify_exploit_evidence
        self.assertEqual(classify([{"title": "exploit mention"}]), ("generic_mention", 25.0))
        self.assertEqual(classify([{"title": "PoC reference available"}]), ("poc_reference", 50.0))
        self.assertEqual(classify([{"title": "working exploit code"}]), ("verified_exploit", 75.0))
        self.assertEqual(classify([{"title": "actively exploited in the wild"}]), ("in_wild", 100.0))
        self.assertEqual(classify([{"title": "pocket guide", "exploit_mentioned": 0}]), ("none", 0.0))
        self.assertEqual(classify([{"title": "not exploited in the wild"}]), ("none", 0.0))

    def test_cvss_is_only_numeric_for_cves(self):
        from dtem.risk.assessment import RiskAssessmentEngine
        self.assertEqual(RiskAssessmentEngine._calculate_severity_score(
            {"keyword": "CVE-2026-1234", "cvss_base_score": 8.8}), (88.0, "Critical"))
        self.assertEqual(RiskAssessmentEngine._calculate_severity_score(
            {"keyword": "apt29", "cvss_base_score": 8.8}), (None, "Not applicable"))

    def test_nvd_related_cve_mention_does_not_match_or_supply_target_cvss(self):
        related = {
            "source": "NVD", "title": "CVE-2021-9999: Related package fix",
            "content": "This addresses CVE-2021-44228.", "severity": "CVSS (8.1)",
            "raw_data": {"cve": {"id": "CVE-2021-9999"}},
        }
        target = {
            "source": "NVD", "title": "CVE-2021-44228: Remote code execution",
            "content": "Target record.", "severity": "CVSS (10.0)",
            "raw_data": {"cve": {"id": "CVE-2021-44228"}},
        }
        self.assertFalse(ThreatInfoExtractor._record_mentions_cve(related, "CVE-2021-44228"))
        self.assertTrue(ThreatInfoExtractor._record_mentions_cve(target, "CVE-2021-44228"))
        self.assertEqual(ThreatInfoExtractor._extract_cvss_base_score([target]), 10.0)

    def test_weights_must_sum_to_one(self):
        source = Path(__file__).parent / "dtem" / "config.json"
        config = json.loads(source.read_text(encoding="utf-8"))
        config["emergence_model"]["weights"]["growth_rate"] = 0.31
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "invalid.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(ValueError):
                DTEMScoringEngine(config_path=path)


if __name__ == "__main__":
    unittest.main()
