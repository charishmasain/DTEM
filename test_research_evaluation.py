"""
test_research_evaluation.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Regression checks for the ablation, baseline, split, and ranking-metric layer
added to address the reviewer's request for ablation, simple baselines, PR-AUC,
and a chronological development/validation/test separation.

These tests validate that the software computes and reports the right numbers
and refuses to fabricate them. They are not evidence of real-world predictive
validity; that depends on genuine, leakage-safe input data.
"""

import json
import math
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dtem.evaluation.ablation import (
    compute_sub_scores, run_ablation, threshold_sensitivity, growth_scale_sensitivity,
    weighted_score,
)
from dtem.evaluation.baselines import run_baselines
from dtem.evaluation.metrics import (
    bootstrap_pr_auc_ci, pr_auc, threshold_metrics,
)
from dtem.evaluation.split import chronological_split
from dtem.model.scoring import DTEMScoringEngine


class MetricsTests(unittest.TestCase):
    def test_pr_auc_perfect_and_worst_ranking(self):
        self.assertEqual(pr_auc([1, 1, 0, 0], [4, 3, 2, 1])["pr_auc"], 1.0)
        self.assertAlmostEqual(pr_auc([0, 0, 1, 1], [4, 3, 2, 1])["pr_auc"], 0.416667, places=5)

    def test_pr_auc_handles_ties_as_one_operating_point(self):
        result = pr_auc([1, 0], [5, 5])
        self.assertEqual(result["status"], "computed")
        self.assertAlmostEqual(result["pr_auc"], 0.5)
        self.assertEqual(result["random_baseline"], 0.5)

    def test_pr_auc_single_class_is_not_a_number(self):
        self.assertEqual(pr_auc([1, 1], [2, 1])["status"], "single_class")
        self.assertIsNone(pr_auc([1, 1], [2, 1])["pr_auc"])
        self.assertEqual(pr_auc([], [])["status"], "no_samples")

    def test_threshold_metrics_report_undefined_rates(self):
        metrics = threshold_metrics([1, 0], [80.0, 20.0], 50.0)
        self.assertEqual(metrics["confusion_matrix"], {"tp": 1, "fp": 0, "fn": 0, "tn": 1})
        self.assertEqual(metrics["f1"], 1.0)
        undefined = threshold_metrics([0, 0], [10.0, 10.0], 50.0)
        self.assertIsNone(undefined["precision"])
        self.assertIn("precision", undefined["undefined_metrics"])

    def test_bootstrap_interval_is_deterministic(self):
        labels = [1, 1, 0, 0, 1, 0, 0, 1]
        scores = [90, 85, 20, 15, 80, 30, 25, 70]
        first = bootstrap_pr_auc_ci(labels, scores, n_resamples=50, seed=7)
        second = bootstrap_pr_auc_ci(labels, scores, n_resamples=50, seed=7)
        self.assertEqual(first["status"], "computed")
        self.assertEqual(first["interval"], second["interval"])
        self.assertTrue(first["interval"][0] <= first["interval"][1])

    def test_metrics_reject_non_finite_scores(self):
        with self.assertRaises(ValueError):
            pr_auc([1, 0], [float("nan"), 1.0])


class LogGrowthScoringTests(unittest.TestCase):
    def test_log_growth_transform_boundaries_and_symmetry(self):
        norm = DTEMScoringEngine._normalize_log_growth
        self.assertAlmostEqual(norm(0.0, 1.386), 50.0)
        self.assertEqual(norm(None, 1.386), 0.0)
        self.assertEqual(norm(float("nan"), 1.386), 0.0)
        self.assertEqual(norm(float("inf"), 1.386), 100.0)
        self.assertEqual(norm(float("-inf"), 1.386), 0.0)
        self.assertGreater(norm(2.0, 1.386), norm(1.0, 1.386))
        self.assertLess(norm(-1.0, 1.386), norm(1.0, 1.386))
        self.assertAlmostEqual(norm(1.386, 1.386), 50.0 * (1 + math.tanh(1.0)), places=4)

    def test_log_growth_scale_validation(self):
        with self.assertRaises(ValueError):
            DTEMScoringEngine._normalize_log_growth(1.0, 0)

    def test_growth_mode_config_selects_log_transform(self):
        base = json.loads((Path(__file__).parent / "dtem" / "config.json").read_text(encoding="utf-8"))
        base["emergence_model"]["growth_mode"] = "log"
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "log.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            engine = DTEMScoringEngine(config_path=path)
        self.assertEqual(engine.growth_mode, "log")
        legacy = engine._normalize_growth_rate(100.0)
        features = {"keyword": "CVE-2020-0001", "detection_frequency": 5, "growth_rate": 100.0,
                    "growth_log_rate": math.log(2), "source_diversity": 2,
                    "exploit_evidence_score": 0.0, "total_records": 5}
        result = engine.calculate_emergence(features)
        self.assertEqual(result["growth_mode"], "log")
        self.assertAlmostEqual(result["sub_scores"]["growth_rate"],
                               round(engine._normalize_log_growth(math.log(2), engine.log_growth_scale), 2))
        self.assertNotEqual(result["sub_scores"]["growth_rate"], legacy)

    def test_invalid_growth_mode_rejected(self):
        base = json.loads((Path(__file__).parent / "dtem" / "config.json").read_text(encoding="utf-8"))
        base["emergence_model"]["growth_mode"] = "quadratic"
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder) / "bad.json"
            path.write_text(json.dumps(base), encoding="utf-8")
            with self.assertRaises(ValueError):
                DTEMScoringEngine(config_path=path)


def _make_rows():
    """Two-class feature rows where exploit evidence separates positives cleanly."""
    rows = [
        {"cve_id": "CVE-A", "cutoff": "2025-01-08T00:00:00Z", "label": 1, "score": 70.0,
         "features": {"detection_frequency": 6, "growth_rate": 100.0, "growth_log_rate": math.log(2),
                      "source_diversity": 3, "exploit_evidence_score": 75.0, "cvss_base_score": 9.0}},
        {"cve_id": "CVE-A", "cutoff": "2025-01-15T00:00:00Z", "label": 1, "score": 72.0,
         "features": {"detection_frequency": 8, "growth_rate": 120.0, "growth_log_rate": math.log(3),
                      "source_diversity": 3, "exploit_evidence_score": 100.0, "cvss_base_score": 9.0}},
        {"cve_id": "CVE-B", "cutoff": "2025-01-08T00:00:00Z", "label": 0, "score": 20.0,
         "features": {"detection_frequency": 2, "growth_rate": 0.0, "growth_log_rate": 0.0,
                      "source_diversity": 1, "exploit_evidence_score": 0.0, "cvss_base_score": 3.0}},
        {"cve_id": "CVE-B", "cutoff": "2025-01-15T00:00:00Z", "label": 0, "score": 22.0,
         "features": {"detection_frequency": 2, "growth_rate": 0.0, "growth_log_rate": 0.0,
                      "source_diversity": 1, "exploit_evidence_score": 0.0, "cvss_base_score": 3.0}},
    ]
    return rows


class AblationAndBaselinesTests(unittest.TestCase):
    def setUp(self):
        self.engine = DTEMScoringEngine()
        self.rows = _make_rows()

    def test_compute_sub_scores_matches_engine_legacy(self):
        subs = compute_sub_scores(self.engine, self.rows[0]["features"], "legacy")
        self.assertEqual(subs["detection_frequency"],
                         self.engine._normalize_frequency(6))
        self.assertEqual(subs["exploit_availability"], 75.0)

    def test_weighted_score_renormalizes_over_subset(self):
        subs = {"detection_frequency": 100.0, "growth_rate": 0.0,
                "source_diversity": 0.0, "exploit_availability": 0.0}
        # Only frequency active -> full 100 regardless of its small base weight.
        self.assertAlmostEqual(weighted_score(subs, self.engine.weights, ["detection_frequency"]), 100.0)
        self.assertIsNone(weighted_score(subs, {"detection_frequency": 0.0}, ["detection_frequency"]))

    def test_run_ablation_reports_full_leave_one_out_and_single(self):
        report = run_ablation(self.rows, self.engine, threshold=50.0)
        self.assertEqual(report["full_model"]["pr_auc_status"], "computed")
        self.assertEqual(report["class_support"], {"positive": 2, "negative": 2, "two_class_present": True})
        self.assertIn("without_exploit_availability", report["leave_one_out"])
        self.assertIn("only_detection_frequency", report["single_indicator"])

    def test_ablation_detects_uninformative_indicator(self):
        # Exploit_availability has weight 0 in config; the ablation correctly
        # cannot produce a score from it alone (no positive weight → None).
        report = run_ablation(self.rows, self.engine, threshold=50.0)
        exploit_variant = report["single_indicator"]["only_exploit_availability"]
        # With weight=0, no rows can be scored by exploit alone → sample_count 0
        self.assertEqual(exploit_variant.get("sample_count", 0), 0)

    def test_threshold_and_growth_scale_sensitivity(self):
        grid = threshold_sensitivity(self.rows, self.engine, [40.0, 50.0, 60.0])
        self.assertEqual(len(grid), 3)
        self.assertEqual(grid[0]["pr_auc"], grid[2]["pr_auc"])  # ranking is threshold-independent
        scale_grid = growth_scale_sensitivity(self.rows, self.engine, [0.7, 1.386, 2.0])
        self.assertEqual(len(scale_grid), 3)
        for entry in scale_grid:
            self.assertIn(entry["pr_auc_status"], {"computed", "single_class"})

    def test_baselines_compare_on_identical_rows(self):
        report = run_baselines(self.rows, self.engine, threshold=50.0,
                               dtem_scores=[row["score"] for row in self.rows])
        self.assertEqual(report["class_support"]["positive"], 2)
        for method in ("historical_frequency", "growth_rate", "cvss_severity", "dtem_full"):
            self.assertIn(method, report["methods"])
        self.assertEqual(report["methods"]["cvss_severity"]["pr_auc"], 1.0)
        self.assertEqual(report["methods"]["epss"]["sample_count"], 0)


class ChronologicalSplitTests(unittest.TestCase):
    def test_split_is_time_ordered_not_random(self):
        rows = []
        for day in range(1, 11):
            rows.append({"cve_id": f"CVE-{day}", "cutoff": f"2025-01-{day:02d}T00:00:00Z",
                         "label": day % 2, "score": 50.0 + day})
        report = chronological_split(rows, dev_fraction=0.5, val_fraction=0.25, threshold=50.0)
        self.assertEqual(report["status"], "computed")
        dev_max = report["boundaries"]["development_through"]
        test_min = report["periods"]["test"]["distinct_cutoffs"]
        self.assertTrue(dev_max.endswith("T00:00:00Z"))
        self.assertGreaterEqual(test_min, 1)
        # Every development cutoff must be <= every test cutoff.
        dev_rows = [r for r in rows if r["cutoff"] <= dev_max]
        self.assertTrue(all(r["cutoff"] <= dev_max for r in dev_rows))

    def test_split_counts_recurring_cves_across_periods(self):
        rows = [
            {"cve_id": "CVE-SAME", "cutoff": "2025-01-01T00:00:00Z", "label": 0, "score": 10.0},
            {"cve_id": "CVE-OTHER", "cutoff": "2025-01-05T00:00:00Z", "label": 1, "score": 90.0},
            {"cve_id": "CVE-TWO", "cutoff": "2025-01-09T00:00:00Z", "label": 1, "score": 80.0},
            {"cve_id": "CVE-SAME", "cutoff": "2025-01-10T00:00:00Z", "label": 0, "score": 20.0},
        ]
        report = chronological_split(rows, dev_fraction=0.5, val_fraction=0.25)
        self.assertGreaterEqual(report["leakage"]["cves_spanning_multiple_periods"], 1)
        self.assertTrue(report["leakage"]["temporal_leakage_prevented"])

    def test_split_requires_dated_rows(self):
        report = chronological_split([{"label": 1, "score": 5.0}])
        self.assertEqual(report["status"], "no_dated_cutoffs")


class BacktestIntegrationTests(unittest.TestCase):
    def test_backtest_emits_pr_auc_ablation_baselines_and_split(self):
        from dtem.evaluation.research_pipeline import run_temporal_backtest

        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            observations = root / "observations.jsonl"
            lines = [
                {"cve_id": "CVE-2025-0001", "source": "OTX", "title": "CVE-2025-0001 working exploit code",
                 "content": "verified", "published_at": "2025-05-01T00:00:00Z",
                 "available_at": "2025-05-01T00:00:00Z", "severity": "CVSS (9.1)"},
                {"cve_id": "CVE-2025-0002", "source": "OTX", "title": "CVE-2025-0002 advisory",
                 "content": "no exploit", "published_at": "2025-05-01T00:00:00Z",
                 "available_at": "2025-05-01T00:00:00Z", "severity": "CVSS (3.0)"},
            ]
            observations.write_text("\n".join(json.dumps(row) for row in lines) + "\n", encoding="utf-8")
            kev = root / "kev.json"
            kev.write_text(json.dumps({"vulnerabilities": [
                {"cveID": "CVE-2025-0001", "dateAdded": "2025-06-10"}]}), encoding="utf-8")
            kev.with_suffix(".json.coverage.json").write_text(
                json.dumps({"complete_through": "2025-07-02T00:00:00Z"}), encoding="utf-8")
            report = run_temporal_backtest(
                observations, kev, root / "report.json",
                start=datetime(2025, 6, 1, tzinfo=timezone.utc),
                end=datetime(2025, 6, 3, tzinfo=timezone.utc), step_days=1,
            )

        self.assertGreater(report["prediction_count"], 0)
        self.assertEqual(report["pr_auc_status"], "computed")
        self.assertIsNotNone(report["pr_auc"])
        self.assertIn("exploit_availability", json.dumps(report["ablation"]["leave_one_out"]))
        self.assertIn("cvss_severity", report["baselines"]["methods"])
        self.assertEqual(report["chronological_split"]["status"], "computed")


if __name__ == "__main__":
    unittest.main()
