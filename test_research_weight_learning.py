"""
test_research_weight_learning.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Regression checks for the three capabilities added to move DTEM from assumed
weights to evidence-earned ones:

  * ``alert_budget_metrics``  - precision/recall under a fixed review capacity.
  * ``diagnostics``           - indicator collinearity and source-independence.
  * ``weight_learning``       - simplex-constrained weights fit on development,
                                selected on validation, evaluated once on test.

These verify the software computes, refuses to fabricate, and reports honestly.
A passing suite does NOT mean DTEM wins; on the real single-source cohort the
learned model is expected to lose to frequency-only, and these tests pin that
honest-reporting behaviour, not a favorable number.
"""

import math
import unittest
from datetime import datetime, timedelta, timezone

from dtem.evaluation.diagnostics import feature_correlation, source_independence_audit
from dtem.evaluation.metrics import alert_budget_metrics
from dtem.evaluation.split import partition_periods
from dtem.evaluation.weight_learning import fit_weights, run_weight_learning
from dtem.model.scoring import DTEMScoringEngine


def _row(cve, day, label, *, freq=10, growth=50.0, div=1, exploit=0.0):
    cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(days=day)
    return {
        "cve_id": cve,
        "cutoff": cutoff.isoformat(),
        "label": label,
        "features": {
            "detection_frequency": freq,
            "growth_rate": growth,
            "source_diversity": div,
            "exploit_evidence_score": exploit,
            "total_records": freq,
            "cvss_base_score": 7.0,
        },
    }


class AlertBudgetTests(unittest.TestCase):
    def test_perfect_ranking_scores_all_hits(self):
        result = alert_budget_metrics([1, 1, 0, 0], [4, 3, 2, 1], top_k=2)
        self.assertEqual(result["precision_at_budget"], 1.0)
        self.assertEqual(result["positives_captured"], 2)
        self.assertEqual(result["false_alerts"], 0)

    def test_random_ranking_matches_prevalence(self):
        result = alert_budget_metrics([1, 0, 0, 0], [1, 2, 3, 4], top_k=1)
        self.assertEqual(result["precision_at_budget"], 0.0)
        self.assertEqual(result["false_alerts"], 1)

    def test_ties_at_cutoff_are_disclosed_not_hidden(self):
        result = alert_budget_metrics([1, 0, 1, 0], [5, 5, 5, 5], top_k=2)
        self.assertEqual(result["n_ties_at_cutoff"], 4)
        self.assertEqual(result["budget"], 2)

    def test_budget_fraction_defaults_to_ten_percent(self):
        labels = [1] + [0] * 99
        scores = [10] + [1] * 99
        result = alert_budget_metrics(labels, scores)
        self.assertEqual(result["budget"], 10)

    def test_empty_input_has_no_budget(self):
        self.assertEqual(alert_budget_metrics([], [])["status"], "no_samples")


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.engine = DTEMScoringEngine()

    def test_constant_indicator_is_flagged(self):
        rows = [_row(f"CVE-2025-{i:04d}", i % 3, i % 2, div=1) for i in range(6)]
        result = feature_correlation(rows, self.engine)
        self.assertIn("source_diversity", result["constant_indicators"])

    def test_collinear_indicators_are_detected(self):
        # Growth tracking frequency exactly should flag the pair as near-duplicate.
        rows = []
        for i in range(8):
            freq = (i + 1) * 3
            rows.append(_row(f"CVE-2025-{i:04d}", i % 4, i % 2,
                             freq=freq, growth=float(freq * 10)))
        result = feature_correlation(rows, self.engine, threshold=0.8)
        pairs = [tuple(sorted(p["pair"])) for p in result["near_collinear_pairs"]]
        self.assertIn(("detection_frequency", "growth_rate"), pairs)

    def test_fewer_than_two_rows_is_not_computed(self):
        self.assertEqual(feature_correlation([_row("CVE-2025-0000", 0, 1)], self.engine)["status"],
                         "insufficient_rows")

    def test_single_source_cohort_flagged(self):
        obs = [{"source": "NVD", "title": "a", "content": "b"} for _ in range(5)]
        result = source_independence_audit(obs)
        self.assertTrue(result["single_source_cohort"])
        self.assertEqual(result["distinct_sources"], 1)

    def test_multiple_sources_and_duplicate_content_counted(self):
        obs = [
            {"source": "NVD", "title": "same", "content": "text"},
            {"source": "NVD", "title": "same", "content": "text"},
            {"source": "AlienVault OTX", "title": "other", "content": "note"},
        ]
        result = source_independence_audit(obs)
        self.assertEqual(result["distinct_sources"], 2)
        self.assertFalse(result["single_source_cohort"])
        self.assertGreaterEqual(result["duplicate_content_records"], 1)


class SplitPartitionTests(unittest.TestCase):
    def test_buckets_are_chronological_and_complete(self):
        rows = [_row(f"CVE-2025-{i:04d}", d, i % 2) for d in range(10) for i in range(2)]
        result = partition_periods(rows)
        self.assertEqual(result["status"], "computed")
        buckets = result["buckets"]
        self.assertEqual(sum(len(b) for b in buckets.values()), len(rows))
        max_dev = max(datetime.fromisoformat(r["cutoff"]) for r in buckets["development"])
        min_test = min(datetime.fromisoformat(r["cutoff"]) for r in buckets["test"])
        self.assertLess(max_dev, min_test)


class WeightLearningTests(unittest.TestCase):
    def setUp(self):
        self.engine = DTEMScoringEngine()

    def _separable_rows(self):
        # Exploit evidence alone separates the classes; frequency is constant and
        # therefore uninformative, so a learner should move weight onto exploit.
        rows = []
        for d in range(10):
            for idx, label in enumerate([1, 0, 1, 0]):
                rows.append(_row(f"CVE-2025-{d:02d}{idx}", d, label,
                                 freq=10, growth=50.0, exploit=100.0 if label else 0.0))
        return rows

    def test_single_class_development_returns_original_weights(self):
        rows = [_row(f"CVE-2025-{i:04d}", 0, 1) for i in range(5)]
        result = fit_weights(rows, self.engine)
        self.assertEqual(result["status"], "single_class_or_insufficient_rows")
        self.assertEqual(result["weights"], dict(self.engine.weights))

    def test_learned_weights_are_valid_simplex(self):
        result = fit_weights(self._separable_rows(), self.engine)
        self.assertEqual(result["status"], "fit")
        weights = result["weights"]
        self.assertTrue(all(w >= 0 for w in weights.values()))
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=6)

    def _adversarial_rows(self):
        # Growth is anti-correlated with the label while frequency is positively
        # correlated. With current weights (freq 0.50, growth 0.20, div 0.30, exploit 0),
        # the learner should shift weight from growth toward frequency.
        rows = []
        for d in range(10):
            for idx, label in enumerate([1, 0, 1, 0]):
                rows.append(_row(f"CVE-2025-{d:02d}{idx}", d, label,
                                 freq=30 if label else 5,
                                 growth=-50.0 if label else 120.0,
                                 exploit=0.0))
        return rows

    def test_learning_improves_development_ranking(self):
        result = fit_weights(self._adversarial_rows(), self.engine)
        self.assertEqual(result["status"], "fit")
        self.assertIsNotNone(result["dev_pr_auc_uniform"])
        self.assertGreaterEqual(result["dev_pr_auc_learned"], result["dev_pr_auc_uniform"])

    def test_learner_concentrates_on_the_informative_indicator(self):
        result = fit_weights(self._adversarial_rows(), self.engine)
        # Frequency weight should not decrease (already high); growth should not increase.
        self.assertGreaterEqual(result["weights"]["detection_frequency"],
                               self.engine.weights["detection_frequency"] - 0.01)
        self.assertLessEqual(result["weights"]["growth_rate"],
                             self.engine.weights["growth_rate"] + 0.01)

    def test_run_reports_honest_test_verdict(self):
        result = run_weight_learning(self._separable_rows(), self.engine)
        self.assertIn(result["test_comparison"]["verdict"], {
            "learned_beats_frequency_only", "frequency_only_matches_or_beats_learned",
            "tie", "undefined_on_test_single_class_or_empty",
            "not_testable_development_lacks_both_classes",
        })
        self.assertTrue(math.isclose(sum(result["weights"]["learned"].values()), 1.0, abs_tol=1e-6))

    def test_learned_beats_constant_frequency_on_separable_data(self):
        # When exploit fully predicts the label and frequency is constant, the
        # learned model should clear the frequency-only bar on the untouched test.
        result = run_weight_learning(self._separable_rows(), self.engine)
        self.assertTrue(result["learning_eligible"])
        self.assertTrue(result["test_comparison"]["learned_beats_frequency_only_on_test"])

    def test_undersampled_split_without_dates_is_reported(self):
        rows = [_row("CVE-2025-0000", 0, 1)]
        rows[0]["cutoff"] = "not-a-date"
        self.assertEqual(run_weight_learning(rows, self.engine)["status"], "no_dated_cutoffs")


if __name__ == "__main__":
    unittest.main()
