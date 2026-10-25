"""Unit checks for timestamp and outcome safeguards; stdlib-only."""

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from unittest.mock import patch

from dtem.data import database
from dtem.evaluation.historical import (
    kev_outcome,
    kev_history_outcome,
    lead_time,
    match_cve_records,
    observations_available_by,
)
from dtem.evaluation.research_pipeline import (
    collect_epss_history, collect_nvd_history, run_temporal_backtest,
)


class HistoricalValidityTests(unittest.TestCase):
    def setUp(self):
        self.cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_cve_match_requires_exact_identifier(self):
        records = [
            {"title": "CVE-2025-12345 details"},
            {"title": "CVE-2025-123456 details"},
            {"title": "Generic CVE discussion"},
        ]
        self.assertEqual(match_cve_records(records, "CVE-2025-12345"), records[:1])

    def test_nvd_description_mention_does_not_override_record_cve_id(self):
        related = {
            "source": "NVD", "cve_id": "CVE-2021-9999",
            "title": "CVE-2021-9999 related fix",
            "content": "References CVE-2021-44228.",
        }
        exact = {"source": "NVD", "cve_id": "CVE-2021-44228", "title": "log4j vulnerability"}
        self.assertEqual(match_cve_records([related, exact], "CVE-2021-44228"), [exact])

    def test_cutoff_excludes_future_and_missing_availability(self):
        records = [
            {"available_at": "2025-12-31T23:00:00Z", "published_at": "2025-12-31T22:00:00Z"},
            {"available_at": "2026-01-02T00:00:00Z", "published_at": "2026-01-01T12:00:00Z"},
            {"published_at": "2025-12-01T00:00:00Z"},
            {"available_at": "2025-12-30T00:00:00Z", "source_type": "dark_web"},
        ]
        kept, counts = observations_available_by(records, self.cutoff)
        self.assertEqual(kept, records[:1])
        self.assertEqual(counts, {"included": 1, "missing_availability": 1, "after_cutoff": 1,
                                  "missing_publication": 0,
                                  "prototype_or_unverified_dark_web": 1})

    def test_cutoff_excludes_missing_publication_timestamp(self):
        records = [{"available_at": "2025-12-31T23:00:00Z"}]
        kept, counts = observations_available_by(records, self.cutoff)
        self.assertEqual(kept, [])
        self.assertEqual(counts["missing_publication"], 1)

    def test_kev_horizon_and_non_inclusion_interpretation(self):
        included = kev_outcome({"dateAdded": "2026-01-15"}, self.cutoff, 30)
        excluded = kev_outcome({"dateAdded": "2026-02-15"}, self.cutoff, 30)
        self.assertEqual(included["outcome"], 1)
        self.assertEqual(excluded["outcome"], 0)
        self.assertIn("not evidence", excluded["interpretation"])
        self.assertEqual(kev_outcome({"dateAdded": "2026-01-01"}, self.cutoff, 30)["outcome"], 0)
        self.assertEqual(kev_outcome({"dateAdded": "2026-01-31"}, self.cutoff, 30)["outcome"], 1)

    def test_versioned_kev_outcome_requires_coverage_and_keeps_removals_auditable(self):
        events = [
            {"state": "added", "dateAdded": "2026-01-15"},
            {"state": "removed", "dateAdded": "2026-01-15"},
        ]
        positive = kev_history_outcome(
            events, self.cutoff, 30, history_start="2025-01-01T00:00:00Z",
            complete_through="2026-03-01T00:00:00Z")
        negative = kev_history_outcome(
            [], self.cutoff, 30, history_start="2025-01-01T00:00:00Z",
            complete_through="2026-03-01T00:00:00Z")
        unknown = kev_history_outcome(
            [], self.cutoff, 30, history_start="2026-01-02T00:00:00Z",
            complete_through="2026-03-01T00:00:00Z")
        self.assertEqual(positive["outcome"], 1)
        self.assertEqual(negative["outcome"], 0)
        self.assertIsNone(unknown["outcome"])

    def test_lead_time_early_late_and_missing(self):
        event = "2026-01-10T00:00:00Z"
        early = lead_time(event, "2026-01-08T00:00:00Z")
        late = lead_time(event, "2026-01-11T00:00:00Z")
        missed = lead_time(event, None)
        false_alert = lead_time(None, "2026-01-08T00:00:00Z", outcome_positive=False)
        no_event = lead_time(None, None, outcome_positive=False)
        self.assertEqual((early["status"], early["lead_days"]), ("early", 2.0))
        self.assertEqual((late["status"], late["lead_days"]), ("late", -1.0))
        self.assertEqual(false_alert["status"], "false_alert")
        self.assertEqual(no_event["status"], "no_event_no_alert")
        self.assertEqual(missed["status"], "missed_event")
        self.assertIsNone(missed["lead_days"])

    def test_database_insert_is_idempotent_for_same_source_item(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder, patch.object(database, "DB_PATH", Path(folder) / "test.db"):
            database.init_db()
            query_id = database.get_or_create_query("CVE-2026-1234")
            record = {
                "query_id": query_id, "source": "NVD", "source_type": "public_api",
                "title": "CVE-2026-1234 issue", "url": "https://example.invalid/cve",
                "published_at": "2026-01-01T00:00:00Z",
            }
            self.assertEqual(database.insert_intel_records([record]), 1)
            self.assertEqual(database.insert_intel_records([record]), 0)
            self.assertEqual(database.count_intel_for_keyword("CVE-2026-1234"), 1)

    def test_backtest_refuses_unverified_coverage_and_writes_reproducible_empty_report(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            observations = root / "observations.jsonl"
            observations.write_text(
                '{"cve_id":"CVE-2025-12345","source":"OTX",'
                '"title":"PoC reference","published_at":"2025-12-20T00:00:00Z",'
                '"available_at":"2025-12-20T00:00:00Z"}\n', encoding="utf-8")
            kev = root / "kev.json"
            kev.write_text('{"vulnerabilities":[]}', encoding="utf-8")
            output = root / "report.json"
            report = run_temporal_backtest(
                observations, kev, output,
                start=datetime(2025, 12, 1, tzinfo=timezone.utc),
                end=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
            self.assertEqual(report["status"], "insufficient_historical_coverage")
            self.assertEqual(report["prediction_count"], 0)
            self.assertIsNone(report["metrics"])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)

    def test_backtest_labels_nvd_history_as_exploratory_not_cti_validation(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            observations = root / "nvd.jsonl"
            observations.write_text(
                json.dumps({"cve_id": "CVE-2025-12345", "source": "NVD",
                            "title": "NVD change", "content": "record update",
                            "published_at": "2025-05-31T12:00:00Z",
                            "available_at": "2025-05-31T12:00:00Z",
                            "raw_data": {"change": {"cveId": "CVE-2025-12345"}}}) + "\n",
                encoding="utf-8")
            kev = root / "kev.jsonl"
            kev.write_text("", encoding="utf-8")
            kev.with_suffix(".jsonl.coverage.json").write_text(json.dumps({
                "history_start": "2025-01-01T00:00:00Z",
                "complete_through": "2025-08-01T00:00:00Z",
                "coverage_intervals": [{"start": "2025-01-01T00:00:00Z",
                                        "complete_through": "2025-08-01T00:00:00Z"}],
            }), encoding="utf-8")
            report = run_temporal_backtest(
                observations, kev, root / "report.json",
                start=datetime(2025, 6, 1, tzinfo=timezone.utc),
                end=datetime(2025, 6, 2, tzinfo=timezone.utc), step_days=1,
            )
            self.assertEqual(report["status"], "exploratory_nvd_only")
            self.assertEqual(report["observation_source_counts"], {"NVD": 1})
            self.assertIn("not CTI evidence", report["evaluation_scope"])
            self.assertEqual(report["prediction_count"], 1)

    def test_epss_history_collector_persists_returned_dates_without_inference(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            responses = [
                {"data": [{"cve": "CVE-2025-12345", "date": "2025-12-01",
                           "epss": "0.2", "percentile": "0.8"}]},
                {"data": []},
            ]
            with patch("dtem.evaluation.research_pipeline._get_json", side_effect=responses):
                manifest = collect_epss_history(
                    ["CVE-2025-12345"], "2025-12-01", "2025-12-02",
                    Path(folder), request_delay=0,
                )
            self.assertEqual(manifest["observation_count"], 1)
            saved = [json.loads(line) for line in
                     (Path(folder) / manifest["file"]).read_text(encoding="utf-8").splitlines()]
            self.assertEqual(saved[0]["score_date"], "2025-12-01")
            self.assertNotIn("available_at", saved[0])
            self.assertIn("not an invented timestamp", manifest["availability_semantics"])

    def test_epss_history_can_request_only_selected_dates(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            responses = [
                {"data": [{"cve": "CVE-2025-12345", "date": "2025-06-01",
                           "epss": "0.2", "percentile": "0.8"}]},
                {"data": [{"cve": "CVE-2025-12345", "date": "2025-06-15",
                           "epss": "0.3", "percentile": "0.9"}]},
            ]
            with patch("dtem.evaluation.research_pipeline._get_json", side_effect=responses) as request:
                manifest = collect_epss_history(
                    ["CVE-2025-12345"], "2025-06-01", "2025-06-30", Path(folder),
                    request_delay=0, requested_dates=["2025-06-15", "2025-06-01"],
                )
            self.assertEqual(request.call_count, 2)
            self.assertEqual(manifest["requested_dates"], ["2025-06-01", "2025-06-15"])
            self.assertEqual(manifest["observation_count"], 2)

    def test_nvd_history_collector_preserves_event_time_and_provenance(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            payload = {"totalResults": 1, "cveChanges": [{
                "cveId": "CVE-2024-12345", "cveChangeId": "event-1",
                "eventName": "CVE Modified", "sourceIdentifier": "cna@example.invalid",
                "created": "2024-02-03T12:34:56.000Z",
                "details": [{"action": "Changed", "type": "Reference", "newValue": "Exploit"}],
            }]}
            with patch("dtem.evaluation.research_pipeline._get_json", return_value=payload):
                manifest = collect_nvd_history(
                    "2024-02-03", "2024-02-03", Path(folder), request_delay=0,
                )
            self.assertEqual(manifest["status"], "ok")
            self.assertEqual(manifest["unique_event_count"], 1)
            saved_path = Path(folder) / manifest["file"]
            event = json.loads(saved_path.read_text(encoding="utf-8").strip())
            self.assertEqual(event["published_at"], "2024-02-03T12:34:56+00:00")
            self.assertEqual(event["available_at"], event["published_at"])
            self.assertEqual(event["raw_data"]["cveChangeId"], "event-1")
            self.assertIn("single-source", manifest["unit_limit"])

    def test_backtest_uses_only_epSS_score_from_before_cutoff_date(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            root = Path(folder)
            observations = root / "observations.jsonl"
            observations.write_text(
                '{"cve_id":"CVE-2025-12345","source":"OTX",'
                '"title":"CVE-2025-12345 report","published_at":"2025-05-01T00:00:00Z",'
                '"available_at":"2025-05-01T00:00:00Z"}\n', encoding="utf-8")
            kev = root / "kev.json"
            kev.write_text('{"vulnerabilities":[{"cveID":"CVE-2025-12345","dateAdded":"2025-06-10"}]}', encoding="utf-8")
            kev.with_suffix(".json.coverage.json").write_text(
                '{"complete_through":"2025-07-02T00:00:00Z"}', encoding="utf-8")
            epss = root / "epss.jsonl"
            epss.write_text(
                '{"cve_id":"CVE-2025-12345","score_date":"2025-06-01","epss":"0.75"}\n',
                encoding="utf-8")
            report = run_temporal_backtest(
                observations, kev, root / "report.jsonl",
                start=datetime(2025, 6, 1, tzinfo=timezone.utc),
                end=datetime(2025, 6, 3, tzinfo=timezone.utc), step_days=1,
                epss_history_path=epss,
            )
            rows = report["predictions"]
            self.assertIsNone(rows[0]["epss"])
            self.assertEqual(rows[1]["epss"], 0.75)
            self.assertEqual(report["epss_baseline"]["sample_count"], 1)
            self.assertEqual(rows[1]["label"], 1)


if __name__ == "__main__":
    unittest.main()
