"""Persistence and endpoint checks for prototype monitoring features."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dtem.data import database
from dtem.web.app import (
    alerts_api, dashboard_data, manage_alert, settings_api, settings_update,
    watchlist_add, watchlist_api, watchlist_delete, threat_detail_page,
    printable_report, export_data,
)
from dtem.monitoring import run_monitoring_cycle


def resolve(coroutine):
    try:
        coroutine.send(None)
    except StopIteration as done:
        return done.value
    raise AssertionError("Expected endpoint handler to complete without async I/O")


class PrototypePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.db_patch = patch.object(database, "DB_PATH", Path(self.temp.name) / "prototype.db")
        self.db_patch.start()
        database.init_db()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def analysis(self, score, risk="High"):
        return database.record_analysis(
            "CVE-2026-4321", {"detection_frequency": 2, "exploit_evidence_level": "poc_reference"},
            {"emergence_score": score, "emergence_stage": "Emerging", "sub_scores": {"frequency": 20}},
            {"risk_score": score, "risk_level": risk, "severity_basis": "unavailable", "recommendations": ["Review evidence"]},
            threshold=65, increase_threshold=10,
        )

    def test_persistent_snapshots_threshold_alerts_and_increase_deduplication(self):
        first, alerts = self.analysis(60)
        self.assertEqual(alerts, [])
        second, alerts = self.analysis(66)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "threshold_crossing")
        third, alerts = self.analysis(68)
        self.assertEqual(alerts, [])
        fourth, alerts = self.analysis(80)
        self.assertEqual([a["alert_type"] for a in alerts], ["significant_increase"])
        self.assertEqual([s["id"] for s in database.get_snapshot_history("CVE-2026-4321")], [first, second, third, fourth])
        self.assertEqual(len(database.list_alerts()), 2)
        self.assertTrue(database.update_alert(alerts[0]["id"], "acknowledged"))
        self.assertEqual(database.list_alerts()[0]["status"], "acknowledged")

    def test_watchlist_and_dashboard_endpoints_use_persisted_data(self):
        added = resolve(watchlist_add({"keyword": "CVE-2026-4321", "category": "vulnerability"}))
        self.assertTrue(added["created"])
        self.analysis(72)
        dashboard = resolve(dashboard_data(days=None, sort="risk"))
        self.assertEqual(dashboard.body[:1], b"{")
        self.assertIn(b"cve-2026-4321", dashboard.body)
        self.assertEqual(len(resolve(watchlist_api())["items"]), 1)
        self.assertEqual(len(resolve(alerts_api(status=None, limit=100))["alerts"]), 1)
        detail = resolve(threat_detail_page("cve-2026-4321"))
        self.assertIn("Persisted snapshots and evidence", detail.body.decode("utf-8"))
        report = resolve(printable_report("cve-2026-4321"))
        self.assertIn("Print / Save PDF", report.body.decode("utf-8"))
        export = resolve(export_data(kind="alerts", format="json"))
        self.assertIn(b"threshold_crossing", export.body)
        self.assertTrue(resolve(watchlist_delete("CVE-2026-4321"))["ok"])

    def test_settings_validation_and_alert_status_validation(self):
        result = resolve(settings_update({"alert_threshold": 70, "minimum_alert_risk": "High", "interval_seconds": 120}))
        self.assertEqual(result["alert_threshold"], 70)
        self.assertEqual(result["minimum_alert_risk"], "High")
        self.assertEqual(resolve(settings_api())["interval_seconds"], 120)
        with self.assertRaises(Exception):
            resolve(settings_update({"alert_threshold": 101}))
        with self.assertRaises(Exception):
            resolve(manage_alert(999, {"status": "acknowledged"}))

    def test_monitor_cycle_uses_public_sources_and_persists_snapshot_and_status(self):
        database.add_watchlist_item("CVE-2026-4321", "vulnerability")

        class FakeManager:
            last_status = []
            def collect(self, keyword, include_sources=None):
                self.last_status = [{"source": "NVD", "status": "empty", "record_count": 0}]
                self.include_sources = include_sources
                return []

        manager = FakeManager()
        with patch("dtem.monitoring.CollectorManager", return_value=manager):
            result = run_monitoring_cycle()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(manager.include_sources, {"NVD", "AlienVault OTX"})
        # A collector cycle with no eligible evidence records its source status
        # but does not create a misleading zero-score threat snapshot.
        self.assertEqual(len(database.get_snapshot_history("CVE-2026-4321")), 0)
        self.assertEqual(database.latest_monitoring_run()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
