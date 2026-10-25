"""
test_dashboard.py
~~~~~~~~~~~~~~~~~

Verification script for Module 5 dashboard and API route handlers.

Tests:
  - Dashboard HTML rendering handler
  - Analysis handler for a seeded keyword
  - Stored-intelligence handler

The handlers are invoked directly because this Windows test sandbox cannot
create asyncio's socket pair. This checks route registration and handler output,
but not the HTTP transport layer.

Run:
    python test_dashboard.py
"""

import json
import logging
import sys
import io
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

# Force UTF-8 on Windows console
if sys.platform == "win32" and __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from starlette.requests import Request
from dtem.web.app import app, analyze_threat, get_stored_intel, read_dashboard
from dtem.extractor.features import ThreatInfoExtractor

logging.basicConfig(level=logging.INFO)


class _ASGIResponse:
    def __init__(self, status_code: int, body: bytes) -> None:
        self.status_code = status_code
        self.text = body.decode("utf-8")

    def json(self):
        return json.loads(self.text)


def _run_endpoint(coroutine):
    """Run these non-awaiting async route functions without a socket-backed loop."""
    try:
        coroutine.send(None)
    except StopIteration as completed:
        return completed.value
    raise AssertionError("Dashboard test route unexpectedly awaited asynchronous I/O")


def _get(path: str) -> _ASGIResponse:
    """Invoke the registered GET endpoint without a threaded test client."""
    parsed = urlsplit(path)
    assert any(route.path == parsed.path and "GET" in getattr(route, "methods", set())
               for route in app.routes)
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": parsed.path, "raw_path": parsed.path.encode("ascii"),
        "query_string": parsed.query.encode("ascii"), "root_path": "",
        "headers": [(b"host", b"testserver")],
        "client": ("testclient", 50000), "server": ("testserver", 80),
        "app": app,
    }
    if parsed.path == "/":
        response = _run_endpoint(read_dashboard(Request(scope)))
    elif parsed.path == "/api/analyze":
        keyword = dict(part.split("=", 1) for part in parsed.query.split("&") if "=" in part).get("keyword", "")
        response = _run_endpoint(analyze_threat(keyword=keyword))
    elif parsed.path == "/api/intel":
        keyword = dict(part.split("=", 1) for part in parsed.query.split("&") if "=" in part).get("keyword", "")
        response = _run_endpoint(get_stored_intel(keyword=keyword))
    else:
        raise AssertionError(f"No supported GET test handler for {parsed.path}")
    return _ASGIResponse(response.status_code, response.body)


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_dashboard_endpoints() -> None:
    separator("DTEM Module 5 -- Web Dashboard & API Test Suite")

    # Test 1: Dashboard UI handler
    print("\n---> Testing dashboard HTML handler")
    res_ui = _get("/")
    assert res_ui.status_code == 200, f"Dashboard UI failed with HTTP {res_ui.status_code}"
    assert "Dynamic Threat Emergence Model" in res_ui.text
    print("  [PASS] Dashboard HTML UI renders successfully (HTTP 200).")

    # Test 2: Analysis handler
    print("\n---> Testing analysis handler for LockBit")
    # Keep this suite deterministic and independent of live NVD/OTX availability.
    # Seeded database records exercise analysis without external network calls.
    with patch("dtem.web.app.collector_manager.collect", return_value=[]):
        res_api = _get("/api/analyze?keyword=LockBit")
        assert res_api.status_code == 200, f"API analyze failed with HTTP {res_api.status_code}"
        data = res_api.json()

    print(f"  Keyword           : {data['keyword']}")
    print(f"  Emergence Score   : {data['emergence']['emergence_score']} ({data['emergence']['emergence_stage']})")
    print(f"  Risk Score        : {data['risk']['risk_score']} ({data['risk']['risk_level']})")
    print(f"  Threat Priority   : {data['risk']['threat_priority']}")
    print(f"  Intelligence Feed : {len(data['collected_intel'])} items")

    if data["emergence"]["score_status"] == "insufficient_data":
        assert data["emergence"]["emergence_score"] is None
        assert data["risk"]["risk_score"] is None
    else:
        assert 0 <= data['emergence']['emergence_score'] <= 100
    assert all(not record.get("demonstration_data", False)
               for record in data["features"].get("evidence_records", []))
    assert "early_warning_message" in data['risk']
    print("  [PASS] API analyze endpoint returned complete DTEM output.")

    # No-evidence analyses return an explicit unavailable status and must not
    # create zero-valued history snapshots or threshold alerts.
    empty = ThreatInfoExtractor._empty_features("CVE-2099-12345")
    with patch("dtem.web.app.collector_manager.collect", return_value=[]), \
         patch("dtem.web.app.extractor.extract_features", return_value=empty), \
         patch("dtem.web.app.record_analysis") as persist, \
         patch("dtem.web.app.run_timeline_backtest_for_api", return_value={"timeline": [], "early_warning_lead_days": None}):
        no_data = _get("/api/analyze?keyword=CVE-2099-12345").json()
    assert no_data["emergence"]["score_status"] == "insufficient_data"
    assert no_data["risk"]["risk_score"] is None
    assert no_data["snapshot_id"] is None
    persist.assert_not_called()

    # Test 3: Stored intelligence handler
    print("\n---> Testing stored intelligence handler for LockBit")
    res_intel = _get("/api/intel?keyword=LockBit")
    assert res_intel.status_code == 200
    intel_data = res_intel.json()
    assert intel_data['total_records'] > 0
    print(f"  [PASS] Stored intel endpoint returned {intel_data['total_records']} records.")

    separator("ALL MODULE 5 TESTS PASSED")
    print("  Web Dashboard & REST APIs verified successfully.\n")


if __name__ == "__main__":
    test_dashboard_endpoints()
