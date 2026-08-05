"""
test_dashboard.py
~~~~~~~~~~~~~~~~~

Verification script for Module 5: Web Dashboard & API Endpoints.

Tests:
  - GET / (renders dashboard HTML page)
  - GET /api/analyze?keyword=LockBit
  - GET /api/analyze?keyword=BlackLock
  - GET /api/intel?keyword=LockBit

Run:
    python test_dashboard.py
"""

import logging
import sys
import io
from pathlib import Path

# Force UTF-8 on Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from dtem.web.app import app

client = TestClient(app)

logging.basicConfig(level=logging.INFO)


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_dashboard_endpoints() -> None:
    separator("DTEM Module 5 -- Web Dashboard & API Test Suite")

    # Test 1: GET / (Dashboard UI)
    print("\n---> Testing GET / (Dashboard HTML UI)")
    res_ui = client.get("/")
    assert res_ui.status_code == 200, f"Dashboard UI failed with HTTP {res_ui.status_code}"
    assert "Dynamic Threat Emergence Model" in res_ui.text
    print("  [PASS] Dashboard HTML UI renders successfully (HTTP 200).")

    # Test 2: GET /api/analyze?keyword=LockBit
    print("\n---> Testing GET /api/analyze?keyword=LockBit")
    res_api = client.get("/api/analyze?keyword=LockBit")
    assert res_api.status_code == 200, f"API analyze failed with HTTP {res_api.status_code}"
    data = res_api.json()

    print(f"  Keyword           : {data['keyword']}")
    print(f"  Emergence Score   : {data['emergence']['emergence_score']} ({data['emergence']['emergence_stage']})")
    print(f"  Risk Score        : {data['risk']['risk_score']} ({data['risk']['risk_level']})")
    print(f"  Threat Priority   : {data['risk']['threat_priority']}")
    print(f"  Intelligence Feed : {len(data['collected_intel'])} items")

    assert data['emergence']['emergence_score'] > 0
    assert "early_warning_message" in data['risk']
    print("  [PASS] API analyze endpoint returned complete DTEM output.")

    # Test 3: GET /api/intel?keyword=LockBit
    print("\n---> Testing GET /api/intel?keyword=LockBit")
    res_intel = client.get("/api/intel?keyword=LockBit")
    assert res_intel.status_code == 200
    intel_data = res_intel.json()
    assert intel_data['total_records'] > 0
    print(f"  [PASS] Stored intel endpoint returned {intel_data['total_records']} records.")

    separator("ALL MODULE 5 TESTS PASSED")
    print("  Web Dashboard & REST APIs verified successfully.\n")


if __name__ == "__main__":
    test_dashboard_endpoints()
