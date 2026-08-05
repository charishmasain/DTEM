"""
test_collector.py
~~~~~~~~~~~~~~~~~

End-to-end verification script for Module 1: Threat Intelligence Collector.

Tests:
  1. Database seeding with simulated dark web data.
  2. Full collector pipeline for a seeded keyword ("lockbit").
  3. JSON output file generation.
  4. Database population verification.
  5. Dynamic generation for an unseeded keyword ("Scattered Spider").

Run:
    python test_collector.py
"""

import json
import logging
import os
import sys
import io
from pathlib import Path

# ---------------------------------------------------------------------------
# Force UTF-8 on Windows console
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace"
    )

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from dtem.data.database import DB_PATH, count_intel_for_keyword, fetch_intel_for_keyword, init_db
from dtem.data.seed_data import seed_database
from dtem.collector.manager import CollectorManager

# ---------------------------------------------------------------------------
# Setup logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_collector")


def separator(title: str) -> None:
    print()
    print("=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_seed_database() -> None:
    """Test 1: Seed the database and verify record counts."""
    separator("TEST 1 -- Seed Database")

    results = seed_database(force=True)
    print(f"  Database path : {DB_PATH}")
    print(f"  Seeded keywords:")
    for kw, count in results.items():
        print(f"    {kw:>20s} -> {count:>3d} records")
    total = sum(results.values())
    print(f"  {'TOTAL':>22s} -> {total:>3d} records")

    assert total > 0, "Seed database produced zero records!"
    print("\n  [PASS] database seeded successfully.")


def test_collect_seeded_keyword() -> None:
    """Test 2: Run full collector pipeline for 'lockbit'."""
    separator("TEST 2 -- Collect Intelligence: 'lockbit'")

    manager = CollectorManager()
    records = manager.collect("lockbit")

    print(f"\n  Records returned: {len(records)}")
    print(f"  Sources found:")

    source_counts: dict[str, int] = {}
    for rec in records:
        src = rec.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    for src, cnt in sorted(source_counts.items()):
        print(f"    {src:>20s} -> {cnt:>3d}")

    # Print first 5 titles
    print(f"\n  Sample records (first 5):")
    for rec in records[:5]:
        exploit_flag = "[EXPLOIT]" if rec.get("exploit_mentioned") else ""
        print(f"    [{rec['source']:>18s}] {rec['title'][:60]}  {exploit_flag}")

    assert len(records) > 0, "Collector returned zero records for 'lockbit'!"
    print("\n  [PASS] collector returned records.")


def test_json_output() -> None:
    """Test 3: Verify JSON output file was created."""
    separator("TEST 3 -- JSON Output File")

    output_path = PROJECT_ROOT / "output" / "lockbit_intel.json"
    assert output_path.exists(), f"JSON output not found at {output_path}"

    with open(output_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    print(f"  File           : {output_path}")
    print(f"  Keyword        : {data.get('keyword')}")
    print(f"  Collected at   : {data.get('collected_at')}")
    print(f"  Total records  : {data.get('total_records')}")

    assert data.get("total_records", 0) > 0, "JSON output has zero records!"
    print("\n  [PASS] JSON output is valid.")


def test_database_population() -> None:
    """Test 4: Verify records are stored in SQLite."""
    separator("TEST 4 -- Database Population")

    count = count_intel_for_keyword("lockbit")
    print(f"  Records in DB for 'lockbit': {count}")

    records = fetch_intel_for_keyword("lockbit")
    sources = set(r["source"] for r in records)
    print(f"  Unique sources: {sources}")

    assert count > 0, "Database has zero records for 'lockbit'!"
    print("\n  [PASS] database is populated.")


def test_dynamic_keyword() -> None:
    """Test 5: Test dynamic generation for an unseeded keyword."""
    separator("TEST 5 -- Dynamic Keyword: 'Scattered Spider'")

    manager = CollectorManager()
    records = manager.collect("Scattered Spider")

    print(f"\n  Records returned: {len(records)}")
    for rec in records[:5]:
        print(f"    [{rec['source']:>18s}] {rec['title'][:65]}")

    # Verify records were saved to DB
    count = count_intel_for_keyword("scattered spider")
    print(f"\n  Records in DB: {count}")

    assert len(records) > 0, "Dynamic generation returned zero records!"
    print("\n  [PASS] dynamic generation works.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    separator("DTEM Module 1 -- Collector Test Suite")
    print(f"  Project root : {PROJECT_ROOT}")
    print(f"  Database     : {DB_PATH}")

    test_seed_database()
    test_collect_seeded_keyword()
    test_json_output()
    test_database_population()
    test_dynamic_keyword()

    separator("ALL TESTS PASSED")
    print("  Module 1 (Threat Intelligence Collector) is verified.\n")


if __name__ == "__main__":
    main()
