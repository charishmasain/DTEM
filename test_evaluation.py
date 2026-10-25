"""
test_evaluation.py
~~~~~~~~~~~~~~~~~~

Runner for the seven-scenario curated prototype evaluation.
It does not perform historical predictive validation.

Run:
    python test_evaluation.py
"""

import json
import logging
import sys
import io
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from dtem.evaluation.validation_data import setup_validation_db
from dtem.evaluation.sensitivity import run_sensitivity_analysis, REPORT_PATH
from dtem.evaluation.backtester import run_timeline_backtest, PLOT_PATH

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_evaluation")

def separator(title: str) -> None:
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)

def main() -> None:
    separator("DTEM Evaluation & Validation Test Suite")
    print(f"Project root : {PROJECT_ROOT}")
    
    # 1. Setup DB
    separator("TEST 1 -- Database Validation Seeding")
    ground_truth = setup_validation_db()
    print(f"Loaded curated prototype labels ({len(ground_truth)} cases):")
    for kw, val in ground_truth.items():
        print(f"  {kw:>25s} -> Escalated: {val}")
    
    # 2. Run Sensitivity grid search
    separator("TEST 2 -- Weight Sensitivity Analysis")
    report = run_sensitivity_analysis()
    
    print("\nWeight Sensitivity Completed:")
    print(f"  Total Combinations Tested : {report['summary']['total_combinations_tested']}")
    print(f"  Optimal Weights Found     : {report['summary']['optimal_weights']}")
    print(f"  Default Baseline Weights  : {report['summary']['default_configured_weights']}")
    
    assert REPORT_PATH.exists(), f"Sensitivity report not found at {REPORT_PATH}"
    print("\n  [PASS] Weight sensitivity analysis verified.")

    # 3. Run Timeline Backtest
    separator("TEST 3 -- Curated Prototype Timeline")
    backtest_res = run_timeline_backtest(keyword="eval_lockbit")
    
    print("\nTimeline Backtest Completed:")
    print(f"  Historical lead time      : {backtest_res['early_warning_lead_days'] or 'Not estimable'}")
    print("\nTimeline values (sample points):")
    for row in backtest_res["timeline"][::3]: # Print every 3rd point
        print(f"  Day {row['day']:>3d}: DTEM={row['dtem']:>5.1f} | CVSS/EPSS/KEV=unavailable for curated prototype data")
        
    assert PLOT_PATH.exists(), f"Backtest chart plot not found at {PLOT_PATH}"
    print("\n  [PASS] Curated prototype timeline generated; this is not historical backtesting.")

    separator("PROTOTYPE EVALUATION RUN COMPLETED")
    print("Seven curated scenarios evaluated; no historical predictive validation was performed.\n")

if __name__ == "__main__":
    # Avoid replacing pytest's captured streams when this module is collected.
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace", write_through=True
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace", write_through=True
        )
    main()
