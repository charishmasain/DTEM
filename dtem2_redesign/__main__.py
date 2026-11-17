from __future__ import annotations

import argparse
from pathlib import Path

from dtem2_redesign.diagnostics import run_diagnostics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the DTEM 2.0 redesign diagnostics and export ranked score summaries.")
    parser.add_argument("--backtest", default="output/evaluation/historical_backtest_3way.json", type=Path)
    parser.add_argument("--output-dir", default="results/dtem2_redesign", type=Path)
    args = parser.parse_args()
    run_diagnostics(args.backtest, args.output_dir)
