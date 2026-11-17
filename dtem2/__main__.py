from dtem2.experimental_pipeline import run_dtem2_experiment

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Run the DTEM 2.0 experimental evaluation.")
    parser.add_argument("--backtest", type=Path, default=Path("output/evaluation/historical_backtest_3way.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("results/dtem2"))
    args = parser.parse_args()
    run_dtem2_experiment(args.backtest, args.output_dir)
