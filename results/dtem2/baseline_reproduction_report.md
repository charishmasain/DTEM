# Baseline Reproduction Report

## Dataset

- Archived artifact: `output/evaluation/historical_backtest_3way.json`
- Number of prediction rows: 36274
- Positive labels: 33
- Negative labels: 36241

## Split summary

The historical backtest artifact includes a chronological split summary with:

- development: 13220 rows
- validation: 10791 rows
- test: 12263 rows

The saved file reports that temporal leakage is prevented and that repeated CVEs are counted as a caveat.

## Metric reproduction

The original historical artifact reports:

- `pr_auc`: 0.001361
- `pr_auc_random_baseline`: 0.00091
- `pr_auc_bootstrap`: [0.000735, 0.00299]

We reproduced the evaluation on the archived backtest and confirmed the baseline metrics are reproducible from the same saved artifact.

## DTEM 2.0 comparison

The experimental branch on the same saved artifact produced:

- frequency-only PR-AUC: 0.001427
- original DTEM 1.0 PR-AUC: 0.001361
- DTEM 2.0 PR-AUC: 0.00108

This indicates that the first DTEM 2.0 formulation did not outperform the historical frequency-only or original DTEM 1.0 baseline on the archived cohort.
