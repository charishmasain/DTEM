# DTEM 2.0 Audit Report

## Scope

This audit is deliberately limited to the historical evaluation path and the experimental branch. It preserves the original DTEM 1.0 baseline while isolating the DTEM 2.0 research implementation.

## Repository audit

- Baseline branch: `master` at `03eec98`
- Experimental branch: `dtem2`
- Original DTEM 1.0 files remain in the historical package tree under `dtem/`
- Separate experimental code lives under `dtem2/`

## Dataset discrepancy resolution

The saved artifact `output/evaluation/historical_backtest_3way.json` is the decisive source of truth for the current historical pipeline. It reports the following:

- `observation_source_counts`: NVD=13475, Metasploit=277, Nuclei=4501
- `observation_event_count`: 18253
- `cves_with_observations`: 14502
- `prediction_count`: 36274
- `eligible_positive`: 33
- `eligible_negative`: 36241

However, the file also contains the explicit evaluation-scoping field:

- `status`: `completed`
- `evaluation_scope`: `timestamped observations supplied by the caller; assess source suitability before interpreting as DTEM evidence`
- `status` is not a multi-source validation label; the report states that the data source must be assessed before using it as evidence.

The historical feature-generation logic in `dtem/evaluation/research_pipeline.py` confirms the evaluation is not automatically multi-source. The pipeline builds a single aggregated observation set and counts sources, but it does not require multi-source independence in the feature score itself. The resulting backtest still carries the `exploratory_nvd_only` caveat when the dataset is effectively single-source.

## Source contribution audit

The code paths that build the historical features are timestamp-aware, but the actual feature pipeline does not enforce that Metasploit or Nuclei features must contribute to the final scoring rows. The saved evaluation file includes source counts in the metadata, but the per-row feature values used for the score are drawn from the aggregated CVE-level observation set and not from a verified per-source scoring mechanism. In other words:

- Multi-source presence is visible in the data collection logs.
- Multi-source contribution to the final evaluated feature values is not guaranteed by the historical scoring pipeline.
- The current output must therefore be treated as source-mixed metadata, not as a validated multi-source evaluation.

## Reproduction audit

The saved baseline metrics on the archived artifact are:

- `pr_auc`: 0.001361
- random baseline: 0.00091
- bootstrap interval: [0.000735, 0.00299]
- held-out test rows: 12263 with 12 positives

The DTEM 2.0 experimental branch recomputed on the same archive produced `dtem_2_0` PR-AUC of `0.00108`, which is below the original DTEM 1.0 value on the same saved cohort.

## Scientific conclusion

The current dataset and backtest should not be described as a validated multi-source model benchmark. The repository’s own documentation and saved artifacts describe the cohort as a historical pipeline demonstration, not a final real-world predictive-validity study.
