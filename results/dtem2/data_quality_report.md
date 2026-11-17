# Data Quality Report

## Source coverage

- NVD: 13475 observations
- Metasploit: 277 observations
- Nuclei: 4501 observations
- Total observed rows in the archived historical backtest metadata: 18253

## Timestamp validity

The historical pipeline applies cutoff enforcement in `dtem/evaluation/historical.py` and excludes records with:

- missing `available_at` / `collected_at`
- missing `published_at`
- publication date or availability date after the cutoff
- prototype or unverified dark-web observations

This is a valid leakage guard but it is not a substitute for a fully verified public-availability dataset.

## Duplicate and correlated evidence

The repository currently counts raw observations but does not enforce strong deduplication across source-specific duplicates or overlapping evidence. DTEM 2.0 adds a stricter evidence-quality weighting layer in `dtem2/features.py` to reduce the impact of redundant observations, but duplicate handling remains conservative rather than over-aggressive.

## Outcome distribution

From the archived historical backtest artifact:

- positive labels: 33
- negative labels: 36241
- positive prevalence: about 0.00091

This is highly imbalanced, so PR-AUC and ranking metrics are more informative than threshold accuracy.

## Final assessment

The archived historical dataset is useful for pipeline validation but it is not yet strong enough to support a credible claim of real-world predictive superiority.
