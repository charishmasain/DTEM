# Reviewer feedback implementation status

Updated: 2026-10-24

This report separates software corrections from evidence needed for a publication claim. The supplied feedback PDF is a reviewer/mentor assessment, not a record of experiments. No performance result is inferred from its examples.

## Implemented in the prototype

- CVE queries now treat NVD records by their own explicit CVE identifier. NVD keyword results whose descriptions mention a different CVE are excluded from the target's features, CVSS extraction, and displayed evidence list.
- Empty eligible evidence is reported as `insufficient_data`. The API returns no emergence or risk estimate, and the dashboard displays `N/A` rather than a misleading stable-growth score. Such queries are not stored as numeric history snapshots or alert candidates. An empty source list is no longer described as a single-source detection.
- Growth is unavailable when neither equal-length comparison window contains dated reports. The indicator then contributes zero to the weighted score; it is not treated as observed 0% growth. The existing percentage equation and weights remain unchanged pending development data.
- Frequency and source-label normalization safely handle malformed/non-finite values. Source diversity trims whitespace and folds case, and is described only as distinct labels, not independent corroboration.
- The shared timeline and historical backtest now treat empty time windows as unavailable rather than plotting a fabricated zero score. No historical lead-time value is manufactured.
- Existing monitoring, API, and database contracts remain available. Risk and emergence scores are nullable only for insufficient evidence; the dashboard handles those values explicitly.

## Implemented but not validated with historical data

- Current public snapshot collection exists for NVD and CISA KEV; the current EPSS collector records only the returned score date. Exact-CVE matching, cutoff filtering, KEV horizon labeling, and a backtest runner are present.
- The historical EPSS path now retrieves genuine date-stamped FIRST scores for a specified CVE cohort and date range. The backtest can pair those scores with DTEM predictions on the same CVE/cutoff rows, using only a score dated before the cutoff UTC date and a documented probability threshold.
- The smoothed log-growth proposal is available as a diagnostic (`alpha=0.5`) and now also as a fully specified bounded sub-score `50*(1+tanh(G/scale))` with a config-selectable `growth_mode` (default remains `legacy`). Its scale/window/smoothing constants have not been selected on development data, so it is not the production score.
- Ablation, simple baselines, average-precision (PR-AUC), bootstrap uncertainty intervals, and a chronological development/validation/test split helper now exist as reproducible modules (`dtem.evaluation.ablation`, `.baselines`, `.metrics`, `.split`) and are emitted by the temporal backtest whenever predictions exist. They operate on whatever rows are supplied; on the current NVD-only exploratory data they are descriptive only and carry the same `exploratory_nvd_only` caveat. They are tooling, not validated results.
- The seven curated scenarios and simulated underground-feed records remain demonstration fixtures only.

## Data actually present

The successful public snapshot manifest is `data/historical/manifest_20261024T072650Z.json`, retrieved at 2026-10-24 07:26 UTC:

| Source | Records returned | Coverage and meaning |
|---|---:|---|
| NVD | 2,000 of 413,864 | Truncated current API response; retrieval time does not establish historical availability. |
| CISA KEV | 1,756 | Current catalog snapshot; no historical completeness sidecar for past cutoffs. |
| EPSS | 0 archived records in this snapshot set | No date-matched historical archive is present. |
| Timestamped CTI observation JSONL | 0 | No reproducible historical CTI capture archive is present. |

The saved backtest artifact `output/evaluation/historical_backtest.json` reports `insufficient_historical_coverage`, 0 predictions, and no metrics. It is not a completed historical performance evaluation. Historical alert events are also absent, so lead time is unavailable.

An initial workflow smoke sample was subsequently retrieved from the official FIRST historical API on 2026-10-24: one CVE (`CVE-2021-44228`), three requested/returned score dates (2024-01-01 through 2024-01-03), 3 observations, 0 request errors. It is stored as `data/historical/epss_history_2024-01-01_2024-01-03_20261024T094531Z.jsonl` with a companion manifest. This is a pipeline smoke sample, not a research cohort and not an experiment; it must not be used to claim model performance.

## Not implemented or still required for empirical publication claims

- Chronological development, validation, and held-out test periods over genuine historical observations. The split helper exists but no genuine multi-source observation cohort has been collected to populate it.
- Date-matched EPSS, simple frequency/growth/rule baselines, and fair same-CVE comparisons. The comparison runner now emits frequency/growth/diversity/exploit/CVSS/EPSS baselines on identical rows, but genuine date-matched EPSS coverage for a real cohort is still absent.
- PR-AUC, ablation studies, weight/threshold sensitivity on validation data, and uncertainty intervals. The computation modules now exist and are wired into the backtest, but have only been exercised on exploratory NVD-only data and are not yet run on a validated development cohort.
- A historical CTI archive with verifiable first-availability timestamps and an auditable KEV coverage sidecar.
- A prospectively or independently selected CVE cohort and a larger EPSS date range; the one-CVE smoke sample does not establish comparative validity.
- Persistent alert-event history sufficient to calculate event-to-first-alert lead time.
- A manuscript revision that removes unsupported 12-day/superiority statements and reports only verified results.

Do not claim that DTEM outperforms EPSS, predicts exploitation, or provides an early-warning lead time until these experiments have been completed on genuine, leakage-resistant data. KEV inclusion is a proxy catalog outcome; no inclusion is not evidence that exploitation did not occur.

## Reproduction and checks

```powershell
python -m pytest -q
node --check dtem/web/static/dashboard.js
git diff --check
python -m dtem.evaluation.research_pipeline collect
python -m dtem.evaluation.research_pipeline backtest --observations data/historical/observations.jsonl --kev data/historical/kev_snapshot.json --start 2024-01-01T00:00:00Z --end 2025-01-01T00:00:00Z
```

The final backtest command requires genuine archived observations and a KEV snapshot with a separately justified `.coverage.json` sidecar. Do not create either from current values or inferred dates.
