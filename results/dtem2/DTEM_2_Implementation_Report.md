# DTEM 2.0 Implementation Report

## Files created

- `dtem2/__init__.py`
- `dtem2/features.py`
- `dtem2/scoring.py`
- `dtem2/experimental_pipeline.py`
- `dtem2/__main__.py`
- `test_dtem2.py`

## What changed

- Added a separate, experimental DTEM 2.0 package without modifying the original DTEM 1.0 implementation.
- Added historical eligibility checks to block future records.
- Added recency-weighted frequency, smoothed growth, and evidence-aware diversity calculations.
- Added a scoring engine and an experimental pipeline that reads the saved historical backtest and emits comparison outputs.

## Validation performed

- `python -m pytest -q test_dtem2.py` -> 5 passed
- `python -m pytest -q test_research_evaluation.py` -> 20 passed

## Result

On the archived historical artifact, DTEM 2.0 did not beat the original DTEM 1.0 score or the frequency-only baseline. The evidence suggests the current cohort is too sparse and source-limited to support a proven improvement claim.
