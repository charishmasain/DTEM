# DTEM 2.0 Scoring Diagnostics

## Root cause

The historical backtest remains a sparse, highly imbalanced dataset: 36,274 rows, 33 positive labels, and 36,241 negatives. The key failure mode was not simply a weak numeric transform; it was a collapse of ranking information.

The saved artifact shows the original DTEM 1.0 scores are highly tied: the tie fraction is 0.999283, which means nearly every row shares a score with many others. This is the central scientific problem. When the score distribution collapses, precision-recall ranking is effectively dominated by input ordering rather than genuine signal.

## Feature-level evidence

The raw historical features are dominated by sparse frequency counts, with `detection_frequency` ranging from 1 to 14 and a median of 1. The `source_diversity` variable is only 1, 2, or 3, and `exploit_evidence_score` is zero for roughly 92% of rows. This means the model is operating in a regime where the ranking signal is almost entirely driven by a few positive outliers.

The redesign therefore targets count-based growth rather than a generic bounded growth transform. The key scientific fix is to preserve the difference between recent and previous counts directly, while avoiding a full-score saturation that destroys ordering.

## Diagnostic result

The redesigned score remains highly saturated on the historical cohort:

- Original DTEM 1.0 PR-AUC: 0.001361
- Frequency-only redesign PR-AUC: 0.001427
- Growth-only redesign PR-AUC: 0.000910
- Combined redesign PR-AUC: 0.001330

This shows the redesign is closer to the original baseline than the first experimental DTEM 2.0 branch, but it still does not establish a statistically defensible improvement on the historical artifact. The tie fraction for the redesigned score remains effectively 1.0, showing that the historical alert set is too sparse and too imbalanced for a stable score calibration signal.

## Decision

The redesign is scientifically preferable to the first DTEM 2.0 attempt because it uses actual recent-vs-previous counts and avoids aggressive saturation. However, the data itself still prevents high-confidence rank separation. The evidence supports preserving the original DTEM 1.0 historical baseline unless a future cohort provides a richer positive signal or a better calibrated feature set.
