# Frequency + Diversity Holdout Evaluation

## Evaluation protocol

This check was designed to answer a single question: does the frequency + diversity hypothesis survive an independent evaluation?

The historical backtest was split chronologically into development, validation, and test periods. Candidate weights for the frequency + diversity combination were selected using the development and validation sets only. The test set was then evaluated once, without tuning.

## Result

Selected weights:

- Frequency: 0.4
- Diversity: 0.6

Selection metrics:

- Development PR-AUC: 0.001281
- Validation PR-AUC: 0.002605

Untouched test evaluation:

- Frequency + diversity PR-AUC: 0.001519
- Original DTEM PR-AUC: 0.001551

Absolute difference:

- Frequency + diversity minus original DTEM: -0.000032

## Interpretation

The earlier pooled-backtest improvement is not reproduced under an independent, leakage-safe evaluation. The simple frequency + diversity model is slightly worse than the original DTEM on the untouched test period, which means the hypothesis does not yet justify a final DTEM 2.0 redesign.

This evidence should determine the final design. The next step is not another broad redesign; it is either a smaller, evidence-driven feature set or a decision to retain the original DTEM baseline unless a richer future cohort demonstrates genuine signal.
