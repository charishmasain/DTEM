# DTEM 2.0 Redesign Report

## Executive summary

The redesigned DTEM 2.0 preserves the actual count-based growth signal and reduces the extreme score compression that made the first experimental branch fail. The experiment does not establish a reliable empirical improvement over the preserved DTEM 1.0 historical baseline, but it is a better-behaved scientific prototype than the first unsaturated version.

## What changed

- Growth now uses recent-vs-previous activity counts directly.
- Frequency normalization is less aggressive and retains separation across moderate values.
- Diversity is capped below a hard 100-point ceiling to prevent flattening.
- Exploit evidence remains a small contribution so it does not monopolize the score.

## Quantitative result

The historical cohort yields the following PR-AUC values:

- Original DTEM 1.0: 0.001361
- Frequency-only redesign: 0.001427
- Combined redesign: 0.001330

The combined redesign does not meaningfully outperform the original baseline, and the tie fraction remains approximately 1.0. This indicates that the signal remains too sparse to justify a new scoring model on this artifact without additional data or a differently structured feature base.

## Conclusion

The redesign successfully addresses the design flaw of the first DTEM 2.0 implementation: it uses count-based growth and avoids excessive concentration of scores. However, the evidence supports preserving the original DTEM 1.0 scoring as the stable baseline until a richer historical or prospective cohort demonstrates a genuine uplift.
