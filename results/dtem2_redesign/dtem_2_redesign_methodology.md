# DTEM 2.0 Redesign Methodology

## Goal

The redesign target was narrow and evidence-driven: preserve the useful ranking information in the historical feature set while eliminating the main failure mode from the first experimental CTEM 2.0 branch, namely aggressive saturation and score collapse.

## Design changes

1. Count-based growth signal
   - Use the actual recent and previous activity counts, not a generic percentage transform.
   - Compute the log-ratio using the smoothed form:
   - $G = \log\left(\frac{R + \alpha}{P + \alpha}\right)$
   - where $R$ is recent activity, $P$ is previous activity, and $\alpha = 1$.

2. Less aggressive frequency scaling
   - Frequency was bounded with a logarithmic map, but the cap was deliberately chosen to keep mid-range frequencies distinguishable rather than squeezing them into a single plateau.

3. Source diversity normalization
   - The source-diversity term was scaled to remain informative across a 1-, 2-, and 3-source profile without forcing all three-source examples to a complete 100 score.

4. Exploit evidence calibration
   - Exploit evidence contributes only a small share of the overall aggregate and is bounded to avoid dominating a sparse positive set.

## Scientific constraint

This redesign does not tune against the historical test labels. The same saved cohort and eligibility rules are used to evaluate the modification. The purpose is to preserve ranking information in a principled way, not to chase a favourable metric by repeated optimization.

## Interpretation

Even with the improved count-based growth and reduced saturation, the empirical result remains below a decisive improvement threshold. The main reason is the cohort sparsity: only 33 positives among 36,274 predictions. That setting naturally limits any ranking model’s ability to separate signal from noise, especially when most features are zero or near-zero.
