# DTEM 2.0 Methodology

## Indicators

DTEM 2.0 retains the four conceptual indicators from DTEM 1.0:

1. Detection Frequency
2. Growth Rate
3. Source Diversity
4. Exploit Availability

## Improved calculations

### Detection frequency

The experimental implementation uses a recency-weighted activity score:

F(t) = sum(exp(-lambda * (t - t_i)))

with lambda chosen by the half-life parameter and a bounded log-saturation transform.

### Growth rate

The experimental growth indicator uses a smoothed log-growth transform:

G(t) = log((R(t) + alpha) / (P(t) + alpha))

where alpha defaults to 1.0.

### Source diversity

Source diversity is quality-aware instead of a bare count. Duplicate records and overlapping evidence are down-weighted to avoid treating correlated reporting as independent corroboration.

### Exploit availability

Exploit evidence remains a weighted ordinal signal, but it is carried forward only when the evidence is historically available by the cutoff.

## Scoring

The experimental weighted score is:

S = 0.30 * F + 0.25 * G + 0.20 * D + 0.25 * E

with all sub-scores bounded to 0..100 before aggregation.

## Audit principle

This implementation is separate from DTEM 1.0 and is intended for experimental comparisons only. It must not be treated as a validated production model unless it demonstrates improvement on genuinely unseen data and a leakage-safe, multi-source cohort.
