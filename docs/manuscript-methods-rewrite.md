# DTEM — Methods/Framework paper rewrite

Target framing: **a leakage-safe methodology and evaluation framework for a
CVE vulnerability-emergence scoring model.** The contribution is the *design and
its reproducibility/anti-leakage properties*, **not** a benchmark accuracy number.
Every figure below is taken from a genuine artifact produced by the prototype
(`output/evaluation/*.json`, `data/historical/*.manifest.json`). Nothing is
simulated or inferred. Predictive-performance and dark-web-superiority claims are
removed.

---

## Suggested revised title

> **DTEM: A Leakage-Safe Evaluation Framework for Vulnerability-Emergence
> Scoring from Public Threat Intelligence**

Drop "Dark Web" from the title: the underground-intelligence layer is simulated
and not empirically validated (reviewer Critical #4).

---

## Abstract (replacement)

Early identification of exploitable vulnerabilities from threat intelligence is
usually evaluated on small, manually curated scenario sets that cannot support
generalisation claims. This paper presents the Dynamic Threat Emergence Model
(DTEM), a transparent, configurable scoring prototype for **vulnerability
emergence at the level of individual CVEs**, together with a **leakage-safe
evaluation framework** for retrospectively scoring such models against future,
verifiable exploitation outcomes. The framework reconstructs what information was
publicly available at each historical observation cutoff, labels each
CVE-cutoff instance by subsequent inclusion in the CISA Known Exploited
Vulnerabilities (KEV) catalogue within a fixed horizon, and compares DTEM against
date-matched EPSS, CVSS severity, and simple frequency/growth baselines on
identical rows. We make the model mathematically reproducible: every indicator
has an explicit normalisation, boundary condition, and missing-data rule, and we
provide leave-one-out ablation, threshold and parameter-sensitivity, PR-AUC with
bootstrap uncertainty, and a chronological development/validation/held-out-test
split.

We report **verified** outcomes and are explicit about their limits. On seven
curated scenarios DTEM acts as an implementation check (prototype verification),
not evidence of predictive skill. On a genuine historical cohort of 25,280
CVE-cutoff observations derived from NVD change history with 17 future KEV
additions, DTEM's average precision is 0.0015 (95% bootstrap CI 0.0005–0.0080)
against a base rate of 0.0007; because NVD change events are database-workflow
activity rather than independent threat-intelligence detections, this run
validates the *pipeline*, not the *predictive model*. Two further backtests on
insufficiently covered archives correctly return zero predictions rather than
fabricated metrics, demonstrating the framework's leakage guards. We therefore
contribute a reproducible, honest evaluation methodology and reference
implementation, and identify the timestamped multi-source CTI cohort required to
turn it into a predictive-validity study.

---

## Contributions (as to be listed after the introduction)

1. A **fully specified, reproducible emergence model** for individual CVEs:
   complete indicator equations, normalisation table, boundary conditions, and
   documented missing-data behaviour (no score is emitted without eligible
   evidence).
2. A **leakage-safe retrospective evaluation protocol**: per-cutoff availability
   filtering, exact-CVE association, a KEV-horizon outcome label, and a strict
   rule that a dated score (e.g. EPSS) is usable only if its date precedes the
   cutoff.
3. A **fair-comparison harness** that scores DTEM, date-matched EPSS, CVSS
   severity, and simple frequency/growth/diversity/exploit baselines on the
   *same* rows and labels, with leave-one-out ablation, threshold/parameter
   sensitivity, average precision with bootstrap intervals, and a chronological
   development/validation/test split.
4. An **honest empirical status report**: prototype verification on curated
   scenarios and a pipeline-validating (not model-validating) historical run,
   plus negative results showing the framework refuses to report metrics without
   sufficient, leakage-safe coverage.

---

## Section IV — Evaluation (full replacement)

### IV-A. Unit of analysis and outcome definition

The evaluation unit is one **exact CVE identifier**; other entities (malware
families, threat actors) are excluded from scoring because they have no single
corresponding CVSS. A CVE-cutoff instance is **positive** when the CISA KEV
`dateAdded` falls strictly after the cutoff and within a 30-day horizon. KEV
inclusion is a *catalogue proxy*, not confirmed exploitation; non-inclusion is
**not** a negative label of "unexploited". An observation is eligible at a
cutoff only when its `available_at` and `published_at` timestamps are both at or
before the cutoff; a dated baseline score is eligible only for its own earlier
date. Empty evidence yields `insufficient_data` and **no** numeric score.

> **Note (preregistration).** The 30-day horizon and the 50-point alert threshold
> are stated design defaults, selected on the prototype, not tuned on the held-out
> historical period. They must be fixed before any future confirmatory test.

### IV-B. Datasets and provenance

All archives are retrieved from official sources; retrieval time never substitutes
for historical availability.

| Dataset | Contents | Coverage | Role |
|---|---:|---|---|
| NVD CVE Change History API v2.0 | 13,475 timestamped change events / 10,343 CVEs | 2025-01-24 → 2025-02-25 | Single-source workflow signal (proxy availability via event `created`) |
| CISA KEV versioned history (`cisagov/kev-data` Git mirror) | 1,768 catalog state events (1,760 additions) over 330 intact snapshots; 1 malformed commit recorded in manifest | 2025-01-24 → 2026-10-23 | Future-event label source |
| FIRST EPSS historical API | 1 CVE (`CVE-2021-44228`), 3 dated scores, 0 errors | 2024-01-01 → 2024-01-03 | Pipeline smoke sample (does **not** overlap the cohort) |
| NVD current snapshot / KEV current feed | 2,000 of 413,864 CVEs (truncated) / 1,756 KEV entries | retrieved 2026-10-24 | Live-prototype inputs; not backfilled as history |

### IV-C. Prototype verification on curated scenarios

Table III (revised) reports an **implementation check**, explicitly not a
predictive-performance estimate.

| Scenario set | Samples | Class balance | Default-weight F1 | Grid-search best in-sample F1 |
|---|---:|---|---:|---:|
| Curated scenarios | 7 | 4 positive / 3 negative | 1.00 | 1.00 (over 1,771 weight combinations) |

A perfect F1 on seven author-labelled examples reflects how those examples were
constructed and is reported only to confirm the scoring engine behaves as
specified. It is **not** evidence of generalisation.

### IV-D. Historical pipeline run (validates the method, not the model)

Running the framework on the genuine NVD-change cohort:

- **Rows / support:** 25,280 CVE-cutoff predictions across 9,591 CVEs; **17**
  positives (12 unique CVEs) inside a fully covered 30-day KEV horizon; base rate
  0.067 %.
- **Threshold metrics at 50:** TP = 0, FP = 6, FN = 17, TN = 25,257.
- **Ranking metric:** average precision **0.0015**, 95 % bootstrap CI
  **[0.0005, 0.0080]**, random/prevalence baseline **0.0007**. The confidence
  interval overlaps the base rate, so no separation is demonstrated.
- **Fair comparison:** the harness emits CVSS-severity and frequency/growth/
  diversity/exploit baselines on the identical rows, plus leave-one-out ablation
  and a chronological development/validation/test split (7,584 / … / 9,591 rows),
  flagging 8,105 CVEs that recur across periods as an independence caveat.
- **Status label:** `exploratory_nvd_only`.

Interpretation: NVD change events are one-source database-workflow activity, not
independent CTI detections, and the same CVEs repeat at adjacent cutoffs. This run
confirms that the **end-to-end evaluation pipeline executes correctly and resists
leakage**; it does **not** establish that DTEM predicts exploitation.

### IV-E. Negative results that demonstrate leakage safety

Two backtests over archives that do not fully cover the required horizons return
**0 predictions** and **no metrics** (`insufficient_historical_coverage`) instead
of emitting numbers from partial or forward-filled data. We report these as
evidence that the framework's availability and coverage guards fail closed.

### IV-F. Threats to validity

- KEV inclusion proxies catalogue action, not exploitation onset; negatives are
  undefined by design.
- The only historical "CTI-like" stream currently archived is NVD workflow
  activity; genuine multi-source CTI with first-availability timestamps is absent.
- EPSS coverage is a single-CVE smoke sample and does not overlap the cohort, so
  no valid DTEM-vs-EPSS comparison is reported.
- Weights (0.25/0.30/0.20/0.25) and the 60:40 composite are documented design
  choices, not empirically optimal values; the smoothed log-growth transform is a
  specified candidate, not a fitted parameter.

---

## Claims removed relative to the previous draft

| Original claim | Reviewer item | Action |
|---|---|---|
| F1 = 1.00 as model performance | #1 | Recast as *prototype verification on 7 curated scenarios*; no generalisation implied |
| "12-day early-warning advantage" over EPSS | #2 | **Removed.** Lead time is emitted only when a real historical alert precedes a labelled future event |
| Fixed 19-day hardcoded lead time / Table III sign inconsistency | #2 | **Removed**; timeline returns `no_timestamped_outcome` |
| Exploit keyword match ⇒ ≥70 sub-score | #3, Math B | Replaced by ordinal evidence hierarchy (25/50/75/100) with negative-context guards |
| Growth equation undefined at P = 0 | #3, Math A | Explicit zero/missing handling + bounded, fully specified smoothed log-growth candidate |
| "Dark-web" detection validated | #4 | Title/claims revised; underground layer described as **simulated**, excluded from scoring |
| DTEM outperforms CVSS/EPSS/KEV | #5 | Reframed as a **fair-comparison harness**; superiority not claimed pending real cohort |

---

## What must still be added before this can become a performance paper

1. A prospectively selected CVE cohort with timestamped public CTI (exact-CVE
   association, first-availability timestamps, collection-delay and duplicate
   accounting).
2. Date-matched EPSS across that cohort with model-version stratification.
3. Preregistered horizon/threshold, chronological development/validation/test
   execution, and weight selection confined to development.
4. Persistent alert history to compute real event-to-first-alert lead time with
   missed/false-alert accounting.

Until then the paper's contribution is the **leakage-safe methodology and
reference implementation**, and this document's phrasing should be used verbatim
so that the claims match the evidence.
