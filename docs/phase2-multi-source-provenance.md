# Phase 2 — Multi-source CTI acquisition: provenance, feasibility, and honest results

This document records what was actually acquired, how it is verifiable, and what
the evaluation showed. It follows the standing rule for this project: **no
multi-source superiority claim is made until genuinely independent,
historically verifiable, leakage-safe data is present; whatever the honest result
is — including a null — is reported.**

## 1. Source feasibility matrix

| Source | Independent timestamp verifiable? | Acquisition cost / limit | Reaches the KEV-positive cohort? | Decision |
|---|---|---|---|---|
| NVD CVE change history | Event `created` time only (no separate public-release time) | Free, ~6 req/min unauthenticated | Yes (it *is* the base cohort) | Kept as base; **single-source on its own** |
| CISA KEV git history | `dateAdded` per snapshot | Blobless clone, no API limit | It is the **label**, not a feature | Used only as outcome, never as an observation |
| FIRST EPSS history | `score_date` (day resolution) | Free API, 2000-char query cap | Baseline only | Used as a **baseline**, not a DTEM source |
| GitHub Security Advisories (GHSA) | `publishedAt` — true public time | 60 req/hr unauthenticated (403 at ~page 23); OSS-skewed | Partial / biased before a token was available | **Excluded from research claims**; importer kept for token-authenticated use |
| AlienVault OTX pulse search | `created` date | 403 without `OTX_API_KEY` | n/a | **Excluded** pending an API key |
| **Metasploit Framework git history** | **Module first-added commit date** (verifiable lower bound, never back-dated) | Blobless clone, reads git metadata only, **no API rate limit** | **Exploit-availability source; covers 251 CVEs** | **Adopted as the genuine second source** |

Why Metasploit: exploit-code availability is exactly the "public exploitation
signal" the redesign asked for, its timestamps come from the public commit graph
(re-verifiable), and enumeration needs no rate-limited API, so coverage is not
silently truncated the way unauthenticated GHSA was.

## 2. Provenance of the acquired multi-source cohort

Reproducible commands (run outside any network-restricted sandbox):

```text
git clone --filter=blob:none --no-checkout https://github.com/rapid7/metasploit-framework output/metasploit-framework
python -m dtem.evaluation.research_pipeline import-msf-history --repo output/metasploit-framework
python -m dtem.evaluation.research_pipeline merge-observations \
  --inputs data/historical/nvd_history_2025-01-24_2025-02-25_20261024T100459Z.jsonl \
           data/historical/metasploit_history_20261025T110330Z.jsonl \
  --output data/historical/multi_source_2025.jsonl
python -m dtem.evaluation.research_pipeline backtest \
  --observations data/historical/multi_source_2025.jsonl \
  --kev data/historical/kev_history_2025-01-24_2026-10-23_20261024T102753Z.jsonl \
  --start 2025-01-24 --end 2025-02-25 \
  --output output/evaluation/historical_backtest_multisource.json
```

Imported artefacts (each paired with a `.manifest.json` recording counts and the
timestamp policy):

- `metasploit_history_20261025T110330Z.jsonl` — **277** dated exploit events over
  **251** distinct CVEs, scanned from 5,871 added module files. `published_at` =
  `available_at` = the commit date the module first appeared (earliest add 2007,
  latest 2026-10-02). Coverage limit stated in the manifest: only modules whose
  **filename declares a CVE** are captured; product-named modules are missed and
  are *not* assumed absent.
- `multi_source_2025.jsonl` — **13,752** merged records, **0** duplicates dropped,
  per-source `{NVD: 13475, Metasploit: 277}`, **2** distinct sources, 10,532
  distinct CVEs.
- `historical_backtest_multisource.json` — full report (25,750 predictions).

## 3. What the evaluation actually showed

Report `status` flipped from `exploratory_nvd_only` to `completed`, and the
`source_independence_audit` now reports `distinct_sources: 2`,
`effective_independent_sources: 2`, `single_source_cohort: false`. The pipeline
correctly recognises a genuinely multi-source cohort. Concretely against the four
problems raised:

**Problem 2a — are frequency and growth collinear?** No. Over all 25,750 scored
rows Pearson r(frequency, growth) = **-0.0145**, r(frequency, diversity) = 0.17,
and **`near_collinear_pairs` is empty** at the 0.80 threshold. On this data the
two indicators are largely independent, contrary to the original concern.

**Problem 2b — is source diversity meaningless?** Partly fixed and honestly
bounded. Across the whole cohort `source_diversity` is **no longer constant**
(`constant_indicators: []`), so the indicator became well-defined. Ablation
confirms it now has a *non-zero* role only in the sense that removing it changes
PR-AUC by **+0.000004** (0.001051 → 0.001055) — i.e. it still adds effectively
nothing to ranking. The reason is decisive and must be stated plainly: **of the
17 positive CVE-cutoff instances, 0 have `source_diversity > 1` and only 1 has
any exploit evidence.** For the specific CVEs that CISA added to KEV within 30
days of a 2025 cutoff, no public Metasploit module (nor a second source record)
existed *before* that cutoff. The second genuine source exists in the data, but it
does not overlap the positives inside the strict horizon, so it cannot lift them.

**Problem 3 — do learned weights beat assumed weights?** Still no. The
dev-fit / val-select / test-once comparison returned
`verdict: frequency_only_matches_or_beats_learned`
(test `pr_auc_delta = -0.003666`). Learning is now exercised on a real two-source
feature set and it does **not** beat frequency-only on the untouched test period.

**Problem 4 — is the target too sparse?** Confirmed. Full-cohort PR-AUC 0.001051
vs random baseline 0.00066; precision-at-10%-budget 0.000777 with **2,035 ties**
at the cutoff; only **2/17** positives captured within the budget. 17 positives
across 25,750 rows is too thin for a positive claim.

Frequency and growth remain the only indicators that move PR-AUC when removed
(-0.000239 and -0.000279 respectively) — both tiny in absolute terms.

## 4. Limitations and validity caveats

- **Metasploit coverage is filename-declared CVEs only.** Product-named modules
  are missed; a CVE with an unnamed module looks un-exploited here. This biases
  exploit evidence *downward*, which is conservative but incomplete.
- **A commit date is an availability lower bound, not the disclosure date.** The
  module could have circulated beforehand; using the add-date never leaks
  future information but can lag real availability.
- **GHSA/OTX were excluded, not failed outright.** With a `GITHUB_TOKEN` /
  `OTX_API_KEY` their importers would yield unbiased cohort coverage; that coverage
  has **not** been obtained and therefore supports **no claim**.
- **Two source labels ≠ editorial independence.** NVD and Metasploit are distinct
  publishers, but the audit warns that label diversity alone does not prove
  independent reporting, and duplicate-content records were not removed from
  scoring.
- **KEV is a proxy outcome, not exploitation onset**; non-KEV rows are not
  confirmed negatives.
- **Recurring CVEs across cutoffs break sample independence**, so the bootstrap
  intervals are optimistic.

## 5. Bottom line for the manuscript

Acquiring a genuinely independent, verifiably dated, leakage-safe second source is
**now demonstrated** and the evaluation correctly detects multi-source input. On
this real data, however, **DTEM's extra indicators do not earn their complexity**
for the KEV-within-30-days task: source diversity is non-constant but covers none
of the positives inside the horizon, learned weights do not beat frequency-only on
the test period, and the positive class remains too sparse for a significant
claim. This is reported as the pre-registered acceptance signal failing — a
honest null — rather than a demonstration of DTEM superiority. The next legitimate
step to change that outcome (not to re-frame it) is broader verifiable coverage of
the positives: token-authenticated GHSA/OTX, or exploit sources that date signals
closer to KEV additions.
