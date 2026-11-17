# DTEM — Dynamic Threat Emergence Model

> A CTI-based vulnerability emergence scoring prototype. It is not validated as a real-world forecasting system and does not provide real-time underground-source surveillance.

DTEM can collect current records from supported public feeds, extract emergence indicators, and display a prototype score for a keyword or CVE. It does not provide live underground-source surveillance or validated real-world prediction. Simulated dark-web records are demonstration-only and are excluded from normal scoring.

---

## Features

- **CTI Collection** — Queries public NVD and AlienVault OTX sources; the dark-web simulator supplies clearly labeled prototype-only records.
- **Emergence Indicators** — Detection Frequency, Growth Rate, Source Diversity, Exploit Availability.
- **Dynamic Scoring Engine** — Configurable weighted model producing an Emergence Score (0–100) when eligible evidence exists; otherwise the dashboard reports that the score is unavailable.
- **Risk Assessment** — Maps emergence to Risk Score (Low / Medium / High / Critical) and Threat Priority.
- **Early Warning Alerts** — Natural-language reasoning explaining why a threat is escalating.
- **Interactive Dashboard** — FastAPI + Jinja2 dashboard with search, charts, and timelines.

---

## Project Structure

```
DTEM UROP/
├── requirements.txt
├── README.md
└── dtem/
    ├── config.json
    ├── data/          # Database schema, seed data
    ├── collector/     # CTI collectors (NVD, OTX, Dark Web)
    ├── extractor/     # Emergence indicator extraction
    ├── model/         # DTEM scoring engine
    ├── risk/          # Risk assessment
    └── web/           # FastAPI dashboard
```

---

## Installation

```bash
# 1. Clone the repository
git clone <repo-url>
cd "DTEM UROP"

# 2. Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Optional: load clearly labeled prototype demonstration data
#    Demo records are excluded from normal dashboard scores and monitoring.
python -m dtem.data.seed_data

# 5. Run the collector test
python test_collector.py
```

---

## Usage

### Run the collector from Python

```python
from dtem.collector.manager import CollectorManager

manager = CollectorManager()
results = manager.collect("LockBit")

for item in results:
    print(f"[{item['source']}] {item['title']}")
```

### Run the dashboard (available after Module 5)

```bash
uvicorn dtem.web.app:app --reload
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| API | FastAPI + Uvicorn |
| Templates | Jinja2 |
| Database | SQLite |
| Analysis | Pandas, NumPy |
| Visualization | Matplotlib, Chart.js |
| HTTP Client | Requests, BeautifulSoup4 |

---

## Research evaluation status

The seven curated scenarios and dark-web posts are simulated prototype data, not historical predictive evidence. See [docs/research-methodology.md](docs/research-methodology.md) for indicator equations, CVE matching and cutoff rules, KEV outcome definition, missing-data handling, and the limits of the current dataset. The `dtem.evaluation.historical` module contains exact-CVE matching, timestamp cutoff, KEV label, and lead-time helpers. No historical performance claims are supported until a sufficiently covered, outcome-independent set of timestamped CTI observations, date-matched EPSS scores, and verified KEV outcomes are available. The pipeline below stores current public snapshots with retrieval-time manifests; these do not establish past availability.

Additional genuine historical files are now archived under `data/historical/`. The NVD History API window (2025-01-24 through 2025-02-25) contains 13,475 timestamped database change events across 10,343 CVEs. NVD's event-created time is used as an earliest-availability proxy; exact public availability is not separately provided by the API. The official CISA KEV Git mirror import covers intact catalog snapshots from 2025-01-24 through 2026-10-23, with 1,768 catalog state events; its manifest records one malformed source commit. The three-score EPSS smoke sample is for one CVE in January 2024 and does not overlap the historical NVD cohort. These inputs support pipeline demonstration, not a publishable performance claim: NVD updates are database workflow activity rather than independent CTI detections, and there is no historical CTI availability dataset.

The NVD-only exploratory backtest has four weekly cutoffs and 25,280 CVE-cutoff rows (9,591 CVEs), with 17 subsequent KEV additions across 12 unique CVEs. At the existing DTEM threshold of 50 it yields TP=0, FP=6, FN=17, TN=25,257. The output is explicitly labeled `exploratory_nvd_only` in `output/evaluation/option_a_nvd_only_exploratory.json`. Do not interpret it as multi-source DTEM validation: it lacks CTI evidence, a chronological development/validation/test split, matched EPSS scores, ablations, threshold sensitivity, uncertainty analysis, and genuine prior DTEM alert events. Consequently, no predictive-validity or lead-time claim is supported.

The evaluation comparison layer is now implemented as reproducible tooling: average precision (PR-AUC) with a bootstrap interval, leave-one-out and single-indicator ablations, threshold and log-growth-scale sensitivity, simple frequency/growth/diversity/exploit/CVSS/EPSS baselines scored on the identical rows DTEM uses, and a chronological development/validation/test split (`dtem.evaluation.metrics`, `.ablation`, `.baselines`, `.split`). The temporal backtest emits all of them whenever predictions exist. They are computation tooling, not proof: run on the current NVD-only exploratory cohort they are descriptive, keep the `exploratory_nvd_only` label, and do not become a validated result until they run on genuine, leakage-safe, both-class CTI observations. Run `python -m pytest test_research_evaluation.py` to exercise this layer.

### Research data and backtest commands

```powershell
# Current NVD and CISA KEV snapshots; saves raw responses and provenance manifests
python -m dtem.evaluation.research_pipeline collect

# Current date-stamped EPSS scores for selected CVEs (not historical backfill)
python -m dtem.evaluation.research_pipeline epss CVE-2024-3400 CVE-2024-3094

# Actual dated EPSS history for a pre-defined CVE cohort (inclusive dates)
python -m dtem.evaluation.research_pipeline epss-history `
  --cves-file data/historical/cohort_cves.txt `
  --start 2024-01-01 --end 2024-12-31

# Timestamped NVD CVE change events (public NVD History API)
python -m dtem.evaluation.research_pipeline nvd-history `
  --start 2025-01-24 --end 2025-02-25

# Import versioned KEV history from a local clone of CISA's official mirror
git clone https://github.com/cisagov/kev-data data/source/kev-data
python -m dtem.evaluation.research_pipeline import-kev-history `
  --repo data/source/kev-data

# Reproduce the archived NVD-only exploratory run from its saved inputs
python -m dtem.evaluation.research_pipeline backtest `
  --observations data/historical/nvd_history_2025-01-24_2025-02-25_20261024T100459Z.jsonl `
  --kev data/historical/kev_history_2025-01-24_2026-10-23_20261024T102753Z.jsonl `
  --start 2025-01-24 --end 2025-02-25 `
  --output output/evaluation/option_a_nvd_only_exploratory.json

# Requires an archived timestamped observations JSONL and KEV snapshot with coverage metadata
python -m dtem.evaluation.research_pipeline backtest `
  --observations data/historical/observations.jsonl `
  --kev data/historical/kev_snapshot.json `
  --epss-history data/historical/epss_history_2024-01-01_2024-12-31_TIMESTAMP.jsonl `
  --start 2024-01-01T00:00:00Z --end 2025-01-01T00:00:00Z
```

The `epss-history` command queries FIRST's historical score API by date and CVE cohort, saves returned values as JSONL, and writes a retrieval/error manifest. Scores retain their actual `score_date`; missing CVE/date values are not imputed. The backtest uses only the latest score whose date is strictly before the cutoff's UTC calendar date. The NVD-history API applies a 6-second default delay between unauthenticated requests. The KEV importer emits coverage intervals and error provenance; gaps are not treated as negative outcomes. Define the CVE cohort independently of future outcomes before collecting and evaluating it. A publishable Option A evaluation still requires timestamped public CTI linked to CVEs, sufficiently long outcome coverage, actual date-matched EPSS, predeclared chronological development/validation/test periods, and alert logs for lead-time analysis.

For NVD rate limits, set `NVD_API_KEY` in the environment. Never store credentials in source/configuration. A KEV completeness assertion belongs in `kev_snapshot.json.coverage.json` with a genuine `complete_through` date; a current feed without archived completeness metadata cannot support historical negative labels.

## Monitoring prototype demonstration

Run `uvicorn dtem.web.app:app --reload --port 8000`, open `http://127.0.0.1:8000/`, add a CVE or threat keyword to the watchlist, and use **Analyze** to store an initial score snapshot. Use **Start monitoring** for periodic NVD and OTX checks, **Run once** for an immediate cycle, or **Stop** to halt polling. Monitoring is opt-in, polls only configured public collectors, and does not include the dark-web simulator. Set `NVD_API_KEY` and optionally `OTX_API_KEY` in the environment; the app can run without either key.

The overview uses persisted analyses and records. Threshold crossings and configured significant score increases create SQLite alerts; users can acknowledge or resolve them. **History** shows only persisted score snapshots, and **Report** opens a printable report. New installs show empty history until analyses run. Settings and watchlist are stored in SQLite. Export JSON or CSV from the dashboard links or `/api/export`. Do not interpret the score, heuristic exploit tier, or public-feed monitoring as proof of active exploitation or complete real-time coverage.

## DTEM 2.0 experimental branch

The DTEM 2.0 implementation is kept separate from the original DTEM 1.0 baseline and lives under `dtem2/`.

```powershell
# Validate the experimental leakage and scoring contract
python -m pytest -q test_dtem2.py

# Preserve the original historical evaluation baseline
python -m pytest -q test_research_evaluation.py

# Run the experimental DTEM 2.0 comparator on the archived historical backtest
python -m dtem2 --backtest output/evaluation/historical_backtest_3way.json --output-dir results/dtem2
```

The DTEM 2.0 output directory contains the experimental metrics and CSV exports under `results/dtem2/`.

---

## License

This project is for academic / research purposes (UROP).
