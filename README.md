# DTEM — Dynamic Threat Emergence Model

> **A research prototype for early identification of cyber threats using dark web threat intelligence.**

DTEM automatically collects Cyber Threat Intelligence from multiple public and simulated dark web sources, extracts emergence indicators, computes a dynamic Emergence Score, assesses risk, and generates early warning alerts — all from a single keyword search.

---

## Features

- **Automated CTI Collection** — Queries NVD, AlienVault OTX, and simulated dark web forums.
- **Emergence Indicators** — Detection Frequency, Growth Rate, Source Diversity, Exploit Availability.
- **Dynamic Scoring Engine** — Configurable weighted model producing an Emergence Score (0–100).
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

# 4. Seed the database with simulated dark web data
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

## Modules

| # | Module | Status |
|---|---|---|
| 1 | Threat Intelligence Collector | 🔨 In Progress |
| 2 | Threat Information Extractor | ⏳ Pending |
| 3 | DTEM Scoring Engine | ⏳ Pending |
| 4 | Risk Assessment | ⏳ Pending |
| 5 | Web Dashboard | ⏳ Pending |

---

## License

This project is for academic / research purposes (UROP).
