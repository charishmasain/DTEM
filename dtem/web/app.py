"""
dtem.web.app
~~~~~~~~~~~~

FastAPI web application and API endpoints for the DTEM prototype.

Provides:
  - Modern web dashboard (`GET /`)
  - Full REST API analysis endpoint (`GET /api/analyze?keyword=...`)
  - Stored intelligence query endpoint (`GET /api/intel?keyword=...`)

Run directly:
    uvicorn dtem.web.app:app --reload --port 8000
"""

import logging
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dtem.collector.manager import CollectorManager
from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.risk.assessment import RiskAssessmentEngine
from dtem.data.database import fetch_intel_for_keyword, init_db
from dtem.data.seed_data import seed_database
from dtem.evaluation.backtester import run_timeline_backtest_for_api

logger = logging.getLogger(__name__)

# Setup directory paths
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

# Instantiate FastAPI app
app = FastAPI(
    title="DTEM — Dynamic Threat Emergence Model",
    description="Research prototype for early identification of cyber threats using Dark Web CTI",
    version="0.1.0",
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Pipeline component singletons
collector_manager = CollectorManager()
extractor = ThreatInfoExtractor(recent_window_days=14)
scoring_engine = DTEMScoringEngine()
risk_engine = RiskAssessmentEngine()


@app.on_event("startup")
def startup_event():
    """Ensure database schema is ready and pre-seeded on startup."""
    init_db()
    seed_database(force=False)
    logger.info("DTEM web application started successfully.")


@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    """Render the main DTEM dashboard UI."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/analyze")
async def analyze_threat(keyword: str = Query(..., min_length=1, description="Threat search keyword")):
    """
    Run full DTEM pipeline for a search keyword:
      User Search -> Collector -> Extractor -> DTEM Model -> Risk Engine -> Output
    """
    keyword_clean = keyword.strip()

    # Step 1: Collect (if not present)
    collected = collector_manager.collect(keyword_clean)

    # Step 2: Extract Features
    features = extractor.extract_features(keyword_clean, auto_collect=False)

    # Step 3: Compute Emergence Score & Stage
    emergence = scoring_engine.calculate_emergence(features)

    # Step 4: Compute Composite Risk & Early Warning
    risk_assessment = risk_engine.assess_risk(emergence)

    # Fetch stored CTI records for table
    db_records = fetch_intel_for_keyword(keyword_clean)

    # Step 5: Run timeline backtest for baseline comparison
    timeline_backtest = run_timeline_backtest_for_api(keyword_clean)

    return JSONResponse({
        "keyword": keyword_clean,
        "emergence": emergence,
        "risk": risk_assessment,
        "features": features,
        "collected_intel": db_records,
        "timeline_backtest": timeline_backtest,
    })


@app.get("/api/intel")
async def get_stored_intel(keyword: str = Query(...)):
    """Fetch stored intelligence records for a threat keyword."""
    records = fetch_intel_for_keyword(keyword.strip())
    return JSONResponse({
        "keyword": keyword,
        "total_records": len(records),
        "records": records,
    })
