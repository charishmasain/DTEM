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
import csv
import html
import io
import json
import re
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from dtem.collector.manager import CollectorManager
from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.risk.assessment import RiskAssessmentEngine
from dtem.data.database import (
    add_watchlist_item, fetch_intel_for_keyword, fetch_recent_intel,
    get_setting, get_snapshot_history, init_db, latest_monitoring_run,
    latest_successful_monitoring_run,
    list_alerts, list_watchlist, record_analysis, remove_watchlist_item,
    set_setting, set_watchlist_enabled, update_alert,
)
from dtem.evaluation.backtester import run_timeline_backtest_for_api
from dtem.monitoring import monitoring_status, run_monitoring_cycle, start_monitoring, stop_monitoring

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
    """Ensure schema is ready; do not inject synthetic demonstration records."""
    init_db()
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
    collected = collector_manager.collect(keyword_clean, include_sources={"NVD", "AlienVault OTX"})

    # Step 2: Extract Features
    features = extractor.extract_features(keyword_clean, auto_collect=False, include_prototype=False)

    # Step 3: Compute Emergence Score & Stage
    emergence = scoring_engine.calculate_emergence(features)

    # Step 4: Compute Composite Risk & Early Warning
    risk_assessment = risk_engine.assess_risk(emergence)

    model_cfg = json.loads((Path(__file__).resolve().parents[1] / "config.json").read_text(encoding="utf-8"))
    defaults = model_cfg.get("monitoring", {})
    threshold = float(get_setting("alert_threshold", str(defaults.get("alert_threshold", 65))))
    increase_threshold = float(get_setting("significant_score_increase", str(defaults.get("significant_score_increase", 10))))
    minimum_risk = get_setting("minimum_alert_risk", str(defaults.get("minimum_alert_risk", "Low")))
    if emergence.get("score_status") == "insufficient_data":
        snapshot_id, generated_alerts = None, []
    else:
        snapshot_id, generated_alerts = record_analysis(
            keyword_clean, features, emergence, risk_assessment,
            threshold=threshold, increase_threshold=increase_threshold, minimum_risk_level=minimum_risk,
        )

    # Fetch stored CTI records for table
    db_records = fetch_intel_for_keyword(keyword_clean)
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", keyword_clean, re.IGNORECASE):
        db_records = [record for record in db_records
                      if extractor._record_mentions_cve(record, keyword_clean)]

    # Step 5: Run timeline backtest for baseline comparison
    timeline_backtest = run_timeline_backtest_for_api(keyword_clean)

    return JSONResponse({
        "keyword": keyword_clean,
        "emergence": emergence,
        "risk": risk_assessment,
        "features": features,
        "collected_intel": db_records,
        "timeline_backtest": timeline_backtest,
        "snapshot_id": snapshot_id,
        "generated_alerts": generated_alerts,
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


@app.get("/api/dashboard")
async def dashboard_data(days: int | None = Query(None, ge=1, le=3650), cve: str | None = None,
                         category: str | None = None, risk_level: str | None = None,
                         source: str | None = None, sort: str = Query("risk", pattern="^(risk|emergence|name)$")):
    """Return dashboard metrics from persisted watchlist, snapshots, alerts and records."""
    watchlist = list_watchlist()
    threats = []
    for item in watchlist:
        history = get_snapshot_history(item["keyword"], 2)
        latest = history[-1] if history else None
        previous = history[-2] if len(history) > 1 else None
        threat = {**item, "latest": latest,
                  "score_delta": round(latest["emergence_score"] - previous["emergence_score"], 2)
                  if latest and previous else None}
        threats.append(threat)
    if cve:
        needle = cve.strip().lower()
        threats = [t for t in threats if needle in t["keyword"].lower()]
    if category:
        threats = [t for t in threats if t["category"].lower() == category.lower()]
    if risk_level:
        threats = [t for t in threats if t["latest"] and str(t["latest"]["risk_level"]).lower() == risk_level.lower()]
    if days:
        from datetime import datetime, timedelta, timezone
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        threats = [t for t in threats if t["latest"] and datetime.fromisoformat(t["latest"]["analyzed_at"].replace("Z", "+00:00")) >= cutoff]
    if source:
        threats = [t for t in threats if fetch_intel_for_keyword(t["keyword"]) and
                   any(r.get("source") == source for r in fetch_intel_for_keyword(t["keyword"]))]
    key = (lambda t: t["keyword"]) if sort == "name" else (lambda t: t["latest"]["emergence_score"] if t["latest"] and sort == "emergence" else t["latest"]["risk_score"] if t["latest"] and t["latest"]["risk_score"] is not None else -1)
    threats.sort(key=key, reverse=sort != "name")
    full = [t for t in threats if t["latest"]]
    distribution: dict[str, int] = {}
    for threat in full:
        level = threat["latest"].get("risk_level") or "Unknown"
        distribution[level] = distribution.get(level, 0) + 1
    import json as json_module
    monitor_cfg = json_module.loads((Path(__file__).resolve().parents[1] / "config.json").read_text(encoding="utf-8")).get("monitoring", {})
    rise_threshold = float(get_setting("significant_score_increase", str(monitor_cfg.get("significant_score_increase", 10))))
    recent = fetch_recent_intel(20, source=source)
    return JSONResponse({
        "threats": threats,
        "overview": {"tracked": len(watchlist), "analyzed": len(full),
                     "mean_emergence": round(sum(t["latest"]["emergence_score"] for t in full) / len(full), 2) if full else None,
                     "risk_distribution": distribution,
                     "exploit_evidence": [{"keyword": t["keyword"],
                         "level": t["latest"].get("features", {}).get("exploit_evidence_level", "none"),
                         "items": t["latest"].get("features", {}).get("exploit_evidence", [])}
                         for t in full if t["latest"].get("features", {}).get("exploit_evidence_level", "none") != "none"],
                     "rapidly_increasing": [t for t in full if t["score_delta"] is not None and t["score_delta"] >= rise_threshold]},
        "recent_activity": recent, "alerts": list_alerts(limit=20),
        "monitoring": monitoring_status(), "last_collection": latest_monitoring_run(),
        "last_successful_collection": latest_successful_monitoring_run(),
    })


@app.get("/api/history")
async def threat_history(keyword: str = Query(..., min_length=1), limit: int = Query(100, ge=1, le=1000)):
    return {"keyword": keyword, "snapshots": get_snapshot_history(keyword, limit),
            "alerts": [a for a in list_alerts(limit=1000) if a["keyword"] == keyword.strip().lower()]}


@app.get("/api/alerts")
async def alerts_api(status: str | None = None, limit: int = Query(100, ge=1, le=1000)):
    if status and status not in {"open", "acknowledged", "resolved"}:
        raise HTTPException(400, "Invalid alert status")
    return {"alerts": list_alerts(status, limit)}


@app.patch("/api/alerts/{alert_id}")
async def manage_alert(alert_id: int, payload: dict[str, str]):
    status = payload.get("status", "")
    try:
        updated = update_alert(alert_id, status)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not updated:
        raise HTTPException(404, "Alert not found")
    return {"ok": True, "alert_id": alert_id, "status": status}


@app.get("/api/watchlist")
async def watchlist_api():
    return {"items": list_watchlist()}


@app.post("/api/watchlist")
async def watchlist_add(payload: dict[str, str]):
    keyword = payload.get("keyword", "").strip()
    category = payload.get("category", "vulnerability")
    if not keyword or len(keyword) > 200:
        raise HTTPException(400, "Provide a keyword of 1-200 characters")
    return {"created": add_watchlist_item(keyword, category), "items": list_watchlist()}


@app.delete("/api/watchlist/{keyword}")
async def watchlist_delete(keyword: str):
    if not remove_watchlist_item(keyword):
        raise HTTPException(404, "Watchlist item not found")
    return {"ok": True}


@app.patch("/api/watchlist/{keyword}")
async def watchlist_update(keyword: str, payload: dict[str, Any]):
    enabled = payload.get("enabled")
    if not isinstance(enabled, bool):
        raise HTTPException(400, "enabled must be a boolean")
    if not set_watchlist_enabled(keyword, enabled):
        raise HTTPException(404, "Watchlist item not found")
    return {"ok": True, "enabled": enabled}


@app.get("/api/settings")
async def settings_api():
    import json as json_module
    cfg = json_module.loads((Path(__file__).resolve().parents[1] / "config.json").read_text(encoding="utf-8")).get("monitoring", {})
    try:
        sources = json.loads(get_setting("monitoring_sources", json.dumps(cfg.get("sources", ["NVD", "AlienVault OTX"]))))
    except json.JSONDecodeError:
        sources = cfg.get("sources", ["NVD", "AlienVault OTX"])
    return {"alert_threshold": float(get_setting("alert_threshold", str(cfg.get("alert_threshold", 65)))),
            "significant_score_increase": float(get_setting("significant_score_increase", str(cfg.get("significant_score_increase", 10)))),
            "minimum_alert_risk": get_setting("minimum_alert_risk", str(cfg.get("minimum_alert_risk", "Low"))),
            "interval_seconds": int(get_setting("monitoring_interval_seconds", str(cfg.get("interval_seconds", 900)))),
            "sources": sources}


@app.put("/api/settings")
async def settings_update(payload: dict[str, Any]):
    for field, low, high in (("alert_threshold", 0, 100), ("significant_score_increase", 0.1, 100), ("interval_seconds", 60, 86400)):
        if field in payload:
            try:
                value = float(payload[field])
            except (TypeError, ValueError):
                raise HTTPException(400, f"{field} must be numeric")
            if not low <= value <= high:
                raise HTTPException(400, f"{field} must be between {low} and {high}")
            key = {"interval_seconds": "monitoring_interval_seconds"}.get(field, field)
            set_setting(key, str(int(value)) if field == "interval_seconds" else str(value))
    if "minimum_alert_risk" in payload:
        level = str(payload["minimum_alert_risk"]).capitalize()
        if level not in {"Low", "Medium", "High", "Critical"}:
            raise HTTPException(400, "minimum_alert_risk must be Low, Medium, High, or Critical")
        set_setting("minimum_alert_risk", level)
    if "sources" in payload:
        sources = payload["sources"]
        allowed = {"NVD", "AlienVault OTX"}
        if not isinstance(sources, list) or not sources or any(source not in allowed for source in sources):
            raise HTTPException(400, "sources must include NVD and/or AlienVault OTX")
        set_setting("monitoring_sources", json.dumps(sorted(set(sources))))
    return await settings_api()


@app.get("/api/monitoring")
async def monitoring_state():
    return {"status": monitoring_status(), "last_run": latest_monitoring_run(),
            "last_successful_run": latest_successful_monitoring_run()}


@app.post("/api/monitoring/start")
async def monitoring_start():
    return start_monitoring()


@app.post("/api/monitoring/stop")
async def monitoring_stop():
    return stop_monitoring()


@app.post("/api/monitoring/run")
async def monitoring_run_once():
    return run_monitoring_cycle()


@app.get("/api/export")
async def export_data(kind: str = Query("alerts", pattern="^(alerts|watchlist|activity)$"),
                      format: str = Query("json", pattern="^(json|csv)$")):
    rows = list_alerts(limit=1000) if kind == "alerts" else list_watchlist() if kind == "watchlist" else fetch_recent_intel(1000)
    if format == "json":
        return JSONResponse({"kind": kind, "records": rows})
    output = io.StringIO()
    fields = sorted({field for row in rows for field in row}) if rows else ["empty"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=dtem-{kind}.csv"})


@app.get("/report/{keyword}", response_class=HTMLResponse)
async def printable_report(keyword: str):
    history = get_snapshot_history(keyword, 1)
    if not history:
        raise HTTPException(404, "No stored analysis exists for this threat yet")
    snap = history[-1]
    alerts = [a for a in list_alerts(limit=1000) if a["keyword"] == keyword.strip().lower()]
    return HTMLResponse(f"""<!doctype html><html><head><title>DTEM Report — {html.escape(keyword)}</title>
    <style>body{{font:16px system-ui;max-width:900px;margin:40px auto}}dt{{font-weight:bold}}@media print{{button{{display:none}}}}</style></head><body>
    <button onclick="window.print()">Print / Save PDF</button><h1>DTEM Threat Report: {html.escape(keyword)}</h1>
    <p>Generated from persisted prototype analysis. Scores are evidence summaries and do not prove exploitation.</p>
    <dl><dt>Analyzed at</dt><dd>{html.escape(snap['analyzed_at'])}</dd><dt>Emergence Score</dt><dd>{snap['emergence_score']}/100</dd>
    <dt>Composite Risk Score</dt><dd>{snap['risk_score'] if snap['risk_score'] is not None else 'Unavailable'}</dd>
    <dt>Risk level</dt><dd>{html.escape(snap['risk_level'] or 'Unknown')}</dd><dt>Indicators</dt><dd><pre>{html.escape(json.dumps(snap['features'], indent=2))}</pre></dd></dl>
    <h2>Stored Alerts</h2><pre>{html.escape(json.dumps(alerts, indent=2))}</pre></body></html>""")


@app.get("/threat/{keyword}", response_class=HTMLResponse)
async def threat_detail_page(keyword: str):
    safe = html.escape(keyword)
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><title>DTEM History — {safe}</title>
    <meta name="viewport" content="width=device-width,initial-scale=1"><script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>body{{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:0 1rem;background:#0b1120;color:#e2e8f0}}a{{color:#67e8f9}}.card{{background:#111b2e;padding:1rem;border-radius:10px;margin:1rem 0}}canvas{{max-height:360px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}</style></head>
    <body><a href="/">← Dashboard</a> · <a href="/report/{html.escape(keyword, quote=True)}">Printable report</a><h1>Threat history: {safe}</h1>
    <section class="card"><div id="current">Loading persisted analysis…</div><canvas id="historyChart"></canvas></section>
    <section class="card"><h2>Persisted snapshots and evidence</h2><div id="snapshots">Loading…</div></section>
    <section class="card"><h2>Alert history</h2><div id="alerts">Loading…</div></section>
    <script>fetch('/api/history?keyword='+encodeURIComponent(decodeURIComponent(location.pathname.split('/').pop()))).then(r=>r.json()).then(data=>{{
      const snaps=data.snapshots||[]; const current=document.getElementById('current');
      if(!snaps.length){{current.textContent='No persisted score history yet. Run an analysis or enable monitoring to start history.';document.getElementById('snapshots').textContent='No snapshots stored.';}}
      else{{const last=snaps[snaps.length-1];current.textContent='Emergence '+last.emergence_score+'/100 · Composite risk '+(last.risk_score??'Unavailable')+' · '+(last.risk_level||'Unknown')+' · '+last.analyzed_at;
       new Chart(document.getElementById('historyChart'),{{type:'line',data:{{labels:snaps.map(x=>new Date(x.analyzed_at).toLocaleString()),datasets:[{{label:'Emergence',data:snaps.map(x=>x.emergence_score),borderColor:'#22d3ee'}},{{label:'Composite risk',data:snaps.map(x=>x.risk_score),borderColor:'#fb7185'}},{{label:'Detection Frequency (count)',data:snaps.map(x=>x.features.detection_frequency||0),borderColor:'#a78bfa',yAxisID:'y1'}},{{label:'Source Diversity (count)',data:snaps.map(x=>x.features.source_diversity||0),borderColor:'#fbbf24',yAxisID:'y1'}},{{label:'Exploit evidence tier (ordinal)',data:snaps.map(x=>x.features.exploit_evidence_score||0),borderColor:'#f87171'}}]}},options:{{responsive:true,scales:{{y:{{min:0,max:100,position:'left'}},y1:{{beginAtZero:true,position:'right',grid:{{drawOnChartArea:false}}}}}}}}}}}});
       const box=document.getElementById('snapshots');box.replaceChildren(...snaps.slice().reverse().map(x=>{{const d=document.createElement('details');const s=document.createElement('summary');s.textContent=x.analyzed_at+' · Emergence '+x.emergence_score+' · Risk '+(x.risk_score??'Unavailable');const p=document.createElement('pre');p.textContent=JSON.stringify({{features:x.features,evidence:x.evidence}},null,2);d.append(s,p);return d;}}));}}
      const ab=document.getElementById('alerts'); if(!data.alerts.length)ab.textContent='No alerts stored for this threat.';else ab.replaceChildren(...data.alerts.map(a=>{{const p=document.createElement('p');p.textContent=a.created_at+' · '+a.alert_type+' · '+a.previous_score+' → '+a.new_score+' · '+a.status;return p;}}));
    }}).catch(e=>document.getElementById('current').textContent='History unavailable: '+e.message);</script></body></html>""")
