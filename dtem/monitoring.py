"""Opt-in periodic monitoring of the persistent threat watchlist."""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from dtem.collector.manager import CollectorManager
from dtem.data.database import (
    get_setting, list_watchlist, record_analysis, record_monitoring_run,
    get_snapshot_history,
)
from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.risk.assessment import RiskAssessmentEngine

logger = logging.getLogger(__name__)
_CONFIG_PATH = Path(__file__).resolve().parent / "config.json"
_lock = threading.Lock()
_stop = threading.Event()
_thread: threading.Thread | None = None
_status: dict[str, Any] = {"running": False, "started_at": None}


def _config() -> dict[str, Any]:
    return json.loads(_CONFIG_PATH.read_text(encoding="utf-8")).get("monitoring", {})


def run_monitoring_cycle() -> dict[str, Any]:
    """Collect configured public sources for enabled watchlist items once."""
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    items = list_watchlist(enabled_only=True)
    cfg = _config()
    try:
        names = json.loads(get_setting("monitoring_sources", json.dumps(cfg.get("sources", ["NVD", "AlienVault OTX"]))))
    except json.JSONDecodeError:
        names = cfg.get("sources", ["NVD", "AlienVault OTX"])
    manager = CollectorManager()
    manager.collector_status = []
    inserted = 0
    errors: list[str] = []
    all_source_status: list[dict[str, Any]] = []
    extractor = ThreatInfoExtractor()
    scorer = DTEMScoringEngine()
    risk_engine = RiskAssessmentEngine()
    threshold = float(get_setting("alert_threshold", str(cfg.get("alert_threshold", 65))))
    increase = float(get_setting("significant_score_increase", str(cfg.get("significant_score_increase", 10))))
    minimum_risk = get_setting("minimum_alert_risk", str(cfg.get("minimum_alert_risk", "Low")))

    for item in items:
        keyword = item["keyword"]
        try:
            collected = manager.collect(keyword, include_sources=set(names))
            all_source_status.extend({**status, "keyword": keyword} for status in getattr(manager, "last_status", []))
            new_records = int(getattr(manager, "last_inserted_count", len(collected)))
            inserted += new_records
            if new_records == 0 and get_snapshot_history(keyword, 1):
                continue
            features = extractor.extract_features(keyword, auto_collect=False, include_prototype=False)
            emergence = scorer.calculate_emergence(features)
            if emergence.get("score_status") == "insufficient_data":
                for status in getattr(manager, "last_status", []):
                    if status.get("status") == "error":
                        errors.append(f"{keyword}/{status.get('source')}: {status.get('error')}")
                continue
            risk = risk_engine.assess_risk(emergence)
            record_analysis(keyword, features, emergence, risk,
                            threshold=threshold, increase_threshold=increase,
                            minimum_risk_level=minimum_risk)
            for status in getattr(manager, "last_status", []):
                if status.get("status") == "error":
                    errors.append(f"{keyword}/{status.get('source')}: {status.get('error')}")
        except Exception as exc:  # preserve a failure record and continue other items
            logger.exception("Monitor failed for %s", keyword)
            errors.append(f"{keyword}: {type(exc).__name__}: {exc}")
    status = "error" if errors and not items else "partial_error" if errors else "ok"
    if not items:
        status = "no_enabled_watch_items"
    source_summary = all_source_status
    error_summary = json.dumps({"errors": errors, "sources": source_summary})
    run_id = record_monitoring_run(status, [i["keyword"] for i in items], inserted,
                                   error_summary if errors or source_summary else None,
                                   started_at=started)
    return {"run_id": run_id, "status": status, "keywords": [i["keyword"] for i in items],
            "inserted_count": inserted, "errors": errors, "sources": source_summary}


def _worker() -> None:
    global _status
    while not _stop.is_set():
        try:
            result = run_monitoring_cycle()
            with _lock:
                _status["last_cycle"] = result
        except Exception as exc:
            logger.exception("Monitoring cycle failed")
            with _lock:
                _status["last_error"] = f"{type(exc).__name__}: {exc}"
        interval = max(60, int(get_setting("monitoring_interval_seconds", str(_config().get("interval_seconds", 900)))))
        _stop.wait(interval)
    with _lock:
        _status["running"] = False


def start_monitoring() -> dict[str, Any]:
    global _thread, _status
    with _lock:
        if _thread is not None and _thread.is_alive():
            return dict(_status)
        _stop.clear()
        _status = {"running": True, "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        _thread = threading.Thread(target=_worker, name="dtem-public-monitor", daemon=True)
        _thread.start()
        return dict(_status)


def stop_monitoring() -> dict[str, Any]:
    _stop.set()
    with _lock:
        _status["running"] = False
        return dict(_status)


def monitoring_status() -> dict[str, Any]:
    with _lock:
        result = dict(_status)
        result["running"] = bool(_thread and _thread.is_alive() and not _stop.is_set())
        return result
