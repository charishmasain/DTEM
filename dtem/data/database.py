"""
dtem.data.database
~~~~~~~~~~~~~~~~~~

SQLite database layer for the DTEM project.

Provides schema creation, connection helpers, and CRUD operations
for threat queries and collected intelligence records.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Resolve database path from config.json
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

def _load_db_path() -> Path:
    """Read the database file path from config.json."""
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        config = json.load(fh)
    db_rel = config.get("database", {}).get("path", "dtem_database.db")
    # Store the DB file next to the project root (parent of `dtem/`)
    project_root = Path(__file__).resolve().parent.parent.parent
    return project_root / db_rel


DB_PATH: Path = _load_db_path()


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
-- Stores every unique search query made by the user.
CREATE TABLE IF NOT EXISTS threat_queries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword         TEXT    NOT NULL,
    searched_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(keyword)  -- one row per unique keyword
);

-- Stores individual threat‑intelligence documents collected from any source.
CREATE TABLE IF NOT EXISTS collected_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id        INTEGER NOT NULL,
    source          TEXT    NOT NULL,          -- e.g. "NVD", "OTX", "BreachForums"
    source_type     TEXT    NOT NULL,          -- "public_api" | "dark_web"
    title           TEXT    NOT NULL,
    content         TEXT    DEFAULT '',
    url             TEXT    DEFAULT '',
    published_at    TEXT    DEFAULT '',        -- ISO‑8601 timestamp from the source
    severity        TEXT    DEFAULT '',        -- e.g. CVSS score or qualitative label
    exploit_mentioned INTEGER DEFAULT 0,      -- 1 = yes, 0 = no
    raw_data        TEXT    DEFAULT '{}',      -- full JSON blob for traceability
    collected_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (query_id) REFERENCES threat_queries(id)
);

-- Index for fast lookups by keyword → query → intel
CREATE INDEX IF NOT EXISTS idx_intel_query  ON collected_intel(query_id);
CREATE INDEX IF NOT EXISTS idx_intel_source ON collected_intel(source);

CREATE TABLE IF NOT EXISTS analysis_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL,
    analyzed_at TEXT NOT NULL,
    emergence_score REAL NOT NULL,
    risk_score REAL,
    risk_level TEXT,
    stage TEXT,
    features_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_snapshot_keyword_time ON analysis_snapshots(keyword, analyzed_at);

CREATE TABLE IF NOT EXISTS threat_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    previous_score REAL,
    new_score REAL NOT NULL,
    risk_level TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',
    acknowledged_at TEXT,
    resolved_at TEXT,
    dedupe_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_alert_status_time ON threat_alerts(status, created_at);

CREATE TABLE IF NOT EXISTS threat_watchlist (
    keyword TEXT PRIMARY KEY,
    category TEXT NOT NULL DEFAULT 'vulnerability',
    enabled INTEGER NOT NULL DEFAULT 1,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS monitoring_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    keywords_json TEXT NOT NULL DEFAULT '[]',
    inserted_count INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
"""


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Create tables and indexes if they don't already exist."""
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.executescript(_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def record_analysis(keyword: str, features: dict[str, Any], emergence: dict[str, Any],
                    risk: dict[str, Any], *, threshold: float = 65.0,
                    increase_threshold: float = 10.0,
                    minimum_risk_level: str = "Low") -> tuple[int, list[dict[str, Any]]]:
    """Persist a real analysis snapshot and create transition alerts once."""
    now = datetime.now(timezone.utc).isoformat()
    key = keyword.strip().lower()
    emergence_score = float(emergence.get("emergence_score", 0))
    risk_score = risk.get("risk_score")
    evidence = {
        "sub_scores": emergence.get("sub_scores", {}),
        "features": features,
        "severity_basis": risk.get("severity_basis", "unavailable"),
        "recommendations": risk.get("recommendations", []),
    }
    conn = get_connection()
    created: list[dict[str, Any]] = []
    try:
        # Serialize concurrent analysis writers so threshold transitions are
        # evaluated against the latest committed snapshot, not a stale read.
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute(
            "SELECT emergence_score, risk_level FROM analysis_snapshots WHERE keyword=? ORDER BY id DESC LIMIT 1", (key,)
        ).fetchone()
        prev_score = float(previous["emergence_score"]) if previous else None
        risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        meets_minimum_risk = risk_rank.get(str(risk.get("risk_level", "")).lower(), -1) >= risk_rank.get(minimum_risk_level.lower(), 0)
        previous_meets_risk = bool(previous and risk_rank.get(str(previous["risk_level"] or "").lower(), -1)
                                   >= risk_rank.get(minimum_risk_level.lower(), 0))
        cur = conn.execute(
            """INSERT INTO analysis_snapshots
            (keyword, analyzed_at, emergence_score, risk_score, risk_level, stage, features_json, evidence_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (key, now, emergence_score, risk_score, risk.get("risk_level"),
             emergence.get("emergence_stage"), json.dumps(features), json.dumps(evidence)),
        )
        snapshot_id = int(cur.lastrowid)
        candidates = []
        if meets_minimum_risk and emergence_score >= threshold and (
                prev_score is None or prev_score < threshold or not previous_meets_risk):
            candidates.append(("threshold_crossing", prev_score))
        if meets_minimum_risk and prev_score is not None and emergence_score - prev_score >= increase_threshold:
            candidates.append(("significant_increase", prev_score))
        for alert_type, before in candidates:
            dedupe = f"{key}:{snapshot_id}:{alert_type}"
            conn.execute(
                """INSERT OR IGNORE INTO threat_alerts
                (keyword, alert_type, created_at, previous_score, new_score, risk_level, evidence_json, dedupe_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (key, alert_type, now, before, emergence_score, risk.get("risk_level"), json.dumps(evidence), dedupe),
            )
            row = conn.execute("SELECT * FROM threat_alerts WHERE dedupe_key=?", (dedupe,)).fetchone()
            if row:
                created.append(dict(row))
        conn.commit()
        return snapshot_id, created
    finally:
        conn.close()


def get_snapshot_history(keyword: str, limit: int = 100) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM analysis_snapshots WHERE keyword=? ORDER BY analyzed_at DESC, id DESC LIMIT ?",
            (keyword.strip().lower(), max(1, min(int(limit), 1000))),
        ).fetchall()
        results = [dict(row) for row in rows]
        for row in results:
            row["features"] = json.loads(row.pop("features_json"))
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return list(reversed(results))
    finally:
        conn.close()


def list_alerts(status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        if status:
            rows = conn.execute("SELECT * FROM threat_alerts WHERE status=? ORDER BY created_at DESC LIMIT ?",
                                (status, max(1, min(limit, 1000)))).fetchall()
        else:
            rows = conn.execute("SELECT * FROM threat_alerts ORDER BY created_at DESC LIMIT ?",
                                (max(1, min(limit, 1000)),)).fetchall()
        data = [dict(r) for r in rows]
        for row in data:
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return data
    finally:
        conn.close()


def update_alert(alert_id: int, status: str) -> bool:
    if status not in {"open", "acknowledged", "resolved"}:
        raise ValueError("status must be open, acknowledged, or resolved")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        cur = conn.execute(
            "UPDATE threat_alerts SET status=?, acknowledged_at=CASE WHEN ?='acknowledged' THEN ? ELSE acknowledged_at END, resolved_at=CASE WHEN ?='resolved' THEN ? ELSE resolved_at END WHERE id=?",
            (status, status, now, status, now, int(alert_id)),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def add_watchlist_item(keyword: str, category: str = "vulnerability") -> bool:
    key = keyword.strip().lower()
    if not key:
        raise ValueError("keyword cannot be empty")
    conn = get_connection()
    try:
        cur = conn.execute("INSERT OR IGNORE INTO threat_watchlist(keyword, category, added_at) VALUES (?, ?, ?)",
                           (key, category.strip() or "other", datetime.now(timezone.utc).isoformat()))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_watchlist(enabled_only: bool = False) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        query = "SELECT * FROM threat_watchlist" + (" WHERE enabled=1" if enabled_only else "") + " ORDER BY keyword"
        return [dict(row) for row in conn.execute(query).fetchall()]
    finally:
        conn.close()


def remove_watchlist_item(keyword: str) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute("DELETE FROM threat_watchlist WHERE keyword=?", (keyword.strip().lower(),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def set_watchlist_enabled(keyword: str, enabled: bool) -> bool:
    conn = get_connection()
    try:
        cur = conn.execute("UPDATE threat_watchlist SET enabled=? WHERE keyword=?",
                           (int(enabled), keyword.strip().lower()))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_setting(key: str, default: str) -> str:
    conn = get_connection()
    try:
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else default
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    conn = get_connection()
    try:
        conn.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, str(value)))
        conn.commit()
    finally:
        conn.close()


def record_monitoring_run(status: str, keywords: list[str], inserted_count: int = 0,
                          error: str | None = None, *, started_at: str | None = None) -> int:
    conn = get_connection()
    try:
        cur = conn.execute("INSERT INTO monitoring_runs(started_at,finished_at,status,keywords_json,inserted_count,error) VALUES(?,?,?,?,?,?)",
                           (started_at or datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(),
                            status, json.dumps(keywords), int(inserted_count), error))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def latest_monitoring_run() -> dict[str, Any] | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM monitoring_runs ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        result = dict(row)
        result["keywords"] = json.loads(result.pop("keywords_json"))
        return result
    finally:
        conn.close()


def latest_successful_monitoring_run() -> dict[str, Any] | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM monitoring_runs WHERE status='ok' ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        result = dict(row)
        result["keywords"] = json.loads(result.pop("keywords_json"))
        return result
    finally:
        conn.close()


def get_connection() -> sqlite3.Connection:
    """
    Return a new SQLite connection with Row factory enabled so that
    rows can be accessed like dictionaries.
    """
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_or_create_query(keyword: str) -> int:
    """
    Return the ``threat_queries.id`` for *keyword*, creating the row
    if it doesn't exist yet.
    """
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT id FROM threat_queries WHERE keyword = ?",
            (keyword.strip().lower(),),
        )
        row = cursor.fetchone()
        if row:
            return int(row["id"])

        cursor = conn.execute(
            "INSERT INTO threat_queries (keyword) VALUES (?)",
            (keyword.strip().lower(),),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]
    finally:
        conn.close()


def insert_intel_records(records: list[dict[str, Any]]) -> int:
    """
    Bulk‑insert a list of CTI records into ``collected_intel``.

    Each dict must contain at minimum:
        query_id, source, source_type, title

    Returns the number of rows inserted.
    """
    if not records:
        return 0

    conn = get_connection()
    inserted = 0
    try:
        for rec in records:
            identity = (
                rec["query_id"], rec["source"], rec["title"],
                rec.get("url", ""), rec.get("published_at", ""),
            )
            exists = conn.execute(
                """SELECT 1 FROM collected_intel
                   WHERE query_id = ? AND source = ? AND title = ?
                     AND url = ? AND published_at = ? LIMIT 1""",
                identity,
            ).fetchone()
            if exists:
                continue
            conn.execute(
                """
                INSERT INTO collected_intel
                    (query_id, source, source_type, title, content,
                     url, published_at, severity, exploit_mentioned, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rec["query_id"],
                    rec["source"],
                    rec["source_type"],
                    rec["title"],
                    rec.get("content", ""),
                    rec.get("url", ""),
                    rec.get("published_at", ""),
                    rec.get("severity", ""),
                    int(rec.get("exploit_mentioned", 0)),
                    json.dumps(rec.get("raw_data", {})),
                ),
            )
            inserted += 1
        conn.commit()
    finally:
        conn.close()

    return inserted


def fetch_intel_for_keyword(keyword: str) -> list[dict[str, Any]]:
    """
    Retrieve all collected intelligence records for a given keyword.
    Returns a list of plain dicts.
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT ci.*
            FROM collected_intel ci
            JOIN threat_queries tq ON ci.query_id = tq.id
            WHERE tq.keyword = ?
            ORDER BY ci.published_at DESC
            """,
            (keyword.strip().lower(),),
        ).fetchall()
        return [_mark_prototype(dict(r)) for r in rows]
    finally:
        conn.close()


def count_intel_for_keyword(keyword: str) -> int:
    """Return the total number of CTI records stored for *keyword*."""
    conn = get_connection()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM collected_intel ci
            JOIN threat_queries tq ON ci.query_id = tq.id
            WHERE tq.keyword = ?
            """,
            (keyword.strip().lower(),),
        ).fetchone()
        return int(row["cnt"]) if row else 0
    finally:
        conn.close()


def fetch_recent_intel(limit: int = 50, source: str | None = None,
                       include_prototype: bool = False) -> list[dict[str, Any]]:
    conn = get_connection()
    try:
        sql = "SELECT ci.*, tq.keyword FROM collected_intel ci JOIN threat_queries tq ON ci.query_id=tq.id"
        params: list[Any] = []
        if source:
            sql += " WHERE ci.source = ?"
            params.append(source)
        sql += " ORDER BY ci.collected_at DESC, ci.id DESC LIMIT ?"
        params.append(max(1, min(int(limit), 1000)))
        rows = conn.execute(sql, params).fetchall()
        records = [_mark_prototype(dict(row)) for row in rows]
        return records if include_prototype else [row for row in records if not row["demonstration_data"]]
    finally:
        conn.close()


def _mark_prototype(record: dict[str, Any]) -> dict[str, Any]:
    raw = record.get("raw_data", {})
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            raw = {}
    record["demonstration_data"] = bool(
        record.get("prototype_data") or record.get("source") == "DarkWeb-Simulator"
        or record.get("source_type") == "dark_web" and record.get("historical_capture") is not True
        or isinstance(raw, dict) and (raw.get("seeded") is True or raw.get("generated") is True)
    )
    return record


# ---------------------------------------------------------------------------
# Convenience: auto‑init on import
# ---------------------------------------------------------------------------

init_db()
