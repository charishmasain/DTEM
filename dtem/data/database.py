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
        return [dict(r) for r in rows]
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


# ---------------------------------------------------------------------------
# Convenience: auto‑init on import
# ---------------------------------------------------------------------------

init_db()
