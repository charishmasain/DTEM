"""
dtem.collector.darkweb
~~~~~~~~~~~~~~~~~~~~~~

Simulated dark web threat intelligence collector.

For the research prototype, real‑time dark web scraping (which would
require Tor routing, forum credentials, and anti‑bot bypasses) is
replaced by a local database of seeded forum posts.

When a keyword is searched:
  1. Pre‑seeded records for that keyword are returned from the DB.
  2. If no seeded records exist, a small set of *dynamically generated*
     placeholder records is created on‑the‑fly to simulate live
     scraping of previously unknown threats.

This lets the DTEM extractor compute realistic Detection Frequency,
Growth Rate, Source Diversity, and Exploit Availability metrics.
"""

import hashlib
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dtem.collector.base import BaseCollector
from dtem.data.database import (
    fetch_intel_for_keyword,
    get_or_create_query,
    insert_intel_records,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


def _load_dw_config() -> dict[str, Any]:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh).get("collectors", {}).get("darkweb_simulator", {})


# ---------------------------------------------------------------------------
# Dynamic post templates for unknown keywords
# ---------------------------------------------------------------------------

_DYNAMIC_TEMPLATES: list[dict[str, Any]] = [
    {
        "title_fmt": "{keyword} — new activity reported on {source}",
        "content_fmt": (
            "Users on {source} are discussing recent activity related to "
            "'{keyword}'. Multiple threads created in the last week."
        ),
        "exploit_mentioned": 0,
        "severity": "medium",
    },
    {
        "title_fmt": "{keyword} exploit / tool shared on {source}",
        "content_fmt": (
            "A post on {source} claims to share tools or exploit code "
            "associated with '{keyword}'. Verification pending."
        ),
        "exploit_mentioned": 1,
        "severity": "high",
    },
    {
        "title_fmt": "{keyword} — IOC and hash dump on {source}",
        "content_fmt": (
            "Thread on {source} contains indicators of compromise "
            "believed to be linked to '{keyword}' operations."
        ),
        "exploit_mentioned": 0,
        "severity": "medium",
    },
    {
        "title_fmt": "{keyword} — target list being sold on {source}",
        "content_fmt": (
            "A seller on {source} is offering a list of targets "
            "vulnerable to '{keyword}'. Price: negotiable."
        ),
        "exploit_mentioned": 1,
        "severity": "high",
    },
]


class DarkWebCollector(BaseCollector):
    """
    Retrieves threat intelligence from the simulated dark web
    data stored in the local SQLite database.
    """

    source_name: str = "DarkWeb-Simulator"
    source_type: str = "dark_web"

    def __init__(self) -> None:
        cfg = _load_dw_config()
        self.enabled: bool = cfg.get("enabled", True)
        self.sources: list[str] = cfg.get(
            "sources",
            ["BreachForums", "Exploit.in", "XSS.is", "RAMP", "Dread"],
        )

    # ------------------------------------------------------------------ #
    # Core collection
    # ------------------------------------------------------------------ #

    def collect(self, keyword: str) -> list[dict[str, Any]]:
        """
        Return dark web intelligence for *keyword*.

        If seeded data exists it is returned directly.  Otherwise,
        dynamic placeholder posts are generated, saved to the DB,
        and then returned.
        """
        if not self.enabled:
            logger.info("Dark web simulator is disabled in config.")
            return []

        keyword_lower = keyword.strip().lower()

        # Fetch existing seeded / previously‑generated records
        existing = fetch_intel_for_keyword(keyword_lower)
        dark_web_records = [
            r for r in existing if r.get("source_type") == "dark_web"
        ]

        if dark_web_records:
            logger.info(
                "Dark web simulator: returning %d seeded records for '%s'.",
                len(dark_web_records),
                keyword_lower,
            )
            return self._normalise(dark_web_records)

        # No seeded data → generate dynamic posts
        logger.info(
            "Dark web simulator: generating dynamic posts for '%s'.",
            keyword_lower,
        )
        return self._generate_dynamic(keyword_lower)

    # ------------------------------------------------------------------ #
    # Dynamic generation for unknown keywords
    # ------------------------------------------------------------------ #

    def _generate_dynamic(self, keyword: str) -> list[dict[str, Any]]:
        """
        Create a small set of realistic forum posts for a keyword
        that has no seeded data.  Posts are saved into the DB so
        subsequent calls are consistent.
        """
        # Deterministic seed so the same keyword always gets the same posts
        seed = int(hashlib.md5(keyword.encode()).hexdigest()[:8], 16)
        rng = random.Random(seed)

        query_id = get_or_create_query(keyword)
        records: list[dict[str, Any]] = []

        # Pick 3–5 random (source, template) combos
        num_posts = rng.randint(3, 5)
        for _ in range(num_posts):
            source = rng.choice(self.sources)
            tpl = rng.choice(_DYNAMIC_TEMPLATES)

            days_ago = rng.randint(1, 60)
            pub_dt = datetime.now(timezone.utc) - timedelta(
                days=days_ago,
                hours=rng.randint(0, 23),
                minutes=rng.randint(0, 59),
            )

            records.append(
                {
                    "query_id": query_id,
                    "source": source,
                    "source_type": "dark_web",
                    "title": tpl["title_fmt"].format(
                        keyword=keyword, source=source
                    ),
                    "content": tpl["content_fmt"].format(
                        keyword=keyword, source=source
                    ),
                    "url": "",
                    "published_at": pub_dt.isoformat(),
                    "severity": tpl["severity"],
                    "exploit_mentioned": tpl["exploit_mentioned"],
                    "raw_data": {"generated": True, "keyword": keyword},
                }
            )

        # Persist so future calls return the same data
        insert_intel_records(records)
        logger.info(
            "Dark web simulator: generated and saved %d records for '%s'.",
            len(records),
            keyword,
        )
        return records

    # ------------------------------------------------------------------ #
    # Normalise DB rows back to the standard dict format
    # ------------------------------------------------------------------ #

    @staticmethod
    def _normalise(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Convert database Row dicts into the normalised record
        format expected by the collector manager.
        """
        normalised: list[dict[str, Any]] = []
        for row in rows:
            raw = row.get("raw_data", "{}")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except json.JSONDecodeError:
                    raw = {}

            normalised.append(
                {
                    "source": row["source"],
                    "source_type": row["source_type"],
                    "title": row["title"],
                    "content": row.get("content", ""),
                    "url": row.get("url", ""),
                    "published_at": row.get("published_at", ""),
                    "severity": row.get("severity", ""),
                    "exploit_mentioned": int(row.get("exploit_mentioned", 0)),
                    "raw_data": raw,
                }
            )
        return normalised
