"""
dtem.data.seed_data
~~~~~~~~~~~~~~~~~~~

Seeds the SQLite database with realistic, time‑distributed dark web
forum posts and supplementary public CTI reports.

The seeded data enables the DTEM extractor to calculate meaningful
Detection Frequency, Growth Rate, Source Diversity, and Exploit
Availability even without live API access.

Run directly:
    python -m dtem.data.seed_data
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dtem.data.database import (
    DB_PATH,
    get_or_create_query,
    init_db,
    insert_intel_records,
    count_intel_for_keyword,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DARK_WEB_SOURCES: list[str] = [
    "BreachForums",
    "Exploit.in",
    "XSS.is",
    "RAMP",
    "Dread",
]

# How far back (in days) we distribute seeded records
SEED_WINDOW_DAYS: int = 90

# Random seed for reproducibility
RANDOM_SEED: int = 42


# ---------------------------------------------------------------------------
# Seed templates — one per keyword
# ---------------------------------------------------------------------------

_SEED_TEMPLATES: dict[str, list[dict]] = {
    # ------------------------------------------------------------------
    # LockBit — high‑frequency, rapidly escalating ransomware
    # ------------------------------------------------------------------
    "lockbit": [
        # --- Dark web posts (high volume, recent surge) ---
        {
            "source": "BreachForums",
            "source_type": "dark_web",
            "title": "LockBit 4.0 builder leaked — download link inside",
            "content": "New builder for LockBit 4.0 has been posted. Includes updated encryption module and configurable C2 callbacks. Link below.",
            "exploit_mentioned": 1,
            "severity": "high",
            "age_offset_days": (1, 5),
            "copies": 3,
        },
        {
            "source": "Exploit.in",
            "source_type": "dark_web",
            "title": "LockBit affiliate recruitment thread",
            "content": "LockBit gang is recruiting new affiliates. Payment is 80/20 split. Targets: healthcare and finance.",
            "exploit_mentioned": 0,
            "severity": "high",
            "age_offset_days": (3, 14),
            "copies": 4,
        },
        {
            "source": "XSS.is",
            "source_type": "dark_web",
            "title": "LockBit RaaS infrastructure analysis",
            "content": "Thread documenting LockBit C2 infrastructure. IP ranges and Tor hidden services catalogued.",
            "exploit_mentioned": 0,
            "severity": "medium",
            "age_offset_days": (7, 30),
            "copies": 2,
        },
        {
            "source": "RAMP",
            "source_type": "dark_web",
            "title": "LockBit decryptor — is it legit?",
            "content": "Someone claims to have a working LockBit decryptor. Asking $5K BTC. Likely scam but discussion is active.",
            "exploit_mentioned": 1,
            "severity": "medium",
            "age_offset_days": (10, 40),
            "copies": 2,
        },
        {
            "source": "Dread",
            "source_type": "dark_web",
            "title": "LockBit targeting critical infrastructure — warning",
            "content": "Multiple reports of LockBit targeting water utilities and power grids in EU region.",
            "exploit_mentioned": 0,
            "severity": "critical",
            "age_offset_days": (1, 7),
            "copies": 2,
        },
        # --- Simulated public mentions (supplementary) ---
        {
            "source": "PublicReport",
            "source_type": "public_report",
            "title": "CISA Advisory: LockBit ransomware indicators of compromise",
            "content": "CISA published updated IOCs for LockBit including file hashes, registry keys, and network signatures.",
            "url": "https://www.cisa.gov/lockbit-advisory",
            "exploit_mentioned": 0,
            "severity": "high",
            "age_offset_days": (5, 20),
            "copies": 2,
        },
    ],

    # ------------------------------------------------------------------
    # BlackLock — emerging, moderate frequency
    # ------------------------------------------------------------------
    "blacklock": [
        {
            "source": "BreachForums",
            "source_type": "dark_web",
            "title": "BlackLock ransomware — first samples observed",
            "content": "New ransomware strain BlackLock observed in the wild. Uses AES-256 + RSA-4096 hybrid encryption.",
            "exploit_mentioned": 0,
            "severity": "medium",
            "age_offset_days": (5, 20),
            "copies": 2,
        },
        {
            "source": "Exploit.in",
            "source_type": "dark_web",
            "title": "BlackLock source code snippet shared",
            "content": "Partial source code for BlackLock posted. Includes persistence mechanism using scheduled tasks.",
            "exploit_mentioned": 1,
            "severity": "high",
            "age_offset_days": (2, 10),
            "copies": 2,
        },
        {
            "source": "XSS.is",
            "source_type": "dark_web",
            "title": "BlackLock — possible ties to Conti operators",
            "content": "Analysis suggests code reuse from Conti ransomware. Same obfuscation patterns detected.",
            "exploit_mentioned": 0,
            "severity": "medium",
            "age_offset_days": (15, 45),
            "copies": 1,
        },
        {
            "source": "RAMP",
            "source_type": "dark_web",
            "title": "BlackLock affiliate programme launch",
            "content": "BlackLock announces RaaS model. 70/30 split. Requires proof of prior operations.",
            "exploit_mentioned": 0,
            "severity": "high",
            "age_offset_days": (3, 12),
            "copies": 2,
        },
    ],

    # ------------------------------------------------------------------
    # CVE-2025-12345 — vulnerability with growing exploit chatter
    # ------------------------------------------------------------------
    "cve-2025-12345": [
        {
            "source": "Exploit.in",
            "source_type": "dark_web",
            "title": "PoC exploit for CVE-2025-12345 — RCE in Apache module",
            "content": "Working proof‑of‑concept for CVE-2025-12345. Remote code execution via crafted HTTP header. Python script attached.",
            "exploit_mentioned": 1,
            "severity": "critical",
            "age_offset_days": (1, 7),
            "copies": 3,
        },
        {
            "source": "XSS.is",
            "source_type": "dark_web",
            "title": "CVE-2025-12345 exploit integration into botnet",
            "content": "Discussion on integrating CVE-2025-12345 into Mirai variant. Mass scanning already observed.",
            "exploit_mentioned": 1,
            "severity": "critical",
            "age_offset_days": (1, 5),
            "copies": 2,
        },
        {
            "source": "BreachForums",
            "source_type": "dark_web",
            "title": "CVE-2025-12345 — vulnerable hosts for sale",
            "content": "Selling list of 10K+ servers vulnerable to CVE-2025-12345. Verified with Nuclei scanner.",
            "exploit_mentioned": 1,
            "severity": "critical",
            "age_offset_days": (2, 8),
            "copies": 2,
        },
        {
            "source": "RAMP",
            "source_type": "dark_web",
            "title": "CVE-2025-12345 — initial access broker offering shells",
            "content": "IAB offering web shells on systems compromised via CVE-2025-12345. Price: $50/shell.",
            "exploit_mentioned": 1,
            "severity": "critical",
            "age_offset_days": (3, 14),
            "copies": 2,
        },
        {
            "source": "PublicReport",
            "source_type": "public_report",
            "title": "NVD Entry: CVE-2025-12345 — CVSS 9.8 Critical",
            "content": "Apache HTTP Server mod_rewrite RCE. Allows unauthenticated remote code execution via crafted request.",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
            "exploit_mentioned": 0,
            "severity": "critical",
            "age_offset_days": (10, 30),
            "copies": 1,
        },
    ],

    # ------------------------------------------------------------------
    # APT29 — nation‑state actor, moderate, steady frequency
    # ------------------------------------------------------------------
    "apt29": [
        {
            "source": "XSS.is",
            "source_type": "dark_web",
            "title": "APT29 tooling discussed — new backdoor variant",
            "content": "Forum post analysing a new WellMess backdoor variant attributed to APT29. C2 communicates over DNS-over-HTTPS.",
            "exploit_mentioned": 0,
            "severity": "high",
            "age_offset_days": (5, 25),
            "copies": 2,
        },
        {
            "source": "Exploit.in",
            "source_type": "dark_web",
            "title": "APT29 phishing kit — templates shared",
            "content": "Phishing templates mimicking Microsoft 365 login attributed to APT29 campaign shared on forum.",
            "exploit_mentioned": 1,
            "severity": "high",
            "age_offset_days": (7, 35),
            "copies": 2,
        },
        {
            "source": "BreachForums",
            "source_type": "dark_web",
            "title": "APT29 indicators of compromise dump",
            "content": "IOC list for APT29 operations: file hashes (SHA-256), C2 domains, and SSL cert fingerprints.",
            "exploit_mentioned": 0,
            "severity": "medium",
            "age_offset_days": (10, 50),
            "copies": 2,
        },
        {
            "source": "Dread",
            "source_type": "dark_web",
            "title": "APT29 — supply chain attack vector discussion",
            "content": "Discussion thread on APT29 leveraging software supply chain (SolarWinds style) for new campaign.",
            "exploit_mentioned": 0,
            "severity": "high",
            "age_offset_days": (3, 15),
            "copies": 1,
        },
        {
            "source": "PublicReport",
            "source_type": "public_report",
            "title": "MITRE ATT&CK update: APT29 techniques expanded",
            "content": "MITRE added T1059.001, T1071.004, and T1547.001 to APT29 group profile.",
            "url": "https://attack.mitre.org/groups/G0016/",
            "exploit_mentioned": 0,
            "severity": "medium",
            "age_offset_days": (15, 60),
            "copies": 1,
        },
    ],
}


# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------

def _random_published_date(
    age_range: tuple[int, int],
    rng: random.Random,
) -> str:
    """
    Return an ISO‑8601 timestamp between *age_range[0]* and
    *age_range[1]* days ago from now, with random hour/minute jitter.
    """
    days_ago = rng.randint(age_range[0], age_range[1])
    hours = rng.randint(0, 23)
    minutes = rng.randint(0, 59)
    dt = datetime.now(timezone.utc) - timedelta(
        days=days_ago, hours=hours, minutes=minutes
    )
    return dt.isoformat()


def seed_database(force: bool = False) -> dict[str, int]:
    """
    Populate the database with realistic threat intelligence records.

    Args:
        force: If True, re‑seed even if data already exists for a keyword.

    Returns:
        A dict mapping each keyword to the number of records inserted.
    """
    init_db()
    rng = random.Random(RANDOM_SEED)
    summary: dict[str, int] = {}

    for keyword, templates in _SEED_TEMPLATES.items():
        # Skip if data already exists (unless force=True)
        if not force and count_intel_for_keyword(keyword) > 0:
            summary[keyword] = 0
            continue

        query_id = get_or_create_query(keyword)
        records: list[dict] = []

        for tpl in templates:
            copies = tpl.get("copies", 1)
            for _ in range(copies):
                pub_date = _random_published_date(
                    tpl["age_offset_days"], rng
                )
                records.append(
                    {
                        "query_id": query_id,
                        "source": tpl["source"],
                        "source_type": tpl["source_type"],
                        "title": tpl["title"],
                        "content": tpl.get("content", ""),
                        "url": tpl.get("url", ""),
                        "published_at": pub_date,
                        "severity": tpl.get("severity", ""),
                        "exploit_mentioned": tpl.get("exploit_mentioned", 0),
                        "raw_data": {"seeded": True, "template_title": tpl["title"]},
                    }
                )

        inserted = insert_intel_records(records)
        summary[keyword] = inserted

    return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("DTEM — Seeding database with simulated dark web data")
    print(f"Database: {DB_PATH}")
    print("=" * 60)

    results = seed_database(force=True)

    for kw, count in results.items():
        print(f"  [{kw:>20s}]  {count:>3d} records inserted")

    total = sum(results.values())
    print("-" * 60)
    print(f"  {'TOTAL':>20s}   {total:>3d} records")
    print("=" * 60)
    print("Done.")
