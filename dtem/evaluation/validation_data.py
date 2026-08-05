"""
dtem.evaluation.validation_data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Defines a curated evaluation dataset with ground-truth escalation labels
and implements functions to populate the database for sensitivity and backtesting analysis.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from dtem.data.database import (
    get_connection,
    get_or_create_query,
    insert_intel_records,
)

logger = logging.getLogger(__name__)

# Ground-truth: True means threat escalated to a major campaign, False means it remained dormant/low-chatter
VALIDATION_GROUND_TRUTH: dict[str, bool] = {
    "eval_lockbit": True,          # Surging ransomware, exploits, high diversity
    "eval_cve_2025_rce": True,     # Surging exploit chatter, high diversity
    "eval_blacklock": True,        # Emerging ransomware, positive growth
    "eval_apt29": True,            # High diversity, steady indicators
    "eval_dormant_cve": False,     # Old records only, no recent growth
    "eval_low_chatter": False,     # Only 1 record, low frequency and diversity
    "eval_stable_medium": False,   # Flat growth, no exploits
}

def get_curated_records(base_time: datetime) -> dict[str, list[dict[str, Any]]]:
    """
    Generates a dictionary of CTI records relative to a base time.
    This ensures growth rate calculations remain stable and independent of when the code is run.
    """
    records: dict[str, list[dict[str, Any]]] = {}

    # 1. eval_lockbit (Escalated: True)
    # High frequency, growth = positive (more in recent 14 days than prior 14 days), exploit present
    rec_lockbit = []
    # Prior 14 days (days 15-28 ago): 5 records
    for i in range(5):
        pub_time = base_time - timedelta(days=15 + i, hours=i * 2)
        rec_lockbit.append({
            "source": "Exploit.in" if i % 2 == 0 else "BreachForums",
            "source_type": "dark_web",
            "title": f"LockBit 4.0 affiliate discussions part {i}",
            "content": "Discussing affiliate models and targets.",
            "published_at": pub_time.isoformat(),
            "severity": "high",
            "exploit_mentioned": 0,
        })
    # Recent 14 days (days 0-14 ago): 15 records (surging volume)
    for i in range(15):
        pub_time = base_time - timedelta(days=i, hours=i)
        rec_lockbit.append({
            "source": "BreachForums" if i % 3 == 0 else ("XSS.is" if i % 3 == 1 else "NVD"),
            "source_type": "dark_web" if i % 3 != 2 else "public_api",
            "title": f"LockBit 4.0 builder leak and exploitation tool {i}",
            "content": "Leaked decryptor builder and python integration payloads." if i % 2 == 0 else "NVD CVE entry.",
            "published_at": pub_time.isoformat(),
            "severity": "critical" if i % 2 == 0 else "high",
            "exploit_mentioned": 1 if i % 2 == 0 else 0,
        })
    records["eval_lockbit"] = rec_lockbit

    # 2. eval_cve_2025_rce (Escalated: True)
    # Exploit availability is very high, growth is surging, 3 sources
    rec_rce = []
    for i in range(3):  # Prior: 3 records
        pub_time = base_time - timedelta(days=16 + i)
        rec_rce.append({
            "source": "NVD",
            "source_type": "public_api",
            "title": "CVE-2025-99999: Apache HTTP Server mod_rewrite RCE",
            "content": "Vulnerability description without exploit details.",
            "published_at": pub_time.isoformat(),
            "severity": "critical",
            "exploit_mentioned": 0,
        })
    for i in range(10):  # Recent: 10 records (surging)
        pub_time = base_time - timedelta(days=i)
        rec_rce.append({
            "source": "Exploit.in" if i % 2 == 0 else "AlienVault OTX",
            "source_type": "dark_web" if i % 2 == 0 else "public_api",
            "title": f"PoC Exploit released for Apache RCE CVE-2025-99999 {i}",
            "content": "Working exploit script for remote code execution.",
            "published_at": pub_time.isoformat(),
            "severity": "critical",
            "exploit_mentioned": 1,
        })
    records["eval_cve_2025_rce"] = rec_rce

    # 3. eval_blacklock (Escalated: True)
    # Emerging ransomware, moderate frequency, positive growth (recent 4, prior 2)
    rec_blacklock = []
    for i in range(2):  # Prior
        pub_time = base_time - timedelta(days=20 + i)
        rec_blacklock.append({
            "source": "RAMP",
            "source_type": "dark_web",
            "title": "BlackLock ransomware affiliate launch",
            "content": "Launching program.",
            "published_at": pub_time.isoformat(),
            "severity": "high",
            "exploit_mentioned": 0,
        })
    for i in range(6):  # Recent
        pub_time = base_time - timedelta(days=i * 2)
        rec_blacklock.append({
            "source": "XSS.is" if i % 2 == 0 else "BreachForums",
            "source_type": "dark_web",
            "title": f"BlackLock targets compromised {i}",
            "content": "Details of targets and payouts.",
            "published_at": pub_time.isoformat(),
            "severity": "high",
            "exploit_mentioned": 0,
        })
    records["eval_blacklock"] = rec_blacklock

    # 4. eval_apt29 (Escalated: True)
    # Steady high diversity, moderate volume (recent 5, prior 4), stable growth
    rec_apt29 = []
    for i in range(4):  # Prior
        pub_time = base_time - timedelta(days=16 + i * 3)
        rec_apt29.append({
            "source": "AlienVault OTX" if i % 2 == 0 else "PublicReport",
            "source_type": "public_api",
            "title": f"APT29 cyber operations bulletin {i}",
            "content": "Steady state operations.",
            "published_at": pub_time.isoformat(),
            "severity": "medium",
            "exploit_mentioned": 0,
        })
    for i in range(5):  # Recent
        pub_time = base_time - timedelta(days=1 + i * 2)
        rec_apt29.append({
            "source": "BreachForums" if i % 2 == 0 else "XSS.is",
            "source_type": "dark_web",
            "title": f"APT29 indicators dump part {i}",
            "content": "Malware hashes and domains.",
            "published_at": pub_time.isoformat(),
            "severity": "high",
            "exploit_mentioned": 0,
        })
    records["eval_apt29"] = rec_apt29

    # 5. eval_dormant_cve (Escalated: False)
    # Old records only (days 35-50 ago), no recent activity
    rec_dormant = []
    for i in range(5):
        pub_time = base_time - timedelta(days=35 + i * 2)
        rec_dormant.append({
            "source": "NVD",
            "source_type": "public_api",
            "title": "CVE-2023-00001 details",
            "content": "Vulnerability in legacy software.",
            "published_at": pub_time.isoformat(),
            "severity": "medium",
            "exploit_mentioned": 0,
        })
    records["eval_dormant_cve"] = rec_dormant

    # 6. eval_low_chatter (Escalated: False)
    # Only 1 record, low frequency, 1 source, no exploit
    records["eval_low_chatter"] = [
        {
            "source": "NVD",
            "source_type": "public_api",
            "title": "CVE-2024-99998: Minor vulnerability in parser",
            "content": "Low priority parser bug.",
            "published_at": (base_time - timedelta(days=5)).isoformat(),
            "severity": "low",
            "exploit_mentioned": 0,
        }
    ]

    # 7. eval_stable_medium (Escalated: False)
    # Flat growth (recent 4, prior 4), no exploit, 1 source
    rec_stable = []
    for i in range(4):  # Prior
        pub_time = base_time - timedelta(days=15 + i * 3)
        rec_stable.append({
            "source": "AlienVault OTX",
            "source_type": "public_api",
            "title": f"OTX Pulse stable chatter indicator {i}",
            "content": "Regular security telemetry.",
            "published_at": pub_time.isoformat(),
            "severity": "medium",
            "exploit_mentioned": 0,
        })
    for i in range(4):  # Recent
        pub_time = base_time - timedelta(days=1 + i * 3)
        rec_stable.append({
            "source": "AlienVault OTX",
            "source_type": "public_api",
            "title": f"OTX Pulse stable chatter indicator recent {i}",
            "content": "Regular security telemetry.",
            "published_at": pub_time.isoformat(),
            "severity": "medium",
            "exploit_mentioned": 0,
        })
    records["eval_stable_medium"] = rec_stable

    return records

def setup_validation_db() -> dict[str, bool]:
    """
    Cleans up any existing evaluation threats in the DB and inserts
    the curated validation records. Returns the ground-truth dictionary.
    """
    base_time = datetime.now(timezone.utc)
    dataset = get_curated_records(base_time)
    
    conn = get_connection()
    try:
        # Clear existing validation data
        for keyword in VALIDATION_GROUND_TRUTH.keys():
            # Get query ID if it exists
            cursor = conn.execute(
                "SELECT id FROM threat_queries WHERE keyword = ?",
                (keyword,),
            )
            row = cursor.fetchone()
            if row:
                query_id = row["id"]
                conn.execute(
                    "DELETE FROM collected_intel WHERE query_id = ?",
                    (query_id,),
                )
                conn.execute(
                    "DELETE FROM threat_queries WHERE id = ?",
                    (query_id,),
                )
        conn.commit()
    finally:
        conn.close()

    # Insert clean curated records
    for keyword, recs in dataset.items():
        query_id = get_or_create_query(keyword)
        to_insert = [{**rec, "query_id": query_id} for rec in recs]
        insert_intel_records(to_insert)
        logger.info("Setup evaluation DB: inserted %d records for '%s'", len(to_insert), keyword)

    return VALIDATION_GROUND_TRUTH
