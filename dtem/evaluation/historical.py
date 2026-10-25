"""Utilities for building leakage-safe CVE evaluation inputs from real observations.

Input is JSON Lines. Each observation needs an exact CVE identifier and an
``available_at`` timestamp (when DTEM could first have known it); source
publication time alone is insufficient for a retrospective cutoff. This module
does not fabricate missing CTI, EPSS, CVSS, or KEV observations.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def match_cve_records(records: Iterable[dict[str, Any]], cve_id: str) -> list[dict[str, Any]]:
    """Match only an exact CVE token in explicit identifiers/text/URL/raw payload."""
    wanted = cve_id.upper()
    if not CVE_RE.fullmatch(wanted):
        raise ValueError("cve_id must be a complete CVE identifier")
    matched = []
    for record in records:
        if str(record.get("source", "")).strip().casefold() == "nvd":
            raw_data = record.get("raw_data", {})
            if isinstance(raw_data, str):
                try:
                    raw_data = json.loads(raw_data)
                except json.JSONDecodeError:
                    raw_data = {}
            raw_cve = raw_data.get("cve", {}) if isinstance(raw_data, dict) else {}
            explicit = str(record.get("cve_id") or raw_cve.get("id") or "").upper()
            if not explicit:
                title = str(record.get("title", ""))
                url = str(record.get("url", ""))
                title_match = CVE_RE.match(title)
                url_match = re.search(r"/detail/(CVE-\d{4}-\d{4,})\b", url, re.IGNORECASE)
                explicit = (title_match or url_match).group(0 if title_match else 1).upper() if title_match or url_match else ""
            if explicit == wanted:
                matched.append(record)
            continue
        identifiers = [record.get("cve_id", ""), record.get("title", ""),
                       record.get("content", ""), record.get("url", ""),
                       json.dumps(record.get("raw_data", {}), sort_keys=True)]
        if any(wanted in {token.upper() for token in CVE_RE.findall(str(value))} for value in identifiers):
            matched.append(record)
    return matched


def observations_available_by(records: Iterable[dict[str, Any]], cutoff: datetime) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep timestamped, genuine records available and published by cutoff."""
    cutoff = parse_time(cutoff)
    if cutoff is None:
        raise ValueError("cutoff must be a valid datetime")
    included, missing, missing_publication, future, prototype = [], 0, 0, 0, 0
    for record in records:
        raw_data = record.get("raw_data", {})
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except json.JSONDecodeError:
                raw_data = {}
        if (record.get("prototype_data") or record.get("source") == "DarkWeb-Simulator"
                or (isinstance(raw_data, dict) and raw_data.get("generated") is True)):
            prototype += 1
            continue
        # Dark-web items are excluded from historical evaluation unless a
        # collector explicitly marks them as captured from a real source.
        if record.get("source_type") == "dark_web" and record.get("historical_capture") is not True:
            prototype += 1
            continue
        available = parse_time(record.get("available_at") or record.get("collected_at"))
        published = parse_time(record.get("published_at"))
        if available is None:
            missing += 1
        elif published is None:
            missing_publication += 1
        elif available > cutoff:
            future += 1
        elif published > cutoff:
            # A future-dated source publication is inconsistent with the cutoff.
            future += 1
        else:
            included.append(record)
    return included, {"included": len(included), "missing_availability": missing,
                      "missing_publication": missing_publication,
                      "after_cutoff": future, "prototype_or_unverified_dark_web": prototype}


def kev_outcome(kev_record: dict[str, Any] | None, cutoff: datetime, horizon_days: int) -> dict[str, Any]:
    """Label subsequent KEV inclusion; absence means not listed, not unexploited."""
    if horizon_days <= 0:
        raise ValueError("horizon_days must be positive")
    cutoff = parse_time(cutoff)
    if cutoff is None:
        raise ValueError("cutoff must be a valid datetime")
    added = parse_time((kev_record or {}).get("dateAdded"))
    end = cutoff + timedelta(days=horizon_days)
    event = added is not None and cutoff < added <= end
    return {
        "outcome": int(event),
        "event_time": added.isoformat() if event else None,
        "horizon_days": horizon_days,
        "definition": "CISA KEV dateAdded falls strictly after cutoff and within horizon",
        "interpretation": "KEV inclusion is a future exploitation-related catalog outcome; non-inclusion is not evidence of no exploitation.",
    }


def kev_history_outcome(events: Iterable[dict[str, Any]], cutoff: datetime,
                        horizon_days: int, *, history_start: Any,
                        complete_through: Any) -> dict[str, Any]:
    """Label a KEV window only when the versioned catalog covers the full window.

    Addition dates define the target. Versioned removal/revision events are
    retained for auditability; a later removal does not erase an earlier
    dateAdded event. If the archived source does not span the cutoff and full
    horizon, the label is unknown rather than negative.
    """
    if horizon_days <= 0:
        raise ValueError("horizon_days must be positive")
    cutoff = parse_time(cutoff)
    start, complete = parse_time(history_start), parse_time(complete_through)
    if cutoff is None:
        raise ValueError("cutoff must be a valid datetime")
    horizon_end = cutoff + timedelta(days=horizon_days)
    if start is None or complete is None or start > cutoff or complete < horizon_end:
        return {"outcome": None, "event_time": None, "status": "history_coverage_insufficient",
                "horizon_days": horizon_days,
                "interpretation": "Archived catalog history does not cover the cutoff and complete prediction horizon."}
    for event in events:
        if str(event.get("state", "")).casefold() != "added":
            continue
        added = parse_time(event.get("dateAdded"))
        if added is not None and cutoff < added <= horizon_end:
            return {"outcome": 1, "event_time": added.isoformat(), "status": "kev_added_in_horizon",
                    "horizon_days": horizon_days,
                    "interpretation": "CISA KEV catalog dateAdded falls strictly after cutoff and within horizon; this is not exploitation onset."}
    return {"outcome": 0, "event_time": None, "status": "no_kev_addition_in_horizon",
            "horizon_days": horizon_days,
            "interpretation": "No catalog addition was observed in the fully covered horizon; this does not prove the vulnerability was not exploited."}


def lead_time(event_time: Any, alert_time: Any,
              outcome_positive: bool | None = None) -> dict[str, Any]:
    """Compute event minus first valid alert and label false/missed alerts explicitly."""
    event, alert = parse_time(event_time), parse_time(alert_time)
    if event is None:
        if outcome_positive is False:
            status = "false_alert" if alert is not None else "no_event_no_alert"
        elif outcome_positive is True:
            status = "event_time_missing"
        else:
            status = "missing_event_time"
        return {"status": status, "lead_days": None}
    if alert is None:
        return {"status": "missed_event", "lead_days": None}
    delta = (event - alert).total_seconds() / 86400
    return {"status": "early" if delta > 0 else "on_time" if delta == 0 else "late", "lead_days": delta}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_manifest(path: Path, records: list[dict[str, Any]], *, retrieved_at: datetime,
                   source: str, date_coverage: dict[str, Any]) -> None:
    """Write source provenance and record count beside a JSONL dataset."""
    manifest = {
        "source": source,
        "retrieved_at": retrieved_at.astimezone(timezone.utc).isoformat(),
        "record_count": len(records),
        "date_coverage": date_coverage,
        "timestamp_policy": "available_at governs historical eligibility; missing values are excluded",
    }
    path.with_suffix(path.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
