"""Reproducible public-data snapshot collection and leakage-safe KEV backtest.

Snapshots are recorded with retrieval time. Current NVD/EPSS responses are not
retroactively treated as historically available observations. Backtests require
an archived observation JSONL whose ``available_at`` and ``published_at`` are
both verified and at or before each cutoff.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from dtem.evaluation.historical import (
    CVE_RE, kev_history_outcome, kev_outcome,
    observations_available_by, parse_time,
)
from dtem.evaluation.ablation import run_ablation
from dtem.evaluation.baselines import run_baselines
from dtem.evaluation.diagnostics import feature_correlation, source_independence_audit
from dtem.evaluation.metrics import alert_budget_metrics, bootstrap_pr_auc_ci, pr_auc
from dtem.evaluation.split import chronological_split
from dtem.evaluation.weight_learning import run_weight_learning
from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "historical"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
GHSA_URL = "https://api.github.com/advisories"


def _get_json(session: requests.Session, url: str, *, params: dict[str, Any] | None,
              headers: dict[str, str], timeout: int) -> Any:
    response = session.get(url, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.json()


def collect_public_snapshots(output_dir: Path = DATA_DIR, *, timeout: int = 30) -> dict[str, Any]:
    """Save genuine current API snapshots, recording retrieval time and errors.

    NVD API key is optional and read only from ``NVD_API_KEY``. Nothing here
    implies that the API response was available before its retrieval timestamp.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    session = requests.Session()
    sources: dict[str, tuple[str, dict[str, Any] | None]] = {
        "nvd": (NVD_URL, {"resultsPerPage": 2000}),
        "kev": (KEV_URL, None),
    }
    manifest: dict[str, Any] = {
        "retrieved_at": retrieved.isoformat(),
        "snapshot_semantics": "current response as retrieved; not a historical availability archive",
        "sources": {},
    }
    headers = {"Accept": "application/json"}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    for name, (url, params) in sources.items():
        source_time = datetime.now(timezone.utc)
        try:
            payload = _get_json(session, url, params=params, headers=headers, timeout=timeout)
            records = payload.get("vulnerabilities", []) if name == "nvd" else payload.get("vulnerabilities", [])
            path = output_dir / f"{name}_{stamp}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            manifest["sources"][name] = {
                "url": url, "retrieved_at": source_time.isoformat(), "status": "ok",
                "record_count": len(records), "file": path.name,
                "total_results": payload.get("totalResults") if name == "nvd" else len(records),
                "truncated": bool(name == "nvd" and payload.get("totalResults", 0) > len(records)),
                "date_fields": ("published", "lastModified") if name == "nvd" else ("dateAdded",),
                "availability_policy": "available no earlier than retrieved_at; response dates do not establish historical availability",
            }
        except (requests.RequestException, ValueError, OSError) as exc:
            manifest["sources"][name] = {
                "url": url, "retrieved_at": source_time.isoformat(),
                "status": "error", "record_count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            }
    manifest_path = output_dir / f"manifest_{stamp}.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def collect_nvd_history(start_date: str, end_date: str, output_dir: Path = DATA_DIR,
                        *, timeout: int = 30, request_delay: float = 6.0) -> dict[str, Any]:
    """Archive NVD CVE change events with their actual event timestamps.

    These are one-source NVD record-change observations, not independent CTI
    reports. NVD documents a maximum 120-day date range per request and a
    5,000-record page limit. The default delay follows NVD's unauthenticated
    request guidance; set NVD_API_KEY and an appropriate delay if authorized.
    """
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()
    if end < start:
        raise ValueError("end_date must be on or after start_date")
    if request_delay < 0:
        raise ValueError("request_delay must be non-negative")
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    headers = {"Accept": "application/json"}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    session = requests.Session()
    events_by_id: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    request_count = 0
    current = start
    while current <= end:
        window_end = min(end, current + timedelta(days=119))
        params_base = {
            "changeStartDate": f"{current.isoformat()}T00:00:00.000Z",
            "changeEndDate": f"{window_end.isoformat()}T23:59:59.999Z",
            "resultsPerPage": 5000,
        }
        start_index = 0
        total_results: int | None = None
        while total_results is None or start_index < total_results:
            params = {**params_base, "startIndex": start_index}
            try:
                payload = _get_json(session, NVD_HISTORY_URL, params=params,
                                    headers=headers, timeout=timeout)
                request_count += 1
                page = payload.get("cveChanges", [])
                total_results = int(payload.get("totalResults", len(page)))
                for item in page:
                    # NVD wraps each history event in a top-level ``change`` key.
                    event = item.get("change", item) if isinstance(item, dict) else {}
                    cve = str(event.get("cveId", "")).upper()
                    created = parse_time(event.get("created"))
                    event_id = str(event.get("cveChangeId") or "")
                    if not cve or not CVE_RE.fullmatch(cve) or created is None:
                        continue
                    if not event_id:
                        event_id = f"{cve}|{created.isoformat()}|{event.get('eventName', '')}"
                    observed = {
                        "cve_id": cve,
                        "source": "NVD",
                        "source_type": "public_api",
                        "event_id": event_id,
                        "title": str(event.get("eventName", "NVD CVE change")),
                        "content": json.dumps(event.get("details", []), ensure_ascii=False, sort_keys=True),
                        "published_at": created.isoformat(),
                        "available_at": created.isoformat(),
                        "timestamp_semantics": "NVD event created time; used only as an earliest-availability proxy because separate public release time is not provided",
                        "source_identifier": event.get("sourceIdentifier"),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        "raw_data": item,
                    }
                    events_by_id[event_id] = observed
                if not page and start_index < total_results:
                    errors.append({"window_start": current.isoformat(), "window_end": window_end.isoformat(),
                                   "start_index": start_index, "error": "empty page before totalResults was reached"})
                    break
                start_index += len(page)
                if request_delay > 0 and start_index < total_results:
                    time.sleep(request_delay)
            except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
                errors.append({"window_start": current.isoformat(), "window_end": window_end.isoformat(),
                               "start_index": start_index, "error": f"{type(exc).__name__}: {exc}"})
                break
        if request_delay > 0 and window_end < end:
            time.sleep(request_delay)
        current = window_end + timedelta(days=1)

    events = sorted(events_by_id.values(), key=lambda row: (row["published_at"], row["event_id"]))
    path = output_dir / f"nvd_history_{start.isoformat()}_{end.isoformat()}_{stamp}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    manifest = {
        "source": "NVD CVE Change History API v2.0", "source_url": NVD_HISTORY_URL,
        "retrieved_at": retrieved.isoformat(), "status": "partial_error" if errors else "ok",
        "requested_start_inclusive": start.isoformat(), "requested_end_inclusive": end.isoformat(),
        "request_count": request_count, "unique_event_count": len(events),
        "distinct_cves": len({row["cve_id"] for row in events}), "file": path.name,
        "errors": errors,
        "timestamp_policy": "NVD event created timestamp is preserved as event time and used as an earliest-availability proxy; NVD does not provide a separate public release time, so this is not verified public availability",
        "unit_limit": "NVD change events are a single-source record-history signal, not independent CTI reports; source diversity remains one, and event counts reflect NVD workflow updates",
    }
    (output_dir / f"nvd_history_{start.isoformat()}_{end.isoformat()}_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def import_kev_git_history(repo_path: Path, output_dir: Path = DATA_DIR,
                           *, timeout: int = 30) -> dict[str, Any]:
    """Convert CISA's official kev-data Git history into auditable state events.

    Clone/fetch the repository separately. This records additions, removals,
    and dateAdded revisions from each catalog snapshot without storing every
    full catalog copy. Coverage starts at the first versioned snapshot only.
    """
    source_file = "known_exploited_vulnerabilities.json"
    log = subprocess.run(
        ["git", "-C", str(repo_path), "log", "--format=%H%x09%cI", "--reverse", "--", source_file],
        check=True, capture_output=True, text=True, timeout=timeout,
    ).stdout
    commits = [line.split("\t", 1) for line in log.splitlines() if "\t" in line]
    if not commits:
        raise ValueError("No CISA KEV catalog history found in the supplied Git repository")
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    previous: dict[str, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    snapshot_metadata: list[dict[str, Any]] = []
    snapshot_errors: list[dict[str, str]] = []
    coverage_intervals: list[dict[str, str]] = []
    gap_open = False
    for sha, committed_at in commits:
        payload_text = subprocess.run(
            ["git", "-C", str(repo_path), "show", f"{sha}:{source_file}"],
            check=True, capture_output=True, text=True, timeout=timeout,
        ).stdout
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            snapshot_errors.append({"commit": sha, "error": str(exc)})
            gap_open = True
            continue
        rows = payload.get("vulnerabilities", [])
        if int(payload.get("count", -1)) != len(rows):
            raise ValueError(f"CISA catalog count mismatch at commit {sha}")
        current = {str(row.get("cveID", "")).upper(): row for row in rows
                   if CVE_RE.fullmatch(str(row.get("cveID", "")).upper())}
        committed = parse_time(committed_at)
        released = parse_time(payload.get("dateReleased"))
        if committed is None or released is None:
            raise ValueError(f"Unparseable CISA snapshot timestamp at commit {sha}")
        snapshot_metadata.append({"commit": sha, "committed_at": committed.isoformat(),
                                  "date_released": released.isoformat(),
                                  "catalog_version": payload.get("catalogVersion"),
                                  "count": len(current)})
        released_iso = released.isoformat()
        if not coverage_intervals:
            coverage_intervals.append({"start": released_iso, "complete_through": released_iso})
            gap_open = False
        elif gap_open and released > parse_time(coverage_intervals[-1]["complete_through"]):
            coverage_intervals.append({"start": released_iso, "complete_through": released_iso})
            gap_open = False
        else:
            coverage_intervals[-1]["complete_through"] = released_iso
            gap_open = False
        for cve in sorted(current.keys() - previous.keys()):
            events.append({"cve_id": cve, "state": "added", "snapshot_at": committed.isoformat(),
                           "dateAdded": current[cve].get("dateAdded"), "source_commit": sha,
                           "raw_data": current[cve]})
        for cve in sorted(previous.keys() - current.keys()):
            events.append({"cve_id": cve, "state": "removed", "snapshot_at": committed.isoformat(),
                           "dateAdded": previous[cve].get("dateAdded"), "source_commit": sha,
                           "raw_data": previous[cve]})
        for cve in sorted(current.keys() & previous.keys()):
            old_date = previous[cve].get("dateAdded")
            new_date = current[cve].get("dateAdded")
            if old_date != new_date:
                events.append({"cve_id": cve, "state": "date_revised", "snapshot_at": committed.isoformat(),
                               "old_dateAdded": old_date, "dateAdded": new_date,
                               "source_commit": sha, "raw_data": current[cve]})
        previous = current
    events.sort(key=lambda row: (row["snapshot_at"], row["cve_id"], row["state"]))
    first_snapshot, last_snapshot = snapshot_metadata[0], snapshot_metadata[-1]
    output_path = output_dir / f"kev_history_{first_snapshot['date_released'][:10]}_{last_snapshot['date_released'][:10]}_{stamp}.jsonl"
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    manifest = {
        "source": "CISA official kev-data Git mirror", "repository": "https://github.com/cisagov/kev-data",
        "source_file": source_file, "retrieved_at": retrieved.isoformat(),
        "status": "partial_error" if snapshot_errors else "ok",
        "snapshot_count": len(snapshot_metadata), "commit_count": len(commits),
        "event_count": len(events), "added_events": sum(row["state"] == "added" for row in events),
        "removed_events": sum(row["state"] == "removed" for row in events),
        "date_revisions": sum(row["state"] == "date_revised" for row in events),
        "history_start": first_snapshot["date_released"],
        "complete_through": last_snapshot["date_released"],
        "first_commit": first_snapshot["commit"], "last_commit": last_snapshot["commit"],
        "file": output_path.name, "snapshots": snapshot_metadata,
        "errors": snapshot_errors,
        "coverage_intervals": coverage_intervals,
        "coverage_policy": "Each repository snapshot is the CISA catalog mirrored at that release; history is treated as complete only from the first recorded snapshot through the last. CISA may rarely remove entries, so removals are retained as events.",
    }
    (output_dir / f"{output_path.stem}.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    output_path.with_suffix(output_path.suffix + ".coverage.json").write_text(
        json.dumps({"history_start": manifest["history_start"],
                    "complete_through": manifest["complete_through"],
                    "coverage_intervals": coverage_intervals,
                    "source": manifest["source"],
                    "first_commit": manifest["first_commit"],
                    "last_commit": manifest["last_commit"]}, indent=2),
        encoding="utf-8")
    return manifest


def collect_ghsa_history(start_date: str, end_date: str, output_dir: Path = DATA_DIR,
                         *, timeout: int = 30, per_page: int = 100, max_pages: int = 60,
                         request_delay: float = 0.5) -> dict[str, Any]:
    """Archive GitHub Security Advisories (GHSA) with their real published time.

    GHSA is an independent publisher whose ``publishedAt`` is the moment GitHub
    made the advisory public, so it is a verifiable historical availability time
    (unlike a current NVD record whose present state cannot be back-dated). One
    advisory may reference a CVE that NVD also reports, giving genuine
    multi-source corroboration with distinct first-seen times.

    Enumerates reviewed advisories whose publish date falls in the inclusive
    ``start_date``..``end_date`` window, paginating up to ``max_pages``. A
    ``GITHUB_TOKEN`` in the environment raises the rate limit; unauthenticated
    use is capped by GitHub (about 60 requests/hour), so partial coverage is
    recorded in the manifest rather than silently truncated. Missing CVE mappings
    and unparseable dates are skipped, never guessed.
    """
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()
    if end < start:
        raise ValueError("end_date must be on or after start_date")
    if per_page <= 0 or per_page > 100:
        raise ValueError("per_page must be in 1..100")
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    session = requests.Session()
    observations: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    request_count = 0
    published_range = f"{start.isoformat()}..{end.isoformat()}"
    for page in range(1, max_pages + 1):
        try:
            payload = _get_json(session, GHSA_URL, params={
                "per_page": per_page, "page": page, "type": "reviewed",
                "published": published_range, "sort": "published", "direction": "asc",
            }, headers=headers, timeout=timeout)
            request_count += 1
        except (requests.RequestException, ValueError) as exc:
            errors.append({"page": page, "error": f"{type(exc).__name__}: {exc}"})
            break
        advisories = payload if isinstance(payload, list) else []
        if not advisories:
            break
        for advisory in advisories:
            cve = str(advisory.get("cve_id") or "").upper()
            ghsa_id = str(advisory.get("ghsa_id") or "")
            published = parse_time(advisory.get("published_at"))
            if not CVE_RE.fullmatch(cve) or published is None or not ghsa_id:
                continue
            cvss = (advisory.get("cvss") or {})
            score = cvss.get("score")
            severity = str(advisory.get("severity") or "")
            record = {
                "cve_id": cve, "source": "GitHub Advisory (GHSA)", "source_type": "public_api",
                "event_id": ghsa_id, "ghsa_id": ghsa_id,
                "title": str(advisory.get("summary") or f"GHSA {ghsa_id}"),
                "content": str(advisory.get("description") or "")[:2000],
                "published_at": published.isoformat(),
                "available_at": published.isoformat(),
                "timestamp_semantics": "GitHub advisory publishedAt is the time GitHub made it publicly visible; used as verified historical availability",
                "url": str(advisory.get("html_url") or f"https://github.com/advisories/{ghsa_id}"),
                "severity": f"CVSS {score} ({severity})" if score is not None else severity,
                "cvss_vector": cvss.get("vector_string"),
                "references": [r.get("url") for r in (advisory.get("references") or []) if isinstance(r, dict)],
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "raw_data": {"ghsa_id": ghsa_id, "cve_id": cve, "severity": severity,
                             "cvss": cvss, "vulnerabilities": advisory.get("vulnerabilities")},
            }
            observations[ghsa_id] = record
        if len(advisories) < per_page:
            break
        if request_delay > 0:
            time.sleep(request_delay)

    events = sorted(observations.values(), key=lambda row: (row["published_at"], row["event_id"]))
    path = output_dir / f"ghsa_history_{start.isoformat()}_{end.isoformat()}_{stamp}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    distinct_dates = {row["published_at"][:10] for row in events}
    manifest = {
        "source": "GitHub Security Advisories REST API", "source_url": GHSA_URL,
        "retrieved_at": retrieved.isoformat(), "status": "partial_error" if errors else "ok",
        "requested_start_inclusive": start.isoformat(), "requested_end_inclusive": end.isoformat(),
        "request_count": request_count, "advisory_count": len(events),
        "distinct_cves": len({row["cve_id"] for row in events}),
        "distinct_publish_dates": len(distinct_dates), "file": path.name, "errors": errors,
        "authenticated": bool(os.environ.get("GITHUB_TOKEN")),
        "timestamp_policy": "advisory publishedAt governs historical availability and equals available_at; no date is back-dated",
        "unit_limit": "GitHub advisories are one additional independent publisher; overlap with NVD gives genuine corroboration, but GHSA skews toward open-source packages and may publish after NVD for the same CVE",
    }
    (output_dir / f"ghsa_history_{start.isoformat()}_{end.isoformat()}_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def collect_ghsa_for_cves(cve_ids: list[str], output_dir: Path = DATA_DIR,
                          *, timeout: int = 30, request_delay: float = 0.8) -> dict[str, Any]:
    """Look up specific CVEs in GHSA to get their advisory publishedAt timestamps.

    Unlike the range-based ``collect_ghsa_history`` that paginates the entire
    advisory list (rate-limit-heavy), this queries one CVE at a time — only
    N requests for N CVEs — so 12 positives use 12 of 60 unauthenticated calls.
    Each GHSA advisory gives a verifiable publication date from an independent
    publisher, making it a genuine second/third observation source whose
    published_at ≤ cutoff is leakage-safe.
    """
    unique = sorted({c.upper().strip() for c in cve_ids
                     if CVE_RE.fullmatch(c.upper().strip())})
    if not unique:
        raise ValueError("At least one valid CVE ID is required")
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    session = requests.Session()
    observations: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    cves_with_advisories: set[str] = set()
    for cve in unique:
        try:
            advisories = _get_json(session, GHSA_URL,
                                   params={"cve_id": cve, "type": "reviewed", "per_page": 10},
                                   headers=headers, timeout=timeout)
            if not isinstance(advisories, list):
                advisories = []
            cves_with_advisories.add(cve)
            for advisory in advisories:
                ghsa_id = str(advisory.get("ghsa_id") or "")
                published = parse_time(advisory.get("published_at"))
                if not ghsa_id or published is None:
                    continue
                record = {
                    "cve_id": cve,
                    "source": "GitHub Advisory (GHSA)",
                    "source_type": "security_advisory",
                    "event_id": ghsa_id,
                    "title": str(advisory.get("summary") or f"GHSA {ghsa_id}"),
                    "content": str(advisory.get("description") or "")[:2000],
                    "published_at": published.isoformat(),
                    "available_at": published.isoformat(),
                    "timestamp_semantics": "GitHub advisory publishedAt is the moment it became publicly visible; verified historical availability",
                    "url": str(advisory.get("html_url") or f"https://github.com/advisories/{ghsa_id}"),
                    "severity": str(advisory.get("severity") or ""),
                    "retrieved_at": datetime.now(timezone.utc).isoformat(),
                }
                observations[ghsa_id] = record
        except (requests.RequestException, ValueError, TypeError) as exc:
            errors.append({"cve": cve, "error": f"{type(exc).__name__}: {exc}"})
        if request_delay > 0:
            time.sleep(request_delay)
    events = sorted(observations.values(), key=lambda r: (r["published_at"], r["event_id"]))
    path = output_dir / f"ghsa_targeted_{stamp}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    manifest = {
        "source": "GitHub Security Advisories (targeted CVE lookup)",
        "method": "per-CVE API call (minimal rate-budget)",
        "retrieved_at": retrieved.isoformat(),
        "authenticated": bool(os.environ.get("GITHUB_TOKEN")),
        "status": "partial_error" if errors else "ok",
        "cves_requested": len(unique),
        "cves_with_advisories": len(cves_with_advisories),
        "advisory_count": len(events),
        "distinct_cves": len({r["cve_id"] for r in events}),
        "file": path.name, "errors": errors,
        "timestamp_policy": "publishedAt governs availability; no back-dating",
    }
    (output_dir / f"ghsa_targeted_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def merge_observation_files(paths: list[Path], output_path: Path, *,
                            source_label: str | None = None) -> dict[str, Any]:
    """Concatenate timestamped observation JSONL files into one multi-source set.

    De-duplicates on (source, url, event_id, published_at) so re-importing the
    same archive does not inflate detection frequency. Records lacking a CVE
    association or a verifiable available_at are preserved unchanged; the
    backtest still excludes what it cannot place before a cutoff. The manifest
    records per-source counts so a reviewer can see the cohort is genuinely
    multi-source rather than one source copied under two labels.
    """
    if not paths:
        raise ValueError("at least one observation file is required")
    seen: set[tuple[Any, ...]] = set()
    merged: list[dict[str, Any]] = []
    per_source: dict[str, int] = {}
    duplicates = 0
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            identity = (str(row.get("source", "")).casefold(), str(row.get("url", "")),
                        str(row.get("event_id", "")), str(row.get("published_at", "")))
            if identity in seen:
                duplicates += 1
                continue
            seen.add(identity)
            if source_label:
                row["merged_source"] = source_label
            source = str(row.get("source") or "unknown")
            per_source[source] = per_source.get(source, 0) + 1
            merged.append(row)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in merged:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest = {
        "merged_record_count": len(merged), "dropped_duplicates": duplicates,
        "inputs": [p.name for p in paths], "output": output_path.name,
        "per_source_counts": per_source, "distinct_sources": len(per_source),
        "distinct_cves": len({r.get("cve_id") for r in merged if r.get("cve_id")}),
    }
    output_path.with_suffix(output_path.suffix + ".manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _extract_cve_tokens_from_path(path: str) -> list[str]:
    """Pull CVE ids declared in a Metasploit module filename (e.g. cve_2021_34527)."""
    found: list[str] = []
    for year, number in re.findall(r"cve[_-]?(\d{4})[_-](\d{3,})", path, re.IGNORECASE):
        token = f"CVE-{year}-{int(number):04d}"
        if CVE_RE.fullmatch(token) and token not in found:
            found.append(token)
    for token in CVE_RE.findall(path):
        upper = token.upper()
        if upper not in found:
            found.append(upper)
    return found


def _parse_msf_add_log(log_text: str, *, modules_prefix: str = "modules") -> tuple[list[dict[str, Any]], int]:
    """Parse ``git log --reverse --diff-filter=A --name-only --format=%cI\t%H`` output.

    Returns (events, added_module_files_scanned). Pure and git-free so the CVE
    extraction and first-add-date assignment can be tested directly. Commit
    headers are lines starting with an ISO date and containing a tab; every
    following non-empty line is a file path added in that commit.
    """
    current_time: str | None = None
    current_sha: str | None = None
    seen: set[tuple[str, str]] = set()
    events: list[dict[str, Any]] = []
    added_files = 0
    for raw in log_text.splitlines():
        line = raw.rstrip("\n")
        if not line:
            continue
        if "\t" in line and re.match(r"\d{4}-\d{2}-\d{2}", line):
            ts, sha = line.split("\t", 1)
            if parse_time(ts) is not None:
                current_time, current_sha = ts, sha
                continue
        path = line.strip()
        if not current_time or not path.startswith(modules_prefix):
            continue
        added_files += 1
        module_type = path.split("/")[1] if path.count("/") >= 2 else ""
        for cve in _extract_cve_tokens_from_path(path):
            key = (cve, path)
            if key in seen:
                continue
            seen.add(key)
            events.append({
                "cve_id": cve, "source": "Metasploit", "source_type": "exploit_module",
                "event_id": f"{cve}|{path}",
                "title": f"Metasploit {module_type or 'module'}: {path.rsplit('/', 1)[-1]}",
                "content": "Public Metasploit exploit module (exploit code available)",
                "published_at": current_time, "available_at": current_time,
                "timestamp_semantics": "metasploit-framework commit date when the module was first added; verifiable public-availability lower bound",
                "url": f"https://github.com/rapid7/metasploit-framework/blob/{current_sha}/{path}",
                "exploit_evidence": "verified_exploit", "module_path": path,
                "raw_data": {"path": path, "added_at": current_time, "source_commit": current_sha},
            })
    return events, added_files


def import_metasploit_git_history(repo_path: Path, output_dir: Path = DATA_DIR,
                                  *, modules_prefix: str = "modules",
                                  timeout: int = 1800) -> dict[str, Any]:
    """Convert the public Metasploit Framework git history into dated exploit events.

    Clone/fetch the repository separately (as with the KEV importer) and point
    ``--repo`` at the local clone. This reads only git *metadata* (commit dates and
    file paths), so a blobless clone is sufficient and no per-file content or API
    access is required. Each module file that names a CVE in its path becomes an
    exploit-availability observation whose ``published_at``/``available_at`` is the
    date that module was first added to the public repository — a verifiable lower
    bound on when that public exploit became available. It never back-dates an
    observation, so it is safe against look-ahead leakage at a cutoff.

    Coverage is limited to modules whose filename declares the CVE; modules named
    only after a product are not captured, and that gap is reported, not hidden.
    """
    log = subprocess.run(
        ["git", "-C", str(repo_path), "log", "--reverse", "--diff-filter=A",
         "--name-only", "--format=%cI%x09%H", "--", modules_prefix],
        check=True, capture_output=True, text=True, timeout=timeout,
    ).stdout
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    events, added_files = _parse_msf_add_log(log, modules_prefix=modules_prefix)
    for event in events:
        event["retrieved_at"] = retrieved.isoformat()
    events.sort(key=lambda row: (row["published_at"], row["cve_id"], row["module_path"]))
    path_out = output_dir / f"metasploit_history_{stamp}.jsonl"
    with path_out.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    first_ts = events[0]["published_at"] if events else None
    last_ts = events[-1]["published_at"] if events else None
    manifest = {
        "source": "Metasploit Framework git history (rapid7/metasploit-framework)",
        "repository": str(repo_path), "retrieved_at": retrieved.isoformat(),
        "module_add_events_scanned": added_files, "exploit_event_count": len(events),
        "distinct_cves": len({row["cve_id"] for row in events}),
        "earliest_add": first_ts, "latest_add": last_ts, "file": path_out.name,
        "timestamp_policy": "module first-added commit date equals available_at; a lower bound on public exploit availability, never back-dated",
        "coverage_limit": "only modules whose filename declares a CVE id are captured; product-named modules are missed and are not assumed absent",
    }
    (output_dir / f"metasploit_history_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def import_nuclei_git_history(repo_path: Path, output_dir: Path = DATA_DIR,
                              *, pathspec: str = "http/cves",
                              timeout: int = 1800) -> dict[str, Any]:
    """Convert nuclei-templates git history into dated CVE-detection events.

    Nuclei CVE templates are stored at paths like
    ``http/cves/2025/CVE-2025-0108.yaml``, so the CVE is directly in the
    filename. The first-added commit date is a verifiable public-availability
    lower bound — a community detection template was publicly accessible from
    that date onward. This is independent of NVD and Metasploit and provides
    genuine source-diversity evidence for the DTEM model.

    Only CVE-named template adds are scanned (``http/cves`` pathspec), so
    non-CVE workflow templates do not pollute the count.
    """
    log = subprocess.run(
        ["git", "-C", str(repo_path), "log", "--reverse", "--diff-filter=A",
         "--name-only", "--format=%cI%x09%H", "--", pathspec],
        check=True, capture_output=True, text=True, timeout=timeout,
    ).stdout
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    # Reuse the generic path-CVE extraction; pathspec prefix filters non-CVE dirs
    events_raw, added_files = _parse_msf_add_log(log, modules_prefix=pathspec)
    # Convert from Metasploit-specific labels to Nuclei detection
    events: list[dict[str, Any]] = []
    for ev in events_raw:
        ev["source"] = "Nuclei"
        ev["source_type"] = "detection_template"
        ev["title"] = f"Nuclei CVE template: {ev['module_path'].rsplit('/', 1)[-1]}"
        ev["content"] = "Public Nuclei detection template (CVE-specific scan query available)"
        ev["timestamp_semantics"] = (
            "nuclei-templates commit date when the CVE template was first added; "
            "verifiable public-availability lower bound for this detection signal"
        )
        ev["url"] = ev["url"].replace(
            "https://github.com/rapid7/metasploit-framework/blob/",
            f"https://github.com/projectdiscovery/nuclei-templates/blob/",
        )
        # Detection ≠ exploit — remove exploit_evidence tier
        ev.pop("exploit_evidence", None)
        ev["retrieved_at"] = retrieved.isoformat()
        events.append(ev)
    events.sort(key=lambda r: (r["published_at"], r["cve_id"]))
    path_out = output_dir / f"nuclei_history_{stamp}.jsonl"
    with path_out.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    first_ts = events[0]["published_at"] if events else None
    last_ts = events[-1]["published_at"] if events else None
    manifest = {
        "source": "Nuclei Templates git history (projectdiscovery/nuclei-templates)",
        "repository": str(repo_path), "pathspec": pathspec,
        "retrieved_at": retrieved.isoformat(),
        "template_add_events_scanned": added_files,
        "cve_detection_event_count": len(events),
        "distinct_cves": len({r["cve_id"] for r in events}),
        "earliest_add": first_ts, "latest_add": last_ts, "file": path_out.name,
        "timestamp_policy": "template first-added commit date equals available_at; a lower bound on public detection-template availability, never back-dated",
        "coverage_limit": "only CVE-named yaml templates under http/cves are captured; workflow or non-CVE templates are excluded",
    }
    (output_dir / f"nuclei_history_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def collect_epss_snapshots(cve_ids: list[str], output_dir: Path = DATA_DIR,
                           *, timeout: int = 30) -> dict[str, Any]:
    """Collect current EPSS scores in batches; score_date is never backfilled."""
    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    unique = sorted({c.upper() for c in cve_ids if c.upper().startswith("CVE-")})
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for start in range(0, len(unique), 100):
        batch = unique[start:start + 100]
        try:
            payload = _get_json(requests, EPSS_URL, params={"cve": ",".join(batch)},
                                headers={"Accept": "application/json"}, timeout=timeout)
            records.extend(payload.get("data", []))
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"batch {start // 100 + 1}: {type(exc).__name__}: {exc}")
    name = f"epss_{stamp}.json"
    (output_dir / name).write_text(json.dumps(records, indent=2), encoding="utf-8")
    manifest = {
        "source": "FIRST.org EPSS API", "retrieved_at": retrieved.isoformat(),
        "status": "partial_error" if errors else "ok", "requested_cves": len(unique),
        "returned_scores": len(records), "file": name,
        "score_date_field": "date", "historical_policy": "scores apply only to their returned date; no date is inferred",
        "errors": errors,
    }
    (output_dir / f"epss_{stamp}.manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def collect_epss_history(cve_ids: list[str], start_date: str, end_date: str,
                         output_dir: Path = DATA_DIR, *, timeout: int = 30,
                         request_delay: float = 0.15,
                         requested_dates: list[str] | None = None) -> dict[str, Any]:
    """Fetch actual dated EPSS values for CVEs from the FIRST historical API.

    Dates are inclusive. EPSS API date lookups are used for CVE subsets (rather
    than downloading the full population for every day). Returned dates are
    retained verbatim; absent CVE/date pairs are not imputed.
    """
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()
    if end < start:
        raise ValueError("end_date must be on or after start_date")
    if start < datetime(2021, 4, 14).date():
        raise ValueError("FIRST EPSS historical archive begins 2021-04-14")
    unique = sorted({str(c).strip().upper() for c in cve_ids
                     if CVE_RE.fullmatch(str(c).strip())})
    if not unique:
        raise ValueError("At least one CVE identifier is required")
    # FIRST documents a 2,000-character maximum for the CVE query parameter.
    batches: list[list[str]] = []
    batch: list[str] = []
    for cve in unique:
        if len(cve) > 2000:
            raise ValueError("Invalid CVE query value")
        candidate = ",".join(batch + [cve])
        if len(candidate) > 1900 and batch:
            batches.append(batch)
            batch = [cve]
        else:
            batch.append(cve)
    if batch:
        batches.append(batch)

    output_dir.mkdir(parents=True, exist_ok=True)
    retrieved = datetime.now(timezone.utc)
    stamp = retrieved.strftime("%Y%m%dT%H%M%SZ")
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if requested_dates is None:
        score_dates = [start + timedelta(days=offset)
                       for offset in range((end - start).days + 1)]
    else:
        try:
            score_dates = sorted({datetime.strptime(value, "%Y-%m-%d").date()
                                  for value in requested_dates})
        except ValueError as exc:
            raise ValueError("requested_dates must contain YYYY-MM-DD values") from exc
        if not score_dates or any(day < start or day > end for day in score_dates):
            raise ValueError("requested_dates must be non-empty and within the inclusive date range")
    if score_dates[0] < datetime(2021, 4, 14).date():
        raise ValueError("FIRST EPSS historical archive begins 2021-04-14")
    requested_days = len(score_dates)
    session = requests.Session()
    for current in score_dates:
        for batch_index, batch_cves in enumerate(batches):
            try:
                response = _get_json(
                    session, EPSS_URL,
                    params={"cve": ",".join(batch_cves), "date": current.isoformat()},
                    headers={"Accept": "application/json"}, timeout=timeout,
                )
                for row in response.get("data", []):
                    score_date = str(row.get("date", ""))
                    cve = str(row.get("cve", "")).upper()
                    # Do not trust a server response to a different date or CVE.
                    if score_date != current.isoformat() or cve not in batch_cves:
                        continue
                    observations.append({
                        "source": "FIRST.org EPSS historical API",
                        "cve_id": cve,
                        "score_date": score_date,
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                        "epss": row.get("epss"),
                        "percentile": row.get("percentile"),
                    })
            except (requests.RequestException, ValueError) as exc:
                errors.append({"date": current.isoformat(), "batch": str(batch_index + 1),
                               "error": f"{type(exc).__name__}: {exc}"})
            if request_delay > 0:
                time.sleep(request_delay)
    path = output_dir / f"epss_history_{start.isoformat()}_{end.isoformat()}_{stamp}.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in observations:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    manifest = {
        "source": "FIRST.org EPSS historical API", "source_url": EPSS_URL,
        "retrieved_at": retrieved.isoformat(), "status": "partial_error" if errors else "ok",
        "requested_cves": len(unique), "requested_days": requested_days,
        "requested_dates": [day.isoformat() for day in score_dates],
        "requested_start_inclusive": start.isoformat(), "requested_end_inclusive": end.isoformat(),
        "observation_count": len(observations), "distinct_cves": len({r['cve_id'] for r in observations}),
        "distinct_score_dates": len({r['score_date'] for r in observations}),
        "file": path.name, "errors": errors,
        "availability_semantics": "FIRST historical API score_date is retained as a date, not an invented timestamp; a score is eligible only for a cutoff on a later UTC calendar date",
        "model_version_caveat": "EPSS model versions change over time; scores across version transitions are not a stationary series.",
    }
    (output_dir / f"epss_history_{start.isoformat()}_{end.isoformat()}_{stamp}.manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _metric_report(labels: list[int], scores: list[float], threshold: float) -> dict[str, Any]:
    tp = sum(y == 1 and s >= threshold for y, s in zip(labels, scores))
    fp = sum(y == 0 and s >= threshold for y, s in zip(labels, scores))
    fn = sum(y == 1 and s < threshold for y, s in zip(labels, scores))
    tn = sum(y == 0 and s < threshold for y, s in zip(labels, scores))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"threshold": threshold, "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "precision": precision, "recall": recall, "f1": f1,
            "undefined_metrics": [key for key, value in (("precision", precision), ("recall", recall), ("f1", f1)) if value is None]}


def run_temporal_backtest(observations_path: Path, kev_path: Path, output_path: Path,
                          *, start: datetime, end: datetime, step_days: int = 7,
                          horizon_days: int = 30, threshold: float = 50.0,
                          epss_history_path: Path | None = None,
                          epss_threshold: float = 0.1) -> dict[str, Any]:
    """Run cutoff snapshots only where timestamped features and KEV labels exist.

    Input observations JSONL require cve_id, source, published_at,
    available_at/collected_at, title/content. KEV input is the genuine CISA JSON
    feed snapshot or versioned KEV state-event JSONL. A coverage sidecar must
    span each full prediction horizon. Versioned history is preferred because
    current KEV snapshots may omit entries that CISA later removed.
    """
    obs = [json.loads(line) for line in observations_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    # Index exact CVE associations once. The former per-CVE full-scan path was
    # quadratic and impractical for genuine NVD history windows.
    observations_by_cve: dict[str, list[dict[str, Any]]] = {}
    for row in obs:
        if str(row.get("source", "")).strip().casefold() == "nvd":
            raw = row.get("raw_data", {})
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except json.JSONDecodeError:
                    raw = {}
            change = raw.get("change", {}) if isinstance(raw, dict) else {}
            cve = str(row.get("cve_id") or change.get("cveId") or "").upper()
            matched_ids = [cve] if CVE_RE.fullmatch(cve) else []
        else:
            fields = [row.get("cve_id", ""), row.get("title", ""), row.get("content", ""),
                      row.get("url", ""), json.dumps(row.get("raw_data", {}), sort_keys=True)]
            matched_ids = sorted({token.upper() for value in fields
                                  for token in CVE_RE.findall(str(value))})
        for cve in matched_ids:
            observations_by_cve.setdefault(cve, []).append(row)
    epss_rows = []
    if epss_history_path:
        epss_rows = [json.loads(line) for line in epss_history_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    sidecar = kev_path.with_suffix(kev_path.suffix + ".coverage.json")
    kev_history = kev_path.suffix.casefold() == ".jsonl"
    kev: dict[str, dict[str, Any]] = {}
    kev_events: dict[str, list[dict[str, Any]]] = {}
    kev_coverage_start = None
    kev_coverage_intervals: list[tuple[datetime, datetime]] = []
    kev_payload: dict[str, Any] = {}
    if kev_history:
        kev_rows = [json.loads(line) for line in kev_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for event in kev_rows:
            kev_events.setdefault(str(event.get("cve_id", "")).upper(), []).append(event)
    else:
        kev_payload = json.loads(kev_path.read_text(encoding="utf-8"))
        kev = {item.get("cveID", "").upper(): item for item in kev_payload.get("vulnerabilities", [])}
    coverage = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
    complete_through = parse_time(coverage.get("complete_through") or kev_payload.get("complete_through"))
    if kev_history:
        kev_coverage_start = parse_time(coverage.get("history_start"))
        raw_intervals = coverage.get("coverage_intervals") or []
        for interval in raw_intervals:
            interval_start = parse_time(interval.get("start"))
            interval_end = parse_time(interval.get("complete_through"))
            if interval_start and interval_end and interval_start <= interval_end:
                kev_coverage_intervals.append((interval_start, interval_end))
        if not kev_coverage_intervals and kev_coverage_start and complete_through:
            kev_coverage_intervals.append((kev_coverage_start, complete_through))
    if step_days <= 0 or horizon_days <= 0 or start >= end:
        raise ValueError("Require start < end and positive step/horizon")
    if not 0 <= epss_threshold <= 1:
        raise ValueError("epss_threshold must be in [0, 1]")
    extract = ThreatInfoExtractor()
    engine = DTEMScoringEngine()
    epss_by_cve: dict[str, list[dict[str, Any]]] = {}
    for row in epss_rows:
        cve = str(row.get("cve_id", row.get("cve", ""))).upper()
        score_date = str(row.get("score_date", row.get("date", "")))
        try:
            score = float(row.get("epss"))
            parsed_date = datetime.strptime(score_date, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            continue
        if cve and 0 <= score <= 1:
            epss_by_cve.setdefault(cve, []).append({"score_date": parsed_date, "score": score})
    for rows in epss_by_cve.values():
        rows.sort(key=lambda row: row["score_date"])
    predictions: list[dict[str, Any]] = []
    cutoff = start
    while cutoff < end:
        horizon_end = cutoff + timedelta(days=horizon_days)
        coverage_interval = next(((left, right) for left, right in kev_coverage_intervals
                                  if left <= cutoff and right >= horizon_end), None)
        if (complete_through is None or complete_through < horizon_end
                or (kev_history and coverage_interval is None)):
            cutoff += timedelta(days=step_days)
            continue
        cves = sorted(observations_by_cve)
        for cve in cves:
            matched = observations_by_cve[cve]
            eligible, counts = observations_available_by(matched, cutoff)
            if not eligible:
                continue
            freq = extract.calculate_detection_frequency(eligible)
            growth, _, recent_count, previous_count = extract.calculate_growth_rate(eligible, as_of=cutoff)
            growth_available = recent_count + previous_count > 0
            growth_log = extract.calculate_smoothed_log_growth(eligible, as_of=cutoff)[0]
            diversity, _ = extract.calculate_source_diversity(eligible)
            _, exploit_score = extract.classify_exploit_evidence(eligible)
            features = {"detection_frequency": freq, "growth_rate": growth if growth_available else None,
                        "source_diversity": diversity, "exploit_evidence_score": exploit_score}
            features["total_records"] = len(eligible)
            features["growth_data_available"] = growth_available
            features["growth_log_rate"] = growth_log if growth_available else None
            features["cvss_base_score"] = extract._extract_cvss_base_score(eligible)
            score_result = engine.calculate_emergence({
                "keyword": cve, **features,
                "exploit_availability": exploit_score > 0,
                "breakdown": {"exploit_ratio": 1.0 if exploit_score else 0.0},
            })
            label = (kev_history_outcome(kev_events.get(cve, []), cutoff, horizon_days,
                                         history_start=coverage_interval[0],
                                         complete_through=coverage_interval[1])
                     if kev_history else kev_outcome(kev.get(cve), cutoff, horizon_days))
            if label["outcome"] is None:
                continue
            # EPSS archive files provide dates, not intraday publication times.
            # Therefore a score is available only after its UTC score date.
            dated = [row for row in epss_by_cve.get(cve, [])
                     if row["score_date"] < cutoff.astimezone(timezone.utc).date()]
            epss_row = dated[-1] if dated else None
            predictions.append({"cve_id": cve, "cutoff": cutoff.isoformat(),
                                "score": score_result["emergence_score"], "label": label["outcome"],
                                "event_time": label["event_time"], "feature_counts": counts,
                                "feature_available_through": cutoff.isoformat(), "features": features,
                                "epss": epss_row["score"] if epss_row else None,
                                "epss_score_date": epss_row["score_date"].isoformat() if epss_row else None})
        cutoff += timedelta(days=step_days)
    labels = [p["label"] for p in predictions]
    scores = [float(p["score"]) for p in predictions]
    source_counts: dict[str, int] = {}
    for row in obs:
        source = str(row.get("source") or "unknown")
        source_counts[source] = source_counts.get(source, 0) + 1
    nvd_only = bool(source_counts) and set(source_counts) == {"NVD"}
    positive_cves = {p["cve_id"] for p in predictions if p["label"] == 1}
    dtem_ranking = (pr_auc(labels, scores) if predictions
                    else {"status": "no_predictions", "pr_auc": None, "random_baseline": None})
    dtem_bootstrap = (bootstrap_pr_auc_ci(labels, scores) if set(labels) == {0, 1}
                      else {"status": "single_class_or_empty", "point": dtem_ranking.get("pr_auc"),
                            "interval": None})
    if predictions:
        split_summary = chronological_split(predictions, threshold=threshold)
        ablation_summary = run_ablation(predictions, engine, threshold=threshold,
                                        growth_mode=engine.growth_mode)
        baselines_summary = run_baselines(predictions, engine, threshold=threshold,
                                          epss_threshold=epss_threshold, dtem_scores=scores)
        diagnostics_summary = feature_correlation(predictions, engine,
                                                  growth_mode=engine.growth_mode)
        source_audit = source_independence_audit(obs)
        learned_summary = run_weight_learning(predictions, engine, threshold=threshold,
                                              growth_mode=engine.growth_mode)
        dtem_alert_budget = alert_budget_metrics(labels, scores)
    else:
        split_summary = {"status": "no_predictions"}
        ablation_summary = {"status": "no_predictions"}
        baselines_summary = {"status": "no_predictions"}
        diagnostics_summary = {"status": "no_predictions"}
        source_audit = {"status": "no_predictions"}
        learned_summary = {"status": "no_predictions"}
        dtem_alert_budget = {"status": "no_predictions"}
    report = {
        "status": ("exploratory_nvd_only" if predictions and nvd_only else
                   "completed" if predictions else "insufficient_historical_coverage"),
        "evaluation_scope": ("NVD vulnerability-database change events only; this is not CTI evidence and is not a valid evaluation of multi-source DTEM" if nvd_only else
                             "timestamped observations supplied by the caller; assess source suitability before interpreting as DTEM evidence"),
        "observation_source_counts": source_counts,
        "observation_event_count": len(obs),
        "cves_with_observations": len(observations_by_cve),
        "prediction_cutoff_count": len({p["cutoff"] for p in predictions}),
        "unique_cves_with_future_kev_addition": len(positive_cves),
        "task": "CISA KEV dateAdded strictly after cutoff and <= cutoff + horizon",
        "horizon_days": horizon_days, "start": start.isoformat(), "end_exclusive": end.isoformat(),
        "step_days": step_days, "complete_through": complete_through.isoformat() if complete_through else None,
        "kev_label_source": "versioned CISA catalog history" if kev_history else "single CISA KEV snapshot",
        "prediction_count": len(predictions), "eligible_positive": sum(labels),
        "eligible_negative": len(labels) - sum(labels),
        "positive_fraction": sum(labels) / len(labels) if labels else None,
        "metrics": _metric_report(labels, scores, threshold) if predictions else None,
        "epss_baseline": {
            "status": "available" if any(p["epss"] is not None for p in predictions) else "unavailable",
            "comparison_subset": "same prediction rows as DTEM with a historical EPSS score dated before the cutoff UTC date",
            "score_semantics": "FIRST EPSS probability for exploitation in the following 30 days; not rescaled",
            "threshold": epss_threshold,
            "sample_count": sum(p["epss"] is not None for p in predictions),
            "metrics": _metric_report(
                [p["label"] for p in predictions if p["epss"] is not None],
                [float(p["epss"]) for p in predictions if p["epss"] is not None],
                epss_threshold,
            ) if any(p["epss"] is not None for p in predictions) else None,
            "model_version_note": "EPSS versions change over time; comparisons spanning versions require stratification or a documented version policy.",
        },
        "pr_auc": dtem_ranking.get("pr_auc"),
        "pr_auc_status": dtem_ranking.get("status"),
        "pr_auc_random_baseline": dtem_ranking.get("random_baseline"),
        "pr_auc_bootstrap": dtem_bootstrap,
        "dtem_alert_budget": dtem_alert_budget,
        "chronological_split": split_summary,
        "ablation": ablation_summary,
        "baselines": baselines_summary,
        "feature_diagnostics": diagnostics_summary,
        "source_independence_audit": source_audit,
        "learned_weights": learned_summary,
        "limitations": ["KEV is a proxy outcome, not exploitation onset.",
                        "Current source snapshots do not establish historical availability.",
                        "NVD change events are database workflow activity, not independent threat-intelligence detections.",
                        "The chronological split is descriptive; the learned_weights block is what fits on development, selects on validation, and evaluates the test period once.",
                        "Ablation and baseline tables reuse these rows and inherit their scope; they are not validation unless the rows are genuine CTI with both classes.",
                        "Learned-weight comparison fits on development, selects on validation, and reads the test period once; with a single-source cohort it inherits the same scope limitation as every other table here.",
                        "No output is evidence of real-world predictive validity."],
        "predictions": predictions,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("collect", help="save current public API snapshots")
    collect.add_argument("--output-dir", type=Path, default=DATA_DIR)
    nvd_history = commands.add_parser("nvd-history", help="archive timestamped NVD CVE change events")
    nvd_history.add_argument("--start", required=True, help="inclusive YYYY-MM-DD")
    nvd_history.add_argument("--end", required=True, help="inclusive YYYY-MM-DD")
    nvd_history.add_argument("--output-dir", type=Path, default=DATA_DIR)
    nvd_history.add_argument("--request-delay", type=float, default=6.0,
                             help="seconds between NVD pages; default follows unauthenticated guidance")
    epss = commands.add_parser("epss", help="collect date-stamped current EPSS scores")
    epss.add_argument("cves", nargs="+")
    epss.add_argument("--output-dir", type=Path, default=DATA_DIR)
    kev_import = commands.add_parser("import-kev-history", help="convert a local CISA kev-data Git clone to versioned state events")
    kev_import.add_argument("--repo", type=Path, required=True, help="local clone of cisagov/kev-data")
    kev_import.add_argument("--output-dir", type=Path, default=DATA_DIR)
    msf_import = commands.add_parser("import-msf-history", help="convert a local Metasploit Framework git clone into dated exploit observations")
    msf_import.add_argument("--repo", type=Path, required=True, help="local clone of rapid7/metasploit-framework")
    msf_import.add_argument("--output-dir", type=Path, default=DATA_DIR)
    msf_import.add_argument("--timeout", type=int, default=1800,
                            help="seconds for the git-log scan; a full Framework history takes several minutes")
    nuclei_import = commands.add_parser("import-nuclei-history", help="convert a local nuclei-templates git clone into dated CVE-detection observations")
    nuclei_import.add_argument("--repo", type=Path, required=True, help="local clone of projectdiscovery/nuclei-templates")
    nuclei_import.add_argument("--output-dir", type=Path, default=DATA_DIR)
    nuclei_import.add_argument("--pathspec", default="http/cves", help="git pathspec to filter scanned dirs")
    nuclei_import.add_argument("--timeout", type=int, default=1800,
                               help="seconds for the git-log scan")
    epss_history = commands.add_parser("epss-history", help="collect actual daily historical EPSS values for specified CVEs")
    epss_history.add_argument("--cves-file", type=Path, required=True, help="text file with one CVE ID per line")
    epss_history.add_argument("--start", required=True, help="inclusive YYYY-MM-DD (not before 2021-04-14)")
    epss_history.add_argument("--end", required=True, help="inclusive YYYY-MM-DD")
    epss_history.add_argument("--dates-file", type=Path,
                              help="optional sparse YYYY-MM-DD list; requests only these dates within start/end")
    epss_history.add_argument("--output-dir", type=Path, default=DATA_DIR)
    ghsa = commands.add_parser("ghsa", help="archive timestamped GitHub Security Advisories (GHSA)")
    ghsa.add_argument("--start", required=True, help="inclusive YYYY-MM-DD published lower bound")
    ghsa.add_argument("--end", required=True, help="inclusive YYYY-MM-DD published upper bound")
    ghsa.add_argument("--output-dir", type=Path, default=DATA_DIR)
    ghsa.add_argument("--max-pages", type=int, default=60,
                      help="cap pages per run; unauthenticated GitHub is ~60 requests/hour")
    ghsa_cves = commands.add_parser("ghsa-cves", help="query GHSA for specific CVEs (targeted, minimal rate usage)")
    ghsa_cves.add_argument("--cves", nargs="+", required=True, help="CVE IDs to look up (e.g. CVE-2025-0108)")
    ghsa_cves.add_argument("--cves-file", type=Path, help="file with one CVE per line (merged with --cves)")
    ghsa_cves.add_argument("--output-dir", type=Path, default=DATA_DIR)
    ghsa_cves.add_argument("--delay", type=float, default=0.8, help="seconds between API calls")
    merge = commands.add_parser("merge-observations", help="merge timestamped JSONL sources into one set")
    merge.add_argument("--inputs", type=Path, nargs="+", required=True)
    merge.add_argument("--output", type=Path, required=True)
    backtest = commands.add_parser("backtest", help="run against archived timestamped observations")
    backtest.add_argument("--observations", type=Path, required=True)
    backtest.add_argument("--kev", type=Path, required=True)
    backtest.add_argument("--output", type=Path, default=ROOT / "output/evaluation/historical_backtest.json")
    backtest.add_argument("--start", required=True)
    backtest.add_argument("--end", required=True)
    backtest.add_argument("--epss-history", type=Path, help="JSONL from epss-history; adds a date-matched EPSS baseline")
    backtest.add_argument("--epss-threshold", type=float, default=0.1)
    args = parser.parse_args(argv)
    if args.command == "collect":
        result = collect_public_snapshots(args.output_dir)
    elif args.command == "nvd-history":
        result = collect_nvd_history(args.start, args.end, args.output_dir,
                                     request_delay=args.request_delay)
    elif args.command == "import-kev-history":
        result = import_kev_git_history(args.repo, args.output_dir)
    elif args.command == "import-msf-history":
        result = import_metasploit_git_history(args.repo, args.output_dir, timeout=args.timeout)
    elif args.command == "import-nuclei-history":
        result = import_nuclei_git_history(args.repo, args.output_dir,
                                           pathspec=args.pathspec, timeout=args.timeout)
    elif args.command == "epss":
        result = collect_epss_snapshots(args.cves, args.output_dir)
    elif args.command == "epss-history":
        cves = args.cves_file.read_text(encoding="utf-8").splitlines()
        dates = args.dates_file.read_text(encoding="utf-8").splitlines() if args.dates_file else None
        result = collect_epss_history(cves, args.start, args.end, args.output_dir,
                                     requested_dates=dates)
    elif args.command == "ghsa":
        result = collect_ghsa_history(args.start, args.end, args.output_dir,
                                      max_pages=args.max_pages)
    elif args.command == "ghsa-cves":
        cve_list = list(args.cves)
        if args.cves_file:
            cve_list.extend(args.cves_file.read_text(encoding="utf-8").split())
        result = collect_ghsa_for_cves(cve_list, args.output_dir, request_delay=args.delay)
    elif args.command == "merge-observations":
        result = merge_observation_files(args.inputs, args.output)
    else:
        result = run_temporal_backtest(args.observations, args.kev, args.output,
                                       start=parse_time(args.start), end=parse_time(args.end),
                                       epss_history_path=args.epss_history,
                                       epss_threshold=args.epss_threshold)
    if args.command == "backtest":
        summary = {key: value for key, value in result.items() if key != "predictions"}
        summary["prediction_file"] = str(args.output)
        print(json.dumps(summary, indent=2))
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
