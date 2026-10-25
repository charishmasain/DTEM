"""
dtem.extractor.features
~~~~~~~~~~~~~~~~~~~~~~~

Threat Information Extractor for DTEM.

Automatically extracts key emergence indicators from collected
Cyber Threat Intelligence (CTI) records:

  1. Detection Frequency  (Total CTI reports mentioning the threat)
  2. Growth Rate           (Temporal trajectory / percentage growth over time)
  3. Source Diversity     (Number of distinct independent CTI sources)
  4. Exploit Availability (Presence of public exploit code / PoC / trade)

The user NEVER enters these manually — all indicators are computed
directly from the underlying intelligence dataset.
"""

import logging
import json
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pandas as pd

from dtem.data.database import fetch_intel_for_keyword
from dtem.collector.manager import CollectorManager

logger = logging.getLogger(__name__)

# Keywords indicating exploit or proof-of-concept availability
EXPLOIT_KEYWORDS: list[str] = [
    "exploit",
    "poc",
    "proof of concept",
    "payload",
    "rce",
    "remote code execution",
    "0day",
    "zero-day",
    "builder",
    "weaponized",
    "shellcode",
    "exploit-db",
]

_GENERIC_EXPLOIT_TERMS = ("exploit", "payload", "weaponized", "shellcode", "0day", "zero-day")
_POC_TERMS = ("proof of concept", "poc", "reproducer", "reproducible exploit")
_VERIFIED_TERMS = ("working exploit", "exploit code", "exploit script", "functional exploit", "verified exploit")
_IN_WILD_TERMS = ("exploited in the wild", "actively exploited", "observed exploitation", "mass exploitation")


def _has_supported_phrase(text: str, phrase: str) -> bool:
    pattern = r"\b" + re.escape(phrase).replace(r"\ ", r"\s+") + r"\b"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        context = text[max(0, match.start() - 40):match.start()].lower()
        if not re.search(r"\b(no|not|never|without|unconfirmed|unverified|fake|claims?|alleged|pending)\b", context):
            return True
    return False


class ThreatInfoExtractor:
    """
    Extracts structured emergence indicators from raw CTI records.
    """

    def __init__(self, recent_window_days: int = 14) -> None:
        """
        Args:
            recent_window_days: Number of days to consider as the "recent"
                                period for growth rate calculation.
        """
        self.recent_window_days = recent_window_days

    def extract_features(self, keyword: str, auto_collect: bool = True,
                         include_prototype: bool = True) -> dict[str, Any]:
        """
        Extract all four emergence indicators for a given threat keyword.

        Args:
            keyword: Threat keyword (e.g., "LockBit", "CVE-2025-12345").
            auto_collect: If True and no DB records exist, triggers collector manager.

        Returns:
            Dictionary containing:
                - keyword (str)
                - detection_frequency (int)
                - growth_rate (float) — percentage increase (-100.0 to +infinity)
                - growth_trend (str) — "declining", "stable", "growing", "surging"
                - source_diversity (int) — unique source count
                - sources_list (list[str]) — names of unique sources
                - exploit_availability (bool) — True if exploit detected
                - exploit_count (int) — number of reports mentioning exploits
                - breakdown (dict) — detailed metrics for explainability
        """
        keyword_lower = keyword.strip().lower()
        is_cve_query = bool(re.fullmatch(r"cve-\d{4}-\d{4,}", keyword_lower, re.IGNORECASE))
        records = fetch_intel_for_keyword(keyword_lower)
        if not include_prototype:
            records = [record for record in records if not self._is_prototype_record(record)]
        if is_cve_query:
            # A CVE query counts only documents carrying that exact identifier.
            records = [record for record in records if self._record_mentions_cve(record, keyword_lower)]

        # Trigger collection if no data available
        if not records and auto_collect:
            logger.info("No DB records for '%s'. Triggering CollectorManager...", keyword_lower)
            collector_mgr = CollectorManager()
            collector_mgr.collect(keyword_lower, include_sources={"NVD", "AlienVault OTX"})
            records = fetch_intel_for_keyword(keyword_lower)
            if not include_prototype:
                records = [record for record in records if not self._is_prototype_record(record)]
            if is_cve_query:
                records = [record for record in records if self._record_mentions_cve(record, keyword_lower)]

        records = self._deduplicate_records(records)

        # Handle case where no records were found anywhere
        if not records:
            return self._empty_features(keyword_lower)

        # Compute individual indicators
        detection_freq = self.calculate_detection_frequency(records)
        # Live analyses use the actual analysis cutoff. Anchoring the window to
        # the newest record would make years-old reports look newly observed.
        analysis_time = datetime.now(timezone.utc)
        growth_rate, growth_trend, recent_cnt, prev_cnt = self.calculate_growth_rate(records, as_of=analysis_time)
        growth_observed = recent_cnt + prev_cnt > 0
        if not growth_observed:
            growth_rate = None
            growth_trend = "unavailable"
        # Candidate diagnostic only. It is not part of the production score
        # until its parameters are selected on development data.
        growth_log_rate = self.calculate_smoothed_log_growth(records, as_of=analysis_time)[0]
        if not growth_observed:
            growth_log_rate = None
        source_div, source_list = self.calculate_source_diversity(records)
        exploit_avail, exploit_cnt = self.calculate_exploit_availability(records)
        exploit_level, exploit_score = self.classify_exploit_evidence(records)
        exploit_evidence = []
        for record in records:
            level, score = self.classify_exploit_evidence([record])
            if score > 0:
                evidence_text = f"{record.get('title', '')} {record.get('content', '')}".strip()
                exploit_evidence.append({
                    "source": record.get("source", "Unknown"), "classification": level,
                    "heuristic_ordinal_score": score, "evidence_text": evidence_text[:500],
                    "url": record.get("url", ""), "published_at": record.get("published_at", ""),
                    "provenance": record.get("source_type", "unknown"),
                    "caveat": "Rule-based text classification; not independent verification.",
                })
        cvss_base_score = self._extract_cvss_base_score(records)

        return {
            "keyword": keyword,
            "detection_frequency": detection_freq,
            "growth_rate": round(growth_rate, 2) if growth_rate is not None else None,
            "growth_log_rate": round(growth_log_rate, 6) if growth_log_rate is not None else None,
            "growth_trend": growth_trend,
            "growth_data_available": growth_observed,
            "source_diversity": source_div,
            "sources_list": source_list,
            "exploit_availability": exploit_avail,
            "exploit_count": exploit_cnt,
            "exploit_evidence_level": exploit_level,
            "exploit_evidence_score": exploit_score,
            "cvss_base_score": cvss_base_score,
            "total_records": len(records),
            "data_status": "observed",
            "evidence_records": [
                {"source": r.get("source", "Unknown"), "title": r.get("title", ""),
                 "url": r.get("url", ""), "published_at": r.get("published_at", ""),
                 "collected_at": r.get("collected_at", ""), "source_type": r.get("source_type", "unknown")}
                for r in records
            ],
            "exploit_evidence": exploit_evidence,
            "evidence_quality_caveat": "Source labels do not establish independent corroboration; exploit labels are heuristic and copied reports may be duplicated.",
            "breakdown": {
                "recent_reports": recent_cnt,
                "previous_reports": prev_cnt,
                "recent_window_days": self.recent_window_days,
                "exploit_ratio": round(exploit_cnt / max(len(records), 1), 2),
            },
        }

    # ------------------------------------------------------------------ #
    # Indicator 1: Detection Frequency
    # ------------------------------------------------------------------ #

    @staticmethod
    def calculate_detection_frequency(records: list[dict[str, Any]]) -> int:
        """
        Counts distinct source/title/URL/publication-time records.
        """
        return len(ThreatInfoExtractor._deduplicate_records(records))

    @staticmethod
    def _deduplicate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        unique = []
        for record in records:
            identity = (record.get("source", ""), record.get("title", ""),
                        record.get("url", ""), record.get("published_at", ""))
            if identity not in seen:
                seen.add(identity)
                unique.append(record)
        return unique

    # ------------------------------------------------------------------ #
    # Indicator 2: Growth Rate
    # ------------------------------------------------------------------ #

    def calculate_growth_rate(
        self, records: list[dict[str, Any]], as_of: Optional[datetime] = None
    ) -> tuple[float, str, int, int]:
        """
        Calculates report growth rate by comparing recent report volume
        against the prior period.

        Returns:
            (growth_rate_percentage, growth_trend_label, recent_count, previous_count)
        """
        parsed_dates = [self._parse_timestamp(rec.get("published_at") or rec.get("collected_at")) for rec in records]
        dates = [dt for dt in parsed_dates if dt is not None]
        if not dates:
            return 0.0, "stable", 0, 0
        end_time = as_of or max(dates)
        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)
        cutoff_recent = end_time - timedelta(days=self.recent_window_days)
        cutoff_previous = cutoff_recent - timedelta(days=self.recent_window_days)
        recent_count = sum(cutoff_recent <= dt <= end_time for dt in dates)
        previous_count = sum(cutoff_previous <= dt < cutoff_recent for dt in dates)
        if previous_count == 0:
            growth_rate = 100.0 if recent_count else 0.0
        else:
            growth_rate = ((recent_count - previous_count) / previous_count) * 100.0
        # Classify trend label
        if growth_rate > 50.0:
            trend = "surging"
        elif growth_rate > 15.0:
            trend = "growing"
        elif growth_rate < -15.0:
            trend = "declining"
        else:
            trend = "stable"

        return float(growth_rate), trend, recent_count, previous_count

    def calculate_smoothed_log_growth(
        self, records: list[dict[str, Any]], as_of: Optional[datetime] = None, alpha: float = 0.5
    ) -> tuple[float, int, int]:
        """Return ln((recent+alpha)/(previous+alpha)) over adjacent equal windows.

        Windows are [as_of-W, as_of) and [as_of-2W, as_of-W). Missing or
        invalid publication timestamps are excluded; collection time is not a
        substitute for source publication time in historical measurements.
        """
        try:
            alpha = float(alpha)
        except (TypeError, ValueError):
            raise ValueError("alpha must be finite and positive") from None
        if not math.isfinite(alpha) or alpha <= 0:
            raise ValueError("alpha must be finite and positive")
        if as_of is None:
            dates = [self._parse_timestamp(r.get("published_at")) for r in records]
            valid = [d for d in dates if d is not None]
            if not valid:
                return 0.0, 0, 0
            as_of = max(valid) + timedelta(microseconds=1)
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=timezone.utc)
        recent_start = as_of - timedelta(days=self.recent_window_days)
        previous_start = as_of - timedelta(days=2 * self.recent_window_days)
        recent = previous = 0
        for rec in records:
            dt = self._parse_timestamp(rec.get("published_at"))
            if dt is None:
                continue
            if recent_start <= dt < as_of:
                recent += 1
            elif previous_start <= dt < recent_start:
                previous += 1
        return float(math.log((recent + alpha) / (previous + alpha))), recent, previous

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        if not value:
            return None
        try:
            ts = pd.to_datetime(value, utc=True).to_pydatetime()
            return ts
        except (TypeError, ValueError, OverflowError):
            return None

    # ------------------------------------------------------------------ #
    # Indicator 3: Source Diversity
    # ------------------------------------------------------------------ #

    @staticmethod
    def calculate_source_diversity(
        records: list[dict[str, Any]]
    ) -> tuple[int, list[str]]:
        """
        Counts distinct non-empty source labels. Different labels do not establish
        that the underlying reports are independent or independently corroborated.

        Returns:
            (unique_source_count, list_of_sources)
        """
        sources = {}
        for rec in records:
            src = str(rec.get("source") or "").strip()
            if src:
                sources.setdefault(src.casefold(), src)

        sources_list = sorted(sources.values(), key=str.casefold)
        return len(sources_list), sources_list

    # ------------------------------------------------------------------ #
    # Indicator 4: Exploit Availability
    # ------------------------------------------------------------------ #

    @staticmethod
    def calculate_exploit_availability(
        records: list[dict[str, Any]]
    ) -> tuple[bool, int]:
        """
        Determines whether public exploit code or exploit discussions exist.

        Checks:
          - Flag `exploit_mentioned == 1` in records
          - Keyword matching in title and content

        Returns:
            (has_exploit_bool, count_of_exploit_reports)
        """
        exploit_count = 0

        for rec in records:
            if rec.get("exploit_mentioned") == 1:
                exploit_count += 1
                continue

            # Fallback search in title and content
            text = f"{rec.get('title', '')} {rec.get('content', '')}".lower()
            if any(kw in text for kw in EXPLOIT_KEYWORDS):
                exploit_count += 1

        has_exploit = exploit_count > 0
        return has_exploit, exploit_count

    @staticmethod
    def classify_exploit_evidence(records: list[dict[str, Any]]) -> tuple[str, float]:
        """Conservative evidence hierarchy; text flags alone never imply in-wild use.

        Scores: none=0, generic mention=25, PoC reference=50, verified
        exploit code/report=75, in-wild evidence=100. These are ordinal
        prototype scores, not calibrated probabilities.
        """
        level = 0
        for rec in records:
            text = f"{rec.get('title', '')} {rec.get('content', '')}".lower()
            structured = str(rec.get("exploit_evidence", "")).lower()
            raw = rec.get("raw_data", {})
            raw_text = str(raw).lower()
            evidence = f"{text} {structured} {raw_text}"
            if any(_has_supported_phrase(evidence, term) for term in _IN_WILD_TERMS):
                level = max(level, 4)
            elif any(_has_supported_phrase(evidence, term) for term in _VERIFIED_TERMS):
                level = max(level, 3)
            elif any(_has_supported_phrase(evidence, term) for term in _POC_TERMS):
                level = max(level, 2)
            elif rec.get("exploit_mentioned") == 1 or any(_has_supported_phrase(text, term) for term in _GENERIC_EXPLOIT_TERMS):
                level = max(level, 1)
        labels = ("none", "generic_mention", "poc_reference", "verified_exploit", "in_wild")
        scores = (0.0, 25.0, 50.0, 75.0, 100.0)
        return labels[level], scores[level]

    @staticmethod
    def _extract_cvss_base_score(records: list[dict[str, Any]]) -> Optional[float]:
        """Read explicit numeric CVSS values from normalized severity fields only."""
        for rec in records:
            severity = str(rec.get("severity", ""))
            if str(rec.get("source", "")).strip().lower() != "nvd" and "cvss" not in severity.lower():
                continue
            match = re.search(r"\((10(?:\.0)?|[0-9](?:\.\d)?)\)", severity)
            if not match:
                match = re.search(r"\bCVSS\s+(10(?:\.0)?|[0-9](?:\.\d)?)\b", severity, re.IGNORECASE)
            if match:
                value = float(match.group(1))
                if 0.0 <= value <= 10.0:
                    return value
        return None

    @staticmethod
    def _record_mentions_cve(record: dict[str, Any], cve_id: str) -> bool:
        wanted = cve_id.upper()
        source = str(record.get("source", "")).strip().casefold()
        if source == "nvd":
            raw_data = record.get("raw_data", {})
            if isinstance(raw_data, str):
                try:
                    raw_data = json.loads(raw_data)
                except (TypeError, ValueError):
                    raw_data = {}
            raw_cve = raw_data.get("cve", {}) if isinstance(raw_data, dict) else {}
            explicit = str(record.get("cve_id") or raw_cve.get("id") or "").upper()
            if not explicit:
                title_match = re.match(r"\s*(CVE-\d{4}-\d{4,})\b", str(record.get("title", "")), re.IGNORECASE)
                url_match = re.search(r"/detail/(CVE-\d{4}-\d{4,})\b", str(record.get("url", "")), re.IGNORECASE)
                explicit = (title_match or url_match).group(1).upper() if title_match or url_match else ""
            # NVD keyword results may mention another CVE in the description.
            # Only the record's own identifier establishes NVD CVE membership.
            return explicit == wanted
        values = (record.get("cve_id", ""), record.get("title", ""),
                  record.get("content", ""), record.get("url", ""),
                  record.get("raw_data", ""))
        return any(wanted in {token.upper() for token in re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(value), re.IGNORECASE)}
                   for value in values)

    @staticmethod
    def _is_prototype_record(record: dict[str, Any]) -> bool:
        raw = record.get("raw_data", {})
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (TypeError, ValueError):
                raw = {}
        return bool(record.get("prototype_data") or record.get("demonstration_data")
                    or record.get("source") == "DarkWeb-Simulator"
                    or record.get("source_type") == "dark_web" and record.get("historical_capture") is not True
                    or isinstance(raw, dict) and (raw.get("seeded") is True or raw.get("generated") is True))

    # ------------------------------------------------------------------ #
    # Helper: Empty features fallback
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_features(keyword: str) -> dict[str, Any]:
        return {
            "keyword": keyword,
            "detection_frequency": 0,
            "growth_rate": 0.0,
            "growth_log_rate": None,
            "growth_trend": "unavailable",
            "growth_data_available": False,
            "source_diversity": 0,
            "sources_list": [],
            "exploit_availability": False,
            "exploit_count": 0,
            "exploit_evidence_level": "none",
            "exploit_evidence_score": 0.0,
            "cvss_base_score": None,
            "total_records": 0,
            "data_status": "insufficient_data",
            "evidence_quality_caveat": "No eligible records were available. Zero counts are not evidence that the threat is absent.",
            "breakdown": {
                "recent_reports": 0,
                "previous_reports": 0,
                "recent_window_days": 14,
                "exploit_ratio": 0.0,
            },
        }
