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
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pandas as pd
import numpy as np

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

    def extract_features(self, keyword: str, auto_collect: bool = True) -> dict[str, Any]:
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
        records = fetch_intel_for_keyword(keyword_lower)

        # Trigger collection if no data available
        if not records and auto_collect:
            logger.info("No DB records for '%s'. Triggering CollectorManager...", keyword_lower)
            collector_mgr = CollectorManager()
            collector_mgr.collect(keyword_lower)
            records = fetch_intel_for_keyword(keyword_lower)

        # Handle case where no records were found anywhere
        if not records:
            return self._empty_features(keyword_lower)

        # Compute individual indicators
        detection_freq = self.calculate_detection_frequency(records)
        growth_rate, growth_trend, recent_cnt, prev_cnt = self.calculate_growth_rate(records)
        source_div, source_list = self.calculate_source_diversity(records)
        exploit_avail, exploit_cnt = self.calculate_exploit_availability(records)

        return {
            "keyword": keyword,
            "detection_frequency": detection_freq,
            "growth_rate": round(growth_rate, 2),
            "growth_trend": growth_trend,
            "source_diversity": source_div,
            "sources_list": source_list,
            "exploit_availability": exploit_avail,
            "exploit_count": exploit_cnt,
            "total_records": len(records),
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
        Calculates total number of CTI reports mentioning the threat.
        """
        return len(records)

    # ------------------------------------------------------------------ #
    # Indicator 2: Growth Rate
    # ------------------------------------------------------------------ #

    def calculate_growth_rate(
        self, records: list[dict[str, Any]]
    ) -> tuple[float, str, int, int]:
        """
        Calculates report growth rate by comparing recent report volume
        against the prior period.

        Returns:
            (growth_rate_percentage, growth_trend_label, recent_count, previous_count)
        """
        parsed_dates = []
        now = datetime.now(timezone.utc)

        for rec in records:
            dt_str = rec.get("published_at") or rec.get("collected_at")
            if dt_str:
                try:
                    # Clean ISO format string
                    dt = pd.to_datetime(dt_str, utc=True)
                    parsed_dates.append(dt)
                except Exception:
                    continue

        if not parsed_dates:
            return 0.0, "stable", 0, 0

        # Create pandas Series of timestamps
        df = pd.DataFrame({"timestamp": parsed_dates})
        max_date = df["timestamp"].max()

        # Define time boundaries relative to newest report or current time
        cutoff_recent = max_date - pd.Timedelta(days=self.recent_window_days)
        cutoff_previous = cutoff_recent - pd.Timedelta(days=self.recent_window_days)

        recent_count = int((df["timestamp"] >= cutoff_recent).sum())
        previous_count = int(
            ((df["timestamp"] < cutoff_recent) & (df["timestamp"] >= cutoff_previous)).sum()
        )

        # Calculate percentage growth rate
        if previous_count == 0:
            if recent_count > 0:
                growth_rate = 100.0  # New emergence surge
            else:
                growth_rate = 0.0
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

    # ------------------------------------------------------------------ #
    # Indicator 3: Source Diversity
    # ------------------------------------------------------------------ #

    @staticmethod
    def calculate_source_diversity(
        records: list[dict[str, Any]]
    ) -> tuple[int, list[str]]:
        """
        Calculates the number of distinct independent CTI sources reporting the threat.

        Returns:
            (unique_source_count, list_of_sources)
        """
        sources = set()
        for rec in records:
            src = rec.get("source")
            if src:
                sources.add(src)

        sources_list = sorted(list(sources))
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

    # ------------------------------------------------------------------ #
    # Helper: Empty features fallback
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_features(keyword: str) -> dict[str, Any]:
        return {
            "keyword": keyword,
            "detection_frequency": 0,
            "growth_rate": 0.0,
            "growth_trend": "dormant",
            "source_diversity": 0,
            "sources_list": [],
            "exploit_availability": False,
            "exploit_count": 0,
            "total_records": 0,
            "breakdown": {
                "recent_reports": 0,
                "previous_reports": 0,
                "recent_window_days": 14,
                "exploit_ratio": 0.0,
            },
        }
