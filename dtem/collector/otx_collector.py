"""
dtem.collector.otx_collector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Collects threat intelligence from the AlienVault Open Threat
Exchange (OTX) public Pulse search API.

API docs: https://otx.alienvault.com/api

The API can be used without an API key for basic searches,
but may be rate‑limited.  If a key is set in config.json it
will be sent as the ``X-OTX-API-KEY`` header.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from dtem.collector.base import BaseCollector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"


def _load_otx_config() -> dict[str, Any]:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh).get("collectors", {}).get("otx", {})


class OTXCollector(BaseCollector):
    """
    Searches AlienVault OTX Pulses for threat intelligence
    matching a keyword.
    """

    source_name: str = "AlienVault OTX"
    source_type: str = "public_api"

    def __init__(self) -> None:
        cfg = _load_otx_config()
        self.enabled: bool = cfg.get("enabled", True)
        self.base_url: str = cfg.get(
            "base_url",
            "https://otx.alienvault.com/api/v1/search/pulses",
        )
        self.timeout: int = cfg.get("timeout_seconds", 15)
        self.max_results: int = cfg.get("max_results", 50)
        self.api_key: str = os.environ.get("OTX_API_KEY", "")
        self.last_error: str | None = None

    # ------------------------------------------------------------------ #
    # Core collection logic
    # ------------------------------------------------------------------ #

    def collect(self, keyword: str) -> list[dict[str, Any]]:
        """
        Query OTX for Pulses matching *keyword*.

        Returns normalised CTI records.  On failure returns an empty list.
        """
        if not self.enabled:
            logger.info("OTX collector is disabled in config.")
            return []
        self.last_error = None

        params: dict[str, Any] = {
            "q": keyword,
            "limit": min(self.max_results, 50),
            "sort": "modified",
        }

        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            logger.info(
                "OTX API request: keyword=%s, url=%s",
                keyword,
                self.base_url,
            )
            session = requests.Session()
            retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5,
                          status_forcelist=(429, 500, 502, 503, 504),
                          allowed_methods=frozenset(["GET"]), respect_retry_after_header=True)
            session.mount("https://", HTTPAdapter(max_retries=retry))
            response = session.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("OTX API request failed: %s", exc)
            return []

        return self._parse_response(data)

    # ------------------------------------------------------------------ #
    # Response parsing
    # ------------------------------------------------------------------ #

    def _parse_response(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Transform raw OTX JSON into normalised CTI records.
        """
        records: list[dict[str, Any]] = []
        results = data.get("results", [])

        for pulse in results:
            pulse_id = pulse.get("id", "")
            name = pulse.get("name", "Untitled Pulse")
            description = pulse.get("description", "")
            created = pulse.get("created", "")
            modified = pulse.get("modified", "")
            tags = pulse.get("tags", [])
            adversary = pulse.get("adversary", "")

            # Use the modified date as the most recent activity marker
            published_at = modified or created

            # Determine severity from TLP or adversary presence
            tlp = pulse.get("TLP", "white")
            severity = self._map_severity(tlp, adversary)

            # Check for exploit mentions in tags and description
            exploit_mentioned = self._check_exploit(tags, description)

            # Build a public URL for the pulse
            url = f"https://otx.alienvault.com/pulse/{pulse_id}"

            records.append(
                {
                    "source": self.source_name,
                    "source_type": self.source_type,
                    "title": name,
                    "content": description[:2000],  # cap at 2 KB
                    "url": url,
                    "published_at": published_at,
                    "severity": severity,
                    "exploit_mentioned": exploit_mentioned,
                    "raw_data": {
                        "pulse_id": pulse_id,
                        "tags": tags,
                        "adversary": adversary,
                        "tlp": tlp,
                        "indicator_count": len(pulse.get("indicators", [])),
                    },
                }
            )

        logger.info("OTX returned %d records.", len(records))
        return records

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _map_severity(tlp: str, adversary: str) -> str:
        """
        Heuristic severity mapping based on TLP colour and whether
        a named adversary is associated with the pulse.
        """
        tlp_lower = tlp.lower() if tlp else "white"
        if tlp_lower == "red":
            return "critical"
        if tlp_lower == "amber":
            return "high"
        if adversary:
            return "high"
        if tlp_lower == "green":
            return "medium"
        return "low"

    @staticmethod
    def _check_exploit(tags: list[str], description: str) -> int:
        """
        Return 1 if exploit‑related keywords appear in tags or
        description.
        """
        exploit_keywords = [
            "exploit", "poc", "proof of concept", "payload",
            "rce", "remote code execution", "0day", "zero-day",
        ]
        # Check tags
        for tag in tags:
            if any(kw in tag.lower() for kw in exploit_keywords):
                return 1
        # Check description
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in exploit_keywords):
            return 1
        return 0
