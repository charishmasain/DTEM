"""
dtem.collector.nvd_collector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Collects vulnerability data from the NIST National Vulnerability
Database (NVD) public API v2.0.

API docs: https://nvd.nist.gov/developers/vulnerabilities

No API key is required, but requests are rate‑limited to ~5 per
30 seconds without a key.  The collector handles timeouts and
API errors gracefully by returning an empty list.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from dtem.collector.base import BaseCollector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

def _load_nvd_config() -> dict[str, Any]:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh).get("collectors", {}).get("nvd", {})


class NVDCollector(BaseCollector):
    """
    Queries the NVD CVE API for vulnerabilities matching a keyword.
    """

    source_name: str = "NVD"
    source_type: str = "public_api"

    def __init__(self) -> None:
        cfg = _load_nvd_config()
        self.enabled: bool = cfg.get("enabled", True)
        self.base_url: str = cfg.get(
            "base_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        )
        self.timeout: int = cfg.get("timeout_seconds", 15)
        self.max_results: int = cfg.get("max_results", 50)

    # ------------------------------------------------------------------ #
    # Core collection logic
    # ------------------------------------------------------------------ #

    def collect(self, keyword: str) -> list[dict[str, Any]]:
        """
        Search NVD for CVEs matching *keyword*.

        Returns normalised CTI records.  On network failure or if
        the collector is disabled, returns an empty list.
        """
        if not self.enabled:
            logger.info("NVD collector is disabled in config.")
            return []

        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": min(self.max_results, 100),
        }

        try:
            logger.info(
                "NVD API request: keyword=%s, url=%s",
                keyword,
                self.base_url,
            )
            response = requests.get(
                self.base_url,
                params=params,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            logger.warning("NVD API request failed: %s", exc)
            return []

        return self._parse_response(data)

    # ------------------------------------------------------------------ #
    # Response parsing
    # ------------------------------------------------------------------ #

    def _parse_response(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Transform the raw NVD JSON response into normalised CTI records.
        """
        records: list[dict[str, Any]] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # --- Extract description (English preferred) ---
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            # --- Extract CVSS severity ---
            severity = self._extract_severity(cve)

            # --- Extract published date ---
            published = cve.get("published", "")

            # --- Check for exploit references ---
            exploit_mentioned = self._check_exploit_refs(cve)

            # --- Build the URL ---
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            records.append(
                {
                    "source": self.source_name,
                    "source_type": self.source_type,
                    "title": f"{cve_id}: {description[:120]}",
                    "content": description,
                    "url": url,
                    "published_at": published,
                    "severity": severity,
                    "exploit_mentioned": exploit_mentioned,
                    "raw_data": item,
                }
            )

        logger.info("NVD returned %d records.", len(records))
        return records

    # ------------------------------------------------------------------ #
    # Helper: severity extraction
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_severity(cve: dict[str, Any]) -> str:
        """
        Try CVSS v3.1, then v3.0, then v2.0 to find a severity label.
        Falls back to the base score as a string.
        """
        metrics = cve.get("metrics", {})

        # CVSS v3.1
        for entry in metrics.get("cvssMetricV31", []):
            cvss = entry.get("cvssData", {})
            severity = cvss.get("baseSeverity", "")
            score = cvss.get("baseScore", "")
            if severity:
                return f"{severity} ({score})"

        # CVSS v3.0
        for entry in metrics.get("cvssMetricV30", []):
            cvss = entry.get("cvssData", {})
            severity = cvss.get("baseSeverity", "")
            score = cvss.get("baseScore", "")
            if severity:
                return f"{severity} ({score})"

        # CVSS v2.0
        for entry in metrics.get("cvssMetricV2", []):
            score = entry.get("cvssData", {}).get("baseScore", "")
            if score:
                return f"V2 ({score})"

        return "unknown"

    # ------------------------------------------------------------------ #
    # Helper: exploit reference detection
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_exploit_refs(cve: dict[str, Any]) -> int:
        """
        Return 1 if any reference tag contains 'Exploit' or if the
        description mentions exploit‑related keywords.
        """
        # Check reference tags
        for ref in cve.get("references", []):
            tags = ref.get("tags", [])
            if any("exploit" in t.lower() for t in tags):
                return 1

        # Check description keywords
        descriptions = cve.get("descriptions", [])
        exploit_keywords = [
            "exploit", "proof of concept", "poc", "payload",
            "remote code execution", "rce",
        ]
        for desc in descriptions:
            text = desc.get("value", "").lower()
            if any(kw in text for kw in exploit_keywords):
                return 1

        return 0
