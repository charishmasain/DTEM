"""
dtem.collector.base
~~~~~~~~~~~~~~~~~~~

Abstract base class for all threat intelligence collectors.

Every collector must implement the ``collect`` method, which accepts
a search keyword and returns a list of normalised CTI records.
"""

from abc import ABC, abstractmethod
from typing import Any


class BaseCollector(ABC):
    """
    Interface that all CTI collectors must implement.

    Each collector is responsible for querying a single source
    (NVD, AlienVault OTX, a dark web forum, etc.) and returning
    a standardised list of dictionaries.
    """

    # Human‑readable name shown in logs and the dashboard
    source_name: str = "Unknown"

    # "public_api" | "dark_web" | "public_report"
    source_type: str = "public_api"

    @abstractmethod
    def collect(self, keyword: str) -> list[dict[str, Any]]:
        """
        Query the source for intelligence related to *keyword*.

        Returns a list of dicts, each containing at minimum:
            - source        (str)  — name of the source
            - source_type   (str)  — category
            - title         (str)  — headline / summary
            - content       (str)  — body text
            - url           (str)  — link to original (if available)
            - published_at  (str)  — ISO‑8601 timestamp
            - severity      (str)  — qualitative or CVSS severity
            - exploit_mentioned (int) — 1 if exploit / PoC is present
            - raw_data      (dict) — original unprocessed payload
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} source={self.source_name!r}>"
