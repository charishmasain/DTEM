"""
dtem.evaluation.backtester
~~~~~~~~~~~~~~~~~~~~~~~~~~

Implements time-clamped prototype timelines. Baseline values remain unavailable
until actual timestamped observations are integrated.

Supports two modes:
  1. Curated validation data (for offline research evaluation).
  2. Live database records (for dynamic web dashboard display).
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server use
import matplotlib.pyplot as plt

from dtem.extractor.features import ThreatInfoExtractor
from dtem.model.scoring import DTEMScoringEngine
from dtem.data.database import fetch_intel_for_keyword

logger = logging.getLogger(__name__)

# Output paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
EVAL_OUTPUT_DIR = PROJECT_ROOT / "output" / "evaluation"
PLOT_PATH = EVAL_OUTPUT_DIR / "baseline_timeline.png"


def _compute_timeline(records: list[dict[str, Any]], base_time: datetime,
                      require_availability: bool = False) -> list[dict[str, Any]]:
    """
    Core timeline computation shared by both the research backtest
    and the live dashboard API. Takes raw CTI records and a reference
    base_time, returns a list of score snapshots over a 30-day window.
    """
    extractor = ThreatInfoExtractor(recent_window_days=14)
    engine = DTEMScoringEngine()

    timeline_data = []

    for day_offset in range(-30, 1, 2):
        cutoff_time = base_time + timedelta(days=day_offset)

        # Filter records published on or before the cutoff time
        filtered_records = []
        for rec in records:
            pub_str = rec.get("published_at")
            available_str = rec.get("available_at") or rec.get("collected_at")
            if pub_str:
                try:
                    pub_dt = pd.to_datetime(pub_str, utc=True)
                    if require_availability and not available_str:
                        continue
                    if available_str:
                        available_dt = pd.to_datetime(available_str, utc=True)
                        if available_dt > cutoff_time:
                            continue
                    if pub_dt <= cutoff_time:
                        filtered_records.append(rec)
                except Exception:
                    continue

        # Extract features for the time-clamped subset
        if not filtered_records:
            dtem_score = None
        else:
            # Keep the timeline calculation on the same record identity and
            # exploit evidence hierarchy as the live scoring engine.
            filtered_records = extractor._deduplicate_records(filtered_records)
            freq = extractor.calculate_detection_frequency(filtered_records)
            growth_rate, _, recent_count, previous_count = extractor.calculate_growth_rate(filtered_records, as_of=cutoff_time)
            div, _ = extractor.calculate_source_diversity(filtered_records)
            _, exploit_evidence_score = extractor.classify_exploit_evidence(filtered_records)

            f_sub = engine._normalize_frequency(freq)
            g_sub = engine._normalize_growth_rate(growth_rate) if recent_count + previous_count else 0.0
            d_sub = engine._normalize_source_diversity(div)
            e_sub = float(exploit_evidence_score)

            w = engine.weights
            dtem_score = (w["detection_frequency"] * f_sub +
                          w["growth_rate"] * g_sub +
                          w["source_diversity"] * d_sub +
                          w["exploit_availability"] * e_sub)
            dtem_score = round(float(dtem_score), 2)

        timeline_data.append({
            "day": day_offset,
            "dtem": dtem_score,
            "cvss": None,
            "epss": None,
            "cisa_kev": None,
        })

    return timeline_data


def run_timeline_backtest_for_api(keyword: str) -> dict[str, Any]:
    """
    Lightweight backtest designed for the web dashboard API.
    Fetches records from the live database and returns timeline JSON
    without generating matplotlib plots.
    """
    records = fetch_intel_for_keyword(keyword.strip().lower())
    records = [record for record in records if not ThreatInfoExtractor._is_prototype_record(record)]
    # CVE timelines must use the same exact-identifier matching rule as the
    # main extractor, rather than any broader database query matches.
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", keyword.strip(), re.IGNORECASE):
        records = [record for record in records
                   if ThreatInfoExtractor._record_mentions_cve(record, keyword.strip())]

    if not records:
        return {"timeline": [], "early_warning_lead_days": None,
                "lead_time_status": "no_timestamped_outcome"}

    base_time = datetime.now(timezone.utc)
    timeline = _compute_timeline(records, base_time, require_availability=True)

    # Live prototype records do not include a timestamped outcome or a
    # date-matched baseline; therefore lead time is not estimable.
    lead_days = None

    # Current day-0 snapshot for the comparison table
    day_zero = timeline[-1] if timeline else {"dtem": 0, "cvss": 0, "epss": 0, "cisa_kev": 0}

    return {
        "timeline": timeline,
        "early_warning_lead_days": lead_days,
        "lead_time_status": "no_timestamped_outcome",
        "current_snapshot": day_zero,
    }


def run_timeline_backtest(keyword: str = "eval_lockbit") -> dict[str, Any]:
    """
    Full research backtest with matplotlib chart generation.
    Uses curated validation records for offline evaluation.
    """
    from dtem.evaluation.validation_data import get_curated_records

    base_time = datetime.now(timezone.utc)
    dataset = get_curated_records(base_time)
    records = dataset.get(keyword, [])

    if not records:
        raise ValueError(f"No curation records found for keyword '{keyword}'")

    timeline_data = _compute_timeline(records, base_time)

    # Create Matplotlib Plot
    df = pd.DataFrame(timeline_data)

    plt.figure(figsize=(10, 6))

    plt.plot(df["day"], df["dtem"], label="DTEM Emergence Score (Dynamic)", color="#00f2fe", linewidth=3, marker="o")

    plt.title(f"Curated Prototype Timeline: {keyword.replace('eval_', '').upper()}", fontsize=14, fontweight="bold", pad=15)
    plt.xlabel("Timeline (Days Relative to Reference Time)", fontsize=11, labelpad=10)
    plt.ylabel("Normalized Metric Value (0 - 100)", fontsize=11, labelpad=10)

    plt.xlim(-30, 0)
    plt.ylim(-5, 105)
    plt.grid(True, linestyle=":", alpha=0.3)
    plt.legend(loc="upper left", framealpha=0.9, fontsize=10)


    EVAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    plt.savefig(PLOT_PATH, dpi=300, bbox_inches="tight")
    plt.close()

    logger.info("Timeline backtest chart saved to %s", PLOT_PATH)

    return {
        "timeline": df.to_dict(orient="records"),
        "early_warning_lead_days": None,
        "evaluation_type": "curated_prototype_only",
        "lead_time_status": "not_estimable_without_timestamped_future_event",
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = run_timeline_backtest()
    print("Backtest Completed.")
    print("Timeline sample:")
    for row in res["timeline"][-6:]:
        print(f"Day {row['day']:>3d}: DTEM={row['dtem']:>5.1f} | CVSS={row['cvss'] if row['cvss'] is not None else 'N/A'} | EPSS={row['epss'] if row['epss'] is not None else 'N/A'} | KEV={row['cisa_kev'] if row['cisa_kev'] is not None else 'N/A'}")
