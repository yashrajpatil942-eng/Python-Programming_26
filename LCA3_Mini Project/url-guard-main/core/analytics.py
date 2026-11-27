"""
URL Guard — Analytics & Historical Aggregation Engine
Module: core/analytics.py

Pure computational and aggregation engine for URL Guard scan history.
Handles record normalization, CSV injection neutralization stripping,
time-window filtering (Today, Last 7 Days, All Time), KPI metrics calculation,
continuous zero-filled daily trends, 24-hour diurnal distributions,
and hostname risk rankings.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, date, timedelta, timezone
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import pandas as pd

from storage.history_manager import get_history

logger = logging.getLogger(__name__)

# Time window constants
FILTER_TODAY = "Today"
FILTER_LAST_7_DAYS = "Last 7 Days"
FILTER_ALL_TIME = "All Time"
TIME_FILTERS = [FILTER_TODAY, FILTER_LAST_7_DAYS, FILTER_ALL_TIME]

# Threat classification constants matching URL Guard design system
RISK_LOW = "LOW RISK"
RISK_MEDIUM = "MEDIUM RISK"
RISK_HIGH = "HIGH RISK"
VALID_RISK_LEVELS = {RISK_LOW, RISK_MEDIUM, RISK_HIGH}


@dataclass(frozen=True)
class AnalyticsMetrics:
    """Core aggregate metrics for a given scan history window."""

    total_scans: int
    low_risk_count: int
    medium_risk_count: int
    high_risk_count: int
    low_risk_pct: float
    medium_risk_pct: float
    high_risk_pct: float
    high_risk_rate: float
    avg_risk_score: float
    max_risk_score: int
    unique_domains_count: int = 0

    @property
    def unique_hostnames_count(self) -> int:
        """Alias for unique_domains_count for backward/forward compatibility."""
        return self.unique_domains_count


def _parse_iso_timestamp(raw_timestamp: Any) -> Optional[datetime]:
    """
    Defensively parses an ISO 8601 timestamp string into a UTC-aware datetime.
    Handles trailing 'Z', offsets, naive datetimes, and leading formula quotes.
    Returns None if parsing fails.
    """
    if not raw_timestamp:
        return None

    clean_ts = str(raw_timestamp).strip().lstrip("'")
    if not clean_ts:
        return None

    try:
        # Normalize trailing 'Z' to UTC offset for fromisoformat
        if clean_ts.endswith("Z") or clean_ts.endswith("z"):
            clean_ts = clean_ts[:-1] + "+00:00"

        dt = datetime.fromisoformat(clean_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception as exc:
        logger.warning(f"Failed to parse timestamp '{raw_timestamp}': {exc}")
        return None


def clean_history_records(records: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sanitizes, cleans, and standardizes raw history records from storage.

    - Strips CSV formula injection trigger characters (e.g. leading quotes `'`).
    - Defensively parses ISO 8601 timestamps into UTC-aware datetime objects.
    - Coerces risk scores to integers clamped to [0, 100].
    - Normalizes hostnames (lowercase, stripped).
    - Ensures risk_classification matches canonical values or infers from score.
    - Gracefully skips corrupted or unrecoverable rows.
    """
    if not records:
        return []

    cleaned: List[Dict[str, Any]] = []

    for item in records:
        if not isinstance(item, dict):
            continue

        raw_dt = item.get("scan_date_time")
        dt = _parse_iso_timestamp(raw_dt)
        if dt is None:
            # Corrupted timestamp row; skip
            continue

        # Hostname normalization
        raw_host = item.get("hostname", "")
        clean_host = str(raw_host).strip().lstrip("'").strip().lower()
        if not clean_host:
            clean_host = "unknown"

        # Risk score coercion
        raw_score = item.get("risk_score", 0)
        try:
            score_str = str(raw_score).strip().lstrip("'").strip()
            score_float = float(score_str)
            if math.isinf(score_float) or math.isnan(score_float):
                continue
            score_val = int(round(score_float))
            score_clamped = max(0, min(100, score_val))
        except (ValueError, TypeError, OverflowError):
            # Corrupted score row; skip
            continue

        # Risk classification normalization
        raw_class = item.get("risk_classification", "")
        clean_class = str(raw_class).strip().lstrip("'").strip().upper()
        if clean_class not in VALID_RISK_LEVELS:
            if score_clamped <= 20:
                clean_class = RISK_LOW
            elif score_clamped <= 50:
                clean_class = RISK_MEDIUM
            else:
                clean_class = RISK_HIGH

        cleaned.append({
            "scan_date_time": dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "datetime": dt,
            "hostname": clean_host,
            "risk_score": score_clamped,
            "risk_classification": clean_class,
        })

    return cleaned


def filter_history_by_window(
    records: Sequence[Dict[str, Any]],
    window: str,
    ref_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Filters history records according to the requested time window.

    Supported Windows:
      - "Today": Records matching the UTC calendar date of ref_time.
      - "Last 7 Days": Records within [ref_time - 7 days, ref_time + 1 day].
      - "All Time": All valid records without date restriction.

    Accepts both raw and pre-cleaned records.
    """
    if not records:
        return []

    # Ensure records are cleaned and possess 'datetime'
    if records and not (isinstance(records[0], dict) and "datetime" in records[0]):
        cleaned_records = clean_history_records(records)
    else:
        cleaned_records = list(records)

    if not cleaned_records:
        return []

    if ref_time is None:
        ref_time = datetime.now(timezone.utc)
    elif ref_time.tzinfo is None:
        ref_time = ref_time.replace(tzinfo=timezone.utc)
    else:
        ref_time = ref_time.astimezone(timezone.utc)

    normalized_window = str(window).strip().lower()

    if normalized_window in ("today", "filter_today"):
        target_date = ref_time.date()
        return [r for r in cleaned_records if r["datetime"].date() == target_date]

    if normalized_window in ("last 7 days", "week", "last_7_days", "filter_last_7_days"):
        ref_date = ref_time.date()
        start_date = ref_date - timedelta(days=6)
        start_cutoff = datetime.combine(start_date, datetime.min.time(), tzinfo=timezone.utc)
        end_cutoff = datetime.combine(ref_date, datetime.max.time(), tzinfo=timezone.utc)
        return [
            r for r in cleaned_records
            if start_cutoff <= r["datetime"] <= end_cutoff
        ]

    # Default / "All Time"
    return cleaned_records


def compute_metrics(records: Sequence[Dict[str, Any]]) -> AnalyticsMetrics:
    """
    Computes statistical KPI metrics across a list of scan records.

    Zero-division safe: returns zeroed metrics (all 0.0) if records is empty.
    Accepts both raw and pre-cleaned records.
    """
    if not records:
        return AnalyticsMetrics(
            total_scans=0,
            low_risk_count=0,
            medium_risk_count=0,
            high_risk_count=0,
            low_risk_pct=0.0,
            medium_risk_pct=0.0,
            high_risk_pct=0.0,
            high_risk_rate=0.0,
            avg_risk_score=0.0,
            max_risk_score=0,
            unique_domains_count=0,
        )

    # Ensure records are clean
    if not (isinstance(records[0], dict) and "datetime" in records[0]):
        clean_list = clean_history_records(records)
    else:
        clean_list = list(records)

    total = len(clean_list)
    if total == 0:
        return AnalyticsMetrics(
            total_scans=0,
            low_risk_count=0,
            medium_risk_count=0,
            high_risk_count=0,
            low_risk_pct=0.0,
            medium_risk_pct=0.0,
            high_risk_pct=0.0,
            high_risk_rate=0.0,
            avg_risk_score=0.0,
            max_risk_score=0,
            unique_domains_count=0,
        )

    low_count = sum(1 for r in clean_list if r["risk_classification"] == RISK_LOW)
    med_count = sum(1 for r in clean_list if r["risk_classification"] == RISK_MEDIUM)
    high_count = sum(1 for r in clean_list if r["risk_classification"] == RISK_HIGH)

    low_pct = round((low_count / total) * 100.0, 1)
    med_pct = round((med_count / total) * 100.0, 1)
    high_pct = round((high_count / total) * 100.0, 1)
    high_risk_rate = high_pct

    scores = [r["risk_score"] for r in clean_list]
    avg_score = round(sum(scores) / total, 1)
    max_score = max(scores)

    unique_domains = len(set(r["hostname"] for r in clean_list))

    return AnalyticsMetrics(
        total_scans=total,
        low_risk_count=low_count,
        medium_risk_count=med_count,
        high_risk_count=high_count,
        low_risk_pct=low_pct,
        medium_risk_pct=med_pct,
        high_risk_pct=high_pct,
        high_risk_rate=high_risk_rate,
        avg_risk_score=avg_score,
        max_risk_score=max_score,
        unique_domains_count=unique_domains,
    )


def get_daily_trend_data(
    records: Sequence[Dict[str, Any]],
    days: int = 7,
    ref_time: Optional[datetime] = None,
) -> pd.DataFrame:
    """
    Generates a continuous, zero-filled daily time series DataFrame covering
    the past `days` consecutive calendar dates ending on ref_time.

    Returns DataFrame with columns:
      ['date', 'LOW RISK', 'MEDIUM RISK', 'HIGH RISK', 'total', 'avg_score']
    """
    columns = ["date", RISK_LOW, RISK_MEDIUM, RISK_HIGH, "total", "avg_score"]
    if days <= 0:
        return pd.DataFrame(columns=columns)

    if ref_time is None:
        ref_time = datetime.now(timezone.utc)
    elif ref_time.tzinfo is None:
        ref_time = ref_time.replace(tzinfo=timezone.utc)
    else:
        ref_time = ref_time.astimezone(timezone.utc)

    # Ensure records are cleaned
    if records and not (isinstance(records[0], dict) and "datetime" in records[0]):
        clean_list = clean_history_records(records)
    else:
        clean_list = list(records) if records else []

    ref_date = ref_time.date()
    date_sequence: List[date] = [
        ref_date - timedelta(days=i) for i in range(days - 1, -1, -1)
    ]

    # Group records by date
    records_by_date: Dict[date, List[Dict[str, Any]]] = {d: [] for d in date_sequence}
    for r in clean_list:
        rec_date = r["datetime"].date()
        if rec_date in records_by_date:
            records_by_date[rec_date].append(r)

    rows: List[Dict[str, Any]] = []
    for d in date_sequence:
        day_recs = records_by_date[d]
        total = len(day_recs)
        low = sum(1 for r in day_recs if r["risk_classification"] == RISK_LOW)
        med = sum(1 for r in day_recs if r["risk_classification"] == RISK_MEDIUM)
        high = sum(1 for r in day_recs if r["risk_classification"] == RISK_HIGH)
        avg = round(sum(r["risk_score"] for r in day_recs) / total, 1) if total > 0 else 0.0

        rows.append({
            "date": d.strftime("%Y-%m-%d"),
            RISK_LOW: low,
            RISK_MEDIUM: med,
            RISK_HIGH: high,
            "total": total,
            "avg_score": avg,
        })

    return pd.DataFrame(rows)


def get_hourly_distribution_data(
    records: Sequence[Dict[str, Any]]
) -> pd.DataFrame:
    """
    Generates a full 24-hour distribution DataFrame (00:00 to 23:00 UTC).
    Guarantees all 24 hours are present even if counts are 0.

    Returns DataFrame with columns:
      ['hour', 'hour_label', 'count']
    """
    columns = ["hour", "hour_label", "count"]

    if records and not (isinstance(records[0], dict) and "datetime" in records[0]):
        clean_list = clean_history_records(records)
    else:
        clean_list = list(records) if records else []

    counts: Dict[int, int] = {h: 0 for h in range(24)}
    for r in clean_list:
        h = r["datetime"].hour
        counts[h] = counts.get(h, 0) + 1

    rows = [
        {"hour": h, "hour_label": f"{h:02d}:00", "count": counts[h]}
        for h in range(24)
    ]
    return pd.DataFrame(rows, columns=columns)


def get_top_hostnames_data(
    records: Sequence[Dict[str, Any]],
    top_n: int = 8,
) -> pd.DataFrame:
    """
    Aggregates hostname statistics: scan frequency, max risk score, average score,
    and highest risk classification.

    Returns DataFrame with columns:
      ['hostname', 'scans', 'avg_score', 'max_score', 'risk_classification']
    Sorted by scans DESC, then max_score DESC.
    """
    columns = ["hostname", "scans", "avg_score", "max_score", "risk_classification"]

    if not records:
        return pd.DataFrame(columns=columns)

    if not (isinstance(records[0], dict) and "datetime" in records[0]):
        clean_list = clean_history_records(records)
    else:
        clean_list = list(records)

    if not clean_list:
        return pd.DataFrame(columns=columns)

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for r in clean_list:
        host = r["hostname"]
        grouped.setdefault(host, []).append(r)

    rows: List[Dict[str, Any]] = []
    for host, host_recs in grouped.items():
        scans = len(host_recs)
        scores = [r["risk_score"] for r in host_recs]
        max_score = max(scores)
        avg_score = round(sum(scores) / scans, 1)

        # Determine highest severity observed
        has_high = any(r["risk_classification"] == RISK_HIGH for r in host_recs)
        has_med = any(r["risk_classification"] == RISK_MEDIUM for r in host_recs)
        if has_high:
            highest_class = RISK_HIGH
        elif has_med:
            highest_class = RISK_MEDIUM
        else:
            highest_class = RISK_LOW

        rows.append({
            "hostname": host,
            "scans": scans,
            "avg_score": avg_score,
            "max_score": max_score,
            "risk_classification": highest_class,
        })

    df = pd.DataFrame(rows)
    df = df.sort_values(by=["scans", "max_score"], ascending=[False, False]).reset_index(drop=True)
    return df.head(top_n)


def load_and_prepare_analytics(
    data_dir: Optional[Union[Path, str]] = None,
    window: str = FILTER_LAST_7_DAYS,
    ref_time: Optional[datetime] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], AnalyticsMetrics]:
    """
    Convenience loader coordinating disk I/O, record cleaning, window filtering,
    and KPI computation.

    Returns:
      (all_cleaned_records, window_records, metrics)
    """
    raw_records = get_history(data_dir=data_dir)
    all_cleaned = clean_history_records(raw_records)
    window_records = filter_history_by_window(all_cleaned, window=window, ref_time=ref_time)
    metrics = compute_metrics(window_records)
    return all_cleaned, window_records, metrics
