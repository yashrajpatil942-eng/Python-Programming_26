"""
Unit and Regression Test Suite for URL Guard Analytics Engine
Module: tests/test_analytics.py
"""

from datetime import datetime, timedelta, timezone
import pytest
import pandas as pd

from core.analytics import (
    FILTER_TODAY,
    FILTER_LAST_7_DAYS,
    FILTER_ALL_TIME,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    AnalyticsMetrics,
    clean_history_records,
    filter_history_by_window,
    compute_metrics,
    get_daily_trend_data,
    get_hourly_distribution_data,
    get_top_hostnames_data,
    load_and_prepare_analytics,
)


# ---------------------------------------------------------------------------
# Fixtures & Synthetic Records
# ---------------------------------------------------------------------------

@pytest.fixture
def fixed_ref_time():
    """Deterministic reference timestamp: 2026-11-23 12:00:00 UTC."""
    return datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_raw_records():
    """A realistic set of raw history records representing various timestamps and tiers."""
    return [
        # Today (2026-11-23)
        {
            "scan_date_time": "2026-11-23T08:30:00Z",
            "hostname": "safe-portal.example.com",
            "risk_score": "10",
            "risk_classification": "LOW RISK",
        },
        {
            "scan_date_time": "2026-11-23T11:15:00Z",
            "hostname": "phish-bank-login.xyz",
            "risk_score": "85",
            "risk_classification": "HIGH RISK",
        },
        # 3 days ago (2026-11-20)
        {
            "scan_date_time": "2026-11-20T14:00:00Z",
            "hostname": "suspicious-tracker.net",
            "risk_score": "45",
            "risk_classification": "MEDIUM RISK",
        },
        # 6 days ago (2026-11-17)
        {
            "scan_date_time": "2026-11-17T05:10:10Z",
            "hostname": "www.google.com",
            "risk_score": "0",
            "risk_classification": "LOW RISK",
        },
        # 14 days ago (2026-11-09) - Outside 7-day window
        {
            "scan_date_time": "2026-11-09T18:20:00Z",
            "hostname": "old-malware-domain.ru",
            "risk_score": "95",
            "risk_classification": "HIGH RISK",
        },
    ]


# ---------------------------------------------------------------------------
# Record Cleaning & Sanitization Tests
# ---------------------------------------------------------------------------

class TestRecordCleaning:
    """Tests for clean_history_records and timestamp parsing."""

    def test_clean_history_records_empty_input(self):
        assert clean_history_records([]) == []

    def test_clean_history_records_strips_formula_quotes(self):
        records = [
            {
                "scan_date_time": "'2026-11-23T10:00:00Z",
                "hostname": "'=cmd|' /C calc'!A0",
                "risk_score": "'75",
                "risk_classification": "'HIGH RISK",
            }
        ]
        cleaned = clean_history_records(records)
        assert len(cleaned) == 1
        rec = cleaned[0]
        assert rec["scan_date_time"] == "2026-11-23T10:00:00Z"
        assert rec["risk_score"] == 75
        assert rec["risk_classification"] == "HIGH RISK"
        assert not rec["hostname"].startswith("'")

    def test_clean_history_records_coerces_and_clamps_scores(self):
        records = [
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "site1.com", "risk_score": "-15", "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "site2.com", "risk_score": "150", "risk_classification": "HIGH RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "site3.com", "risk_score": 45.8, "risk_classification": "MEDIUM RISK"},
        ]
        cleaned = clean_history_records(records)
        assert len(cleaned) == 3
        assert cleaned[0]["risk_score"] == 0
        assert cleaned[1]["risk_score"] == 100
        assert cleaned[2]["risk_score"] == 46

    def test_clean_history_records_skips_corrupted_rows(self):
        records = [
            {"scan_date_time": "INVALID-TIMESTAMP", "hostname": "valid.com", "risk_score": "10", "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "valid.com", "risk_score": "NOT-A-NUMBER", "risk_classification": "LOW RISK"},
            "not a dictionary",
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "valid.com", "risk_score": "10", "risk_classification": "LOW RISK"},
        ]
        cleaned = clean_history_records(records)
        assert len(cleaned) == 1
        assert cleaned[0]["hostname"] == "valid.com"

    def test_clean_history_records_infers_missing_classification(self):
        records = [
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "a.com", "risk_score": "15", "risk_classification": ""},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "b.com", "risk_score": "35", "risk_classification": "UNKNOWN"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "c.com", "risk_score": "80", "risk_classification": "CORRUPT"},
        ]
        cleaned = clean_history_records(records)
        assert cleaned[0]["risk_classification"] == RISK_LOW
        assert cleaned[1]["risk_classification"] == RISK_MEDIUM
        assert cleaned[2]["risk_classification"] == RISK_HIGH

    def test_clean_history_records_empty_hostname_defaults_to_unknown(self):
        records = [
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "", "risk_score": "0", "risk_classification": "LOW RISK"}
        ]
        cleaned = clean_history_records(records)
        assert cleaned[0]["hostname"] == "unknown"


# ---------------------------------------------------------------------------
# Time Window Filtering Tests
# ---------------------------------------------------------------------------

class TestTimeWindowFiltering:
    """Tests for filter_history_by_window."""

    def test_filter_empty_records(self, fixed_ref_time):
        assert filter_history_by_window([], FILTER_TODAY, ref_time=fixed_ref_time) == []
        assert filter_history_by_window([], FILTER_LAST_7_DAYS, ref_time=fixed_ref_time) == []
        assert filter_history_by_window([], FILTER_ALL_TIME, ref_time=fixed_ref_time) == []

    def test_filter_today_includes_only_today(self, sample_raw_records, fixed_ref_time):
        filtered = filter_history_by_window(sample_raw_records, FILTER_TODAY, ref_time=fixed_ref_time)
        assert len(filtered) == 2
        for r in filtered:
            assert r["datetime"].date() == fixed_ref_time.date()

    def test_filter_last_7_days_includes_week_scans(self, sample_raw_records, fixed_ref_time):
        filtered = filter_history_by_window(sample_raw_records, FILTER_LAST_7_DAYS, ref_time=fixed_ref_time)
        # Should include: Today (2), 3 days ago (1), 6 days ago (1) = 4 records
        # 14 days ago should be excluded
        assert len(filtered) == 4
        hostnames = [r["hostname"] for r in filtered]
        assert "old-malware-domain.ru" not in hostnames
        assert "safe-portal.example.com" in hostnames
        assert "www.google.com" in hostnames

    def test_filter_all_time_includes_all(self, sample_raw_records, fixed_ref_time):
        filtered = filter_history_by_window(sample_raw_records, FILTER_ALL_TIME, ref_time=fixed_ref_time)
        assert len(filtered) == 5

    def test_filter_case_insensitive_window_names(self, sample_raw_records, fixed_ref_time):
        assert len(filter_history_by_window(sample_raw_records, "today", ref_time=fixed_ref_time)) == 2
        assert len(filter_history_by_window(sample_raw_records, "last 7 days", ref_time=fixed_ref_time)) == 4
        assert len(filter_history_by_window(sample_raw_records, "all time", ref_time=fixed_ref_time)) == 5

    def test_filter_accepts_naive_ref_time(self, sample_raw_records):
        naive_ref = datetime(2026, 11, 23, 12, 0, 0)
        filtered = filter_history_by_window(sample_raw_records, FILTER_TODAY, ref_time=naive_ref)
        assert len(filtered) == 2


# ---------------------------------------------------------------------------
# Metrics Computation Tests
# ---------------------------------------------------------------------------

class TestComputeMetrics:
    """Tests for compute_metrics including zero-division resilience."""

    def test_compute_metrics_empty_records_safe_defaults(self):
        metrics = compute_metrics([])
        assert isinstance(metrics, AnalyticsMetrics)
        assert metrics.total_scans == 0
        assert metrics.low_risk_count == 0
        assert metrics.medium_risk_count == 0
        assert metrics.high_risk_count == 0
        assert metrics.low_risk_pct == 0.0
        assert metrics.medium_risk_pct == 0.0
        assert metrics.high_risk_pct == 0.0
        assert metrics.high_risk_rate == 0.0
        assert metrics.avg_risk_score == 0.0
        assert metrics.max_risk_score == 0
        assert metrics.unique_domains_count == 0
        assert metrics.unique_hostnames_count == 0

    def test_compute_metrics_single_record(self):
        records = [
            {
                "scan_date_time": "2026-11-23T10:00:00Z",
                "hostname": "phish.example.com",
                "risk_score": 85,
                "risk_classification": RISK_HIGH,
            }
        ]
        metrics = compute_metrics(records)
        assert metrics.total_scans == 1
        assert metrics.high_risk_count == 1
        assert metrics.low_risk_count == 0
        assert metrics.medium_risk_count == 0
        assert metrics.high_risk_pct == 100.0
        assert metrics.low_risk_pct == 0.0
        assert metrics.medium_risk_pct == 0.0
        assert metrics.high_risk_rate == 100.0
        assert metrics.avg_risk_score == 85.0
        assert metrics.max_risk_score == 85
        assert metrics.unique_domains_count == 1

    def test_compute_metrics_multi_records_percentages(self):
        # 4 records: 2 Low, 1 Med, 1 High
        # Low: 50.0%, Med: 25.0%, High: 25.0%
        # Scores: 0, 20, 40, 80 -> Sum = 140 -> Avg = 35.0, Max = 80
        records = [
            {"scan_date_time": "2026-11-23T01:00:00Z", "hostname": "a.com", "risk_score": 0, "risk_classification": RISK_LOW},
            {"scan_date_time": "2026-11-23T02:00:00Z", "hostname": "b.com", "risk_score": 20, "risk_classification": RISK_LOW},
            {"scan_date_time": "2026-11-23T03:00:00Z", "hostname": "c.com", "risk_score": 40, "risk_classification": RISK_MEDIUM},
            {"scan_date_time": "2026-11-23T04:00:00Z", "hostname": "a.com", "risk_score": 80, "risk_classification": RISK_HIGH},
        ]
        metrics = compute_metrics(records)
        assert metrics.total_scans == 4
        assert metrics.low_risk_count == 2
        assert metrics.medium_risk_count == 1
        assert metrics.high_risk_count == 1
        assert metrics.low_risk_pct == 50.0
        assert metrics.medium_risk_pct == 25.0
        assert metrics.high_risk_pct == 25.0
        assert metrics.high_risk_rate == 25.0
        assert metrics.avg_risk_score == 35.0
        assert metrics.max_risk_score == 80
        # 3 unique hostnames: a.com, b.com, c.com
        assert metrics.unique_domains_count == 3


# ---------------------------------------------------------------------------
# Daily Trend Time Series Tests
# ---------------------------------------------------------------------------

class TestDailyTrendData:
    """Tests for continuous zero-filled get_daily_trend_data."""

    def test_get_daily_trend_zero_fills_all_days(self, fixed_ref_time):
        df = get_daily_trend_data([], days=7, ref_time=fixed_ref_time)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 7
        assert list(df.columns) == ["date", RISK_LOW, RISK_MEDIUM, RISK_HIGH, "total", "avg_score"]
        # All days must be zero-filled
        assert (df["total"] == 0).all()
        assert (df["avg_score"] == 0.0).all()
        # Verify continuous chronological sequence
        expected_dates = [
            (fixed_ref_time.date() - timedelta(days=i)).strftime("%Y-%m-%d")
            for i in range(6, -1, -1)
        ]
        assert list(df["date"]) == expected_dates

    def test_get_daily_trend_aggregates_matching_days(self, sample_raw_records, fixed_ref_time):
        df = get_daily_trend_data(sample_raw_records, days=7, ref_time=fixed_ref_time)
        assert len(df) == 7
        # Today row (2026-11-23): 2 scans (1 Low, 1 High)
        today_row = df[df["date"] == "2026-11-23"].iloc[0]
        assert today_row["total"] == 2
        assert today_row[RISK_LOW] == 1
        assert today_row[RISK_HIGH] == 1
        assert today_row[RISK_MEDIUM] == 0
        assert today_row["avg_score"] == 47.5  # (10 + 85) / 2

        # 2026-11-20 (3 days ago): 1 scan (1 Med, score 45)
        med_row = df[df["date"] == "2026-11-20"].iloc[0]
        assert med_row["total"] == 1
        assert med_row[RISK_MEDIUM] == 1
        assert med_row["avg_score"] == 45.0

        # Unscanned day (2026-11-22): 0 scans
        empty_row = df[df["date"] == "2026-11-22"].iloc[0]
        assert empty_row["total"] == 0
        assert empty_row["avg_score"] == 0.0

    def test_get_daily_trend_zero_or_negative_days(self):
        df = get_daily_trend_data([], days=0)
        assert len(df) == 0
        df_neg = get_daily_trend_data([], days=-5)
        assert len(df_neg) == 0


# ---------------------------------------------------------------------------
# Hourly Distribution Tests
# ---------------------------------------------------------------------------

class TestHourlyDistributionData:
    """Tests for get_hourly_distribution_data (24-hour diurnal cycle)."""

    def test_hourly_distribution_always_has_24_hours(self):
        df = get_hourly_distribution_data([])
        assert len(df) == 24
        assert list(df["hour"]) == list(range(24))
        assert (df["count"] == 0).all()
        assert df.iloc[0]["hour_label"] == "00:00"
        assert df.iloc[23]["hour_label"] == "23:00"

    def test_hourly_distribution_buckets_correctly(self):
        records = [
            {"scan_date_time": "2026-11-23T05:10:00Z", "hostname": "a.com", "risk_score": 10, "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T05:45:00Z", "hostname": "b.com", "risk_score": 20, "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T14:30:00Z", "hostname": "c.com", "risk_score": 50, "risk_classification": "MEDIUM RISK"},
        ]
        df = get_hourly_distribution_data(records)
        assert len(df) == 24
        assert df.loc[df["hour"] == 5, "count"].values[0] == 2
        assert df.loc[df["hour"] == 14, "count"].values[0] == 1
        assert df.loc[df["hour"] == 0, "count"].values[0] == 0


# ---------------------------------------------------------------------------
# Top Hostnames Aggregation Tests
# ---------------------------------------------------------------------------

class TestTopHostnamesData:
    """Tests for get_top_hostnames_data ranking and aggregation."""

    def test_top_hostnames_empty_records(self):
        df = get_top_hostnames_data([])
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0
        assert list(df.columns) == ["hostname", "scans", "avg_score", "max_score", "risk_classification"]

    def test_top_hostnames_aggregates_and_sorts(self):
        records = [
            {"scan_date_time": "2026-11-23T01:00:00Z", "hostname": "google.com", "risk_score": 0, "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T02:00:00Z", "hostname": "google.com", "risk_score": 10, "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T03:00:00Z", "hostname": "google.com", "risk_score": 5, "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T04:00:00Z", "hostname": "evil-phish.net", "risk_score": 90, "risk_classification": "HIGH RISK"},
            {"scan_date_time": "2026-11-23T05:00:00Z", "hostname": "evil-phish.net", "risk_score": 80, "risk_classification": "HIGH RISK"},
        ]
        df = get_top_hostnames_data(records, top_n=5)
        assert len(df) == 2
        # google.com has 3 scans -> first place
        assert df.iloc[0]["hostname"] == "google.com"
        assert df.iloc[0]["scans"] == 3
        assert df.iloc[0]["avg_score"] == 5.0
        assert df.iloc[0]["max_score"] == 10
        assert df.iloc[0]["risk_classification"] == "LOW RISK"

        # evil-phish.net has 2 scans -> second place
        assert df.iloc[1]["hostname"] == "evil-phish.net"
        assert df.iloc[1]["scans"] == 2
        assert df.iloc[1]["avg_score"] == 85.0
        assert df.iloc[1]["max_score"] == 90
        assert df.iloc[1]["risk_classification"] == "HIGH RISK"

    def test_top_hostnames_respects_top_n_limit(self):
        records = [
            {"scan_date_time": "2026-11-23T01:00:00Z", "hostname": f"host{i}.com", "risk_score": i * 10, "risk_classification": "LOW RISK"}
            for i in range(10)
        ]
        df = get_top_hostnames_data(records, top_n=3)
        assert len(df) == 3


# ---------------------------------------------------------------------------
# Integrated Loader Test
# ---------------------------------------------------------------------------

class TestLoadAndPrepareAnalytics:
    """Tests load_and_prepare_analytics with synthetic storage directory."""

    def test_load_and_prepare_analytics_flow(self, tmp_path):
        from storage.history_manager import save_scan

        # Save 2 scans to temporary directory using report dictionaries
        save_scan(
            report={
                "hostname": "test-safe.com",
                "risk_score": 5,
                "risk_classification": "LOW RISK",
            },
            data_dir=tmp_path,
        )
        save_scan(
            report={
                "hostname": "test-phish.com",
                "risk_score": 90,
                "risk_classification": "HIGH RISK",
            },
            data_dir=tmp_path,
        )

        all_clean, window_recs, metrics = load_and_prepare_analytics(
            data_dir=tmp_path,
            window=FILTER_TODAY,
        )
        assert len(all_clean) == 2
        assert len(window_recs) == 2
        assert metrics.total_scans == 2
        assert metrics.high_risk_count == 1
        assert metrics.low_risk_count == 1
        assert metrics.avg_risk_score == 47.5


# ---------------------------------------------------------------------------
# Bug Fix & Defensive Robustness Tests (Challenger 1 Probes)
# ---------------------------------------------------------------------------

class TestDefensiveBugFixes:
    """Verifies edge cases identified by adversarial audit Challenger 1."""

    def test_score_infinity_overflow_handling(self):
        """Verifies 'inf', '-inf', '1e1000', and float('inf') are safely skipped without OverflowError."""
        records = [
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "inf-pos.com", "risk_score": "inf", "risk_classification": "HIGH RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "inf-neg.com", "risk_score": "-inf", "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "inf-exp.com", "risk_score": "1e1000", "risk_classification": "HIGH RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "inf-float.com", "risk_score": float("inf"), "risk_classification": "HIGH RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "nan-str.com", "risk_score": "nan", "risk_classification": "LOW RISK"},
            {"scan_date_time": "2026-11-23T10:00:00Z", "hostname": "valid.com", "risk_score": 75, "risk_classification": "HIGH RISK"},
        ]
        cleaned = clean_history_records(records)
        assert len(cleaned) == 1
        assert cleaned[0]["hostname"] == "valid.com"
        assert cleaned[0]["risk_score"] == 75

    def test_non_dict_first_element_handling(self):
        """Verifies compute_metrics([None]), filter_history_by_window([123], 'Today'), etc., return safe defaults."""
        # compute_metrics([None]) returns zeroed metrics
        metrics = compute_metrics([None])
        assert isinstance(metrics, AnalyticsMetrics)
        assert metrics.total_scans == 0

        # filter_history_by_window([123], 'Today') returns empty list
        filtered = filter_history_by_window([123], "Today")
        assert filtered == []

        # get_daily_trend_data([None]) returns zero-filled 7 days
        df_trend = get_daily_trend_data([None], days=7)
        assert len(df_trend) == 7
        assert (df_trend["total"] == 0).all()

        # get_hourly_distribution_data([None]) returns 24 zero-filled hours
        df_hourly = get_hourly_distribution_data([None])
        assert len(df_hourly) == 24
        assert (df_hourly["count"] == 0).all()

        # get_top_hostnames_data([None]) returns empty DataFrame with expected columns
        df_top = get_top_hostnames_data([None])
        assert len(df_top) == 0
        assert list(df_top.columns) == ["hostname", "scans", "avg_score", "max_score", "risk_classification"]

    def test_last_7_days_does_not_include_tomorrow(self, fixed_ref_time):
        """Verifies scans timestamped tomorrow (ref_time + 1 day) are excluded from 'Last 7 Days'."""
        tomorrow_ts = (fixed_ref_time + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        today_ts = fixed_ref_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        eight_days_ago_ts = (fixed_ref_time - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")

        records = [
            {"scan_date_time": tomorrow_ts, "hostname": "tomorrow.com", "risk_score": 50, "risk_classification": "MEDIUM RISK"},
            {"scan_date_time": today_ts, "hostname": "today.com", "risk_score": 10, "risk_classification": "LOW RISK"},
            {"scan_date_time": eight_days_ago_ts, "hostname": "old.com", "risk_score": 80, "risk_classification": "HIGH RISK"},
        ]

        filtered = filter_history_by_window(records, FILTER_LAST_7_DAYS, ref_time=fixed_ref_time)
        assert len(filtered) == 1
        assert filtered[0]["hostname"] == "today.com"

        # Also verify alignment with get_daily_trend_data:
        df_trend = get_daily_trend_data(records, days=7, ref_time=fixed_ref_time)
        assert df_trend["total"].sum() == len(filtered) == 1

