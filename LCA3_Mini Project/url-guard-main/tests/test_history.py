"""
Unit and integration test suite for storage/history_manager.py.
Validates CSV persistence, privacy redaction, formula injection protection,
corruption resilience, edge cases, concurrency, and RFC 4180 export compliance.
"""

from concurrent.futures import ThreadPoolExecutor
import csv
import io
from pathlib import Path
from unittest.mock import patch
import pytest

from core.detector import CheckResult
from core.report_generator import AnalysisReport
from storage.history_manager import (
    save_scan,
    get_history,
    clear_history,
    export_history_csv,
    neutralize_csv_injection,
    sanitize_hostname_for_storage,
    get_history_file_path,
    DEFAULT_DATA_DIR,
    DEFAULT_CSV_PATH,
    HISTORY_FILE_NAME,
    CSV_HEADER,
    CSV_FIELDNAMES,
)


def _make_report(
    hostname: str = "example.com",
    score: int = 10,
    classification: str = "LOW RISK",
    timestamp: str = "2026-11-15T09:00:00Z",
    original_url: str = "http://example.com",
    sanitized_url: str = "http://example.com",
) -> AnalysisReport:
    """Helper factory generating valid AnalysisReport instances for storage tests."""
    dummy_check = CheckResult(
        check_id="check_https",
        check_name="HTTPS Detection",
        detected=True,
        points=score,
        explanation="HTTP scheme detected",
        evidence="http://",
    )
    return AnalysisReport(
        original_url=original_url,
        normalized_hostname=hostname,
        validation_status="Valid (Formatting and structure verified)",
        protocol_info="HTTP (Unencrypted)",
        url_length=len(original_url),
        ip_detection=dummy_check,
        keyword_detection=dummy_check,
        special_char_detection=dummy_check,
        hyphen_analysis=dummy_check,
        subdomain_analysis=dummy_check,
        individual_points={"check_https": score},
        total_risk_score=score,
        risk_classification=classification,
        detected_explanations=["HTTP scheme detected"],
        recommendation="Verify website identity",
        timestamp=timestamp,
        sanitized_url=sanitized_url,
        badge_color="#10B981" if score <= 20 else "#F59E0B" if score <= 50 else "#EF4444",
    )


# ============================================================================
# 1. TestSaveScan
# ============================================================================

class TestHistorySaveScan:
    """Tests for save_scan() persistence logic."""

    def test_save_scan_creates_dir_and_file_if_not_exist(self, tmp_path):
        target_dir = tmp_path / "new_storage_dir"
        assert not target_dir.exists()

        report = _make_report(hostname="example.com")
        success = save_scan(report, data_dir=target_dir)

        assert success is True
        assert target_dir.exists()
        csv_file = target_dir / HISTORY_FILE_NAME
        assert csv_file.exists()

    def test_save_scan_writes_header_on_initial_save(self, tmp_path):
        report = _make_report(hostname="alpha.com", score=10)
        save_scan(report, data_dir=tmp_path)

        csv_file = tmp_path / HISTORY_FILE_NAME
        lines = csv_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert lines[0] == "scan_date_time,hostname,risk_score,risk_classification"
        assert "alpha.com" in lines[1]

    def test_save_scan_appends_records_without_repeating_header(self, tmp_path):
        rep1 = _make_report(hostname="site1.com", score=0, timestamp="2026-11-15T09:00:00Z")
        rep2 = _make_report(hostname="site2.com", score=25, timestamp="2026-11-15T09:01:00Z")
        rep3 = _make_report(hostname="site3.com", score=60, timestamp="2026-11-15T09:02:00Z")

        save_scan(rep1, data_dir=tmp_path)
        save_scan(rep2, data_dir=tmp_path)
        save_scan(rep3, data_dir=tmp_path)

        csv_file = tmp_path / HISTORY_FILE_NAME
        lines = csv_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 4  # 1 header + 3 data lines
        header_occurrences = [line for line in lines if "scan_date_time" in line]
        assert len(header_occurrences) == 1

    def test_save_scan_to_existing_zero_byte_file_writes_header_first(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text("", encoding="utf-8")
        assert csv_file.stat().st_size == 0

        report = _make_report(hostname="recovered.com", score=15)
        success = save_scan(report, data_dir=tmp_path)
        assert success is True

        lines = csv_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert lines[0] == "scan_date_time,hostname,risk_score,risk_classification"
        assert "recovered.com" in lines[1]

    def test_save_scan_invalid_input_returns_false(self, tmp_path):
        assert save_scan(None, data_dir=tmp_path) is False  # type: ignore
        assert save_scan("not_a_report", data_dir=tmp_path) is False  # type: ignore
        assert save_scan({}, data_dir=tmp_path) is False  # type: ignore
        assert save_scan(12345, data_dir=tmp_path) is False  # type: ignore

    def test_save_scan_accepts_string_path_for_data_dir(self, tmp_path):
        report = _make_report(hostname="strpath.com")
        success = save_scan(report, data_dir=str(tmp_path))
        assert success is True
        assert (tmp_path / HISTORY_FILE_NAME).exists()

    def test_save_scan_accepts_exact_csv_file_path(self, tmp_path):
        custom_csv = tmp_path / "custom_history.csv"
        report = _make_report(hostname="exactfile.com")
        success = save_scan(report, data_dir=custom_csv)
        assert success is True
        assert custom_csv.exists()

    def test_save_scan_from_dict_input(self, tmp_path):
        scan_dict = {
            "normalized_hostname": "dict-site.com",
            "total_risk_score": 15,
            "risk_classification": "LOW RISK",
            "timestamp": "2026-11-15T12:00:00Z",
        }
        success = save_scan(scan_dict, data_dir=tmp_path)
        assert success is True
        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == "dict-site.com"
        assert int(history[0]["risk_score"]) == 15


# ============================================================================
# 2. TestGetHistory
# ============================================================================

class TestHistoryGetHistory:
    """Tests for get_history() retrieval logic."""

    def test_get_history_returns_all_records_in_order(self, tmp_path):
        rep1 = _make_report(hostname="first.org", score=10, classification="LOW RISK", timestamp="2026-11-15T09:00:00Z")
        rep2 = _make_report(hostname="second.org", score=55, classification="HIGH RISK", timestamp="2026-11-15T09:05:00Z")
        save_scan(rep1, data_dir=tmp_path)
        save_scan(rep2, data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        assert len(history) == 2
        assert history[0]["hostname"] == "first.org"
        assert int(history[0]["risk_score"]) == 10
        assert history[0]["risk_classification"] == "LOW RISK"
        assert history[0]["scan_date_time"] == "2026-11-15T09:00:00Z"

        assert history[1]["hostname"] == "second.org"
        assert int(history[1]["risk_score"]) == 55
        assert history[1]["risk_classification"] == "HIGH RISK"
        assert history[1]["scan_date_time"] == "2026-11-15T09:05:00Z"

    def test_get_history_missing_file_returns_empty_list(self, tmp_path):
        assert get_history(data_dir=tmp_path) == []

    def test_get_history_missing_dir_returns_empty_list(self, tmp_path):
        non_existent = tmp_path / "does_not_exist_at_all"
        assert get_history(data_dir=non_existent) == []

    def test_get_history_empty_file_returns_empty_list(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text("", encoding="utf-8")
        assert get_history(data_dir=tmp_path) == []

    def test_get_history_header_only_file_returns_empty_list(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text("scan_date_time,hostname,risk_score,risk_classification\n", encoding="utf-8")
        assert get_history(data_dir=tmp_path) == []

    def test_get_history_whitespace_only_file_returns_empty_list(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text("   \n\t\n   \r\n", encoding="utf-8")
        assert get_history(data_dir=tmp_path) == []


# ============================================================================
# 3. TestClearHistory
# ============================================================================

class TestHistoryClearHistory:
    """Tests for clear_history() cleanup logic."""

    def test_clear_history_clears_all_records(self, tmp_path):
        save_scan(_make_report(hostname="site-a.com"), data_dir=tmp_path)
        save_scan(_make_report(hostname="site-b.com"), data_dir=tmp_path)
        assert len(get_history(data_dir=tmp_path)) == 2

        success = clear_history(data_dir=tmp_path)
        assert success is True
        assert get_history(data_dir=tmp_path) == []

    def test_clear_history_on_nonexistent_file_returns_true(self, tmp_path):
        assert clear_history(data_dir=tmp_path) is True

    def test_clear_history_on_nonexistent_directory_returns_true(self, tmp_path):
        non_existent = tmp_path / "no_such_directory"
        assert clear_history(data_dir=non_existent) is True

    def test_save_scan_works_normally_after_clear_history(self, tmp_path):
        save_scan(_make_report(hostname="before.com"), data_dir=tmp_path)
        clear_history(data_dir=tmp_path)

        save_scan(_make_report(hostname="after.com", score=20), data_dir=tmp_path)
        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == "after.com"


# ============================================================================
# 4. TestExportHistoryCsv
# ============================================================================

class TestHistoryExportCsv:
    """Tests for export_history_csv() RFC 4180 export."""

    def test_export_history_csv_formatting_and_contents(self, tmp_path):
        save_scan(_make_report(hostname="export1.com", score=10), data_dir=tmp_path)
        save_scan(_make_report(hostname="export2.com", score=30), data_dir=tmp_path)

        csv_text = export_history_csv(data_dir=tmp_path)
        assert "scan_date_time,hostname,risk_score,risk_classification" in csv_text
        assert "export1.com" in csv_text
        assert "export2.com" in csv_text

    def test_export_history_csv_parses_back_via_csv_dictreader(self, tmp_path):
        save_scan(_make_report(hostname="alpha.io", score=0), data_dir=tmp_path)
        save_scan(_make_report(hostname="beta.io", score=60, classification="HIGH RISK"), data_dir=tmp_path)

        csv_text = export_history_csv(data_dir=tmp_path)
        reader = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(reader) == 2
        assert reader[0]["hostname"] == "alpha.io"
        assert reader[1]["hostname"] == "beta.io"

    def test_export_history_csv_missing_file_returns_valid_header_template(self, tmp_path):
        csv_text = export_history_csv(data_dir=tmp_path)
        assert "scan_date_time,hostname,risk_score,risk_classification" in csv_text
        reader = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(reader) == 0

    def test_export_history_csv_empty_file_returns_valid_header_template(self, tmp_path):
        (tmp_path / HISTORY_FILE_NAME).write_text("", encoding="utf-8")
        csv_text = export_history_csv(data_dir=tmp_path)
        assert "scan_date_time,hostname,risk_score,risk_classification" in csv_text


# ============================================================================
# 5. TestPrivacyRedaction
# ============================================================================

class TestHistoryPrivacyAndRedaction:
    """Tests ensuring no sensitive user data is stored."""

    def test_query_parameters_never_stored_in_history(self, tmp_path):
        report = _make_report(
            hostname="secure-bank.example.com",
            original_url="https://secure-bank.example.com/transfer?account=987654&pin=1234&token=secret_xyz",
            sanitized_url="https://secure-bank.example.com/transfer",
        )
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert "987654" not in content
        assert "1234" not in content
        assert "secret_xyz" not in content
        assert "account=" not in content
        assert "pin=" not in content
        assert "token=" not in content

    def test_fragment_never_stored_in_history(self, tmp_path):
        report = _make_report(
            hostname="portal.example.com",
            original_url="https://portal.example.com/dashboard#auth_token_secret_123",
            sanitized_url="https://portal.example.com/dashboard",
        )
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert "auth_token_secret_123" not in content
        assert "#" not in content

    def test_credentials_never_stored_in_history(self, tmp_path):
        report = _make_report(
            hostname="admin-console.local",
            original_url="http://admin:super_secret_password@admin-console.local/login",
            sanitized_url="http://admin-console.local/login",
        )
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert "super_secret_password" not in content
        assert "admin@" not in content

    def test_defensive_stripping_if_hostname_contains_stray_query_or_fragment(self, tmp_path):
        report = _make_report(hostname="example.com?token=leak#secret")
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert "token=leak" not in content
        assert "secret" not in content

    def test_defensive_stripping_deep_path(self, tmp_path):
        report = _make_report(hostname="example.com/login/user/admin")
        save_scan(report, data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == "example.com"


# ============================================================================
# 6. TestFormulaInjectionProtection
# ============================================================================

class TestHistoryFormulaInjectionProtection:
    """Tests protection against CSV Formula Injection (DDE)."""

    @pytest.mark.parametrize("prefix,payload", [
        ("=", "=cmd|' /C calc'!A0"),
        ("+", "+SUM(A1:A10)"),
        ("-", "-2+3+cmd|' /C calc'!A0"),
        ("@", "@SUM(1+1)"),
        ("\t", "\t=cmd|' /C calc'!A0"),
        ("\r", "\r=cmd|' /C calc'!A0"),
    ])
    def test_formula_injection_prefixes_escaped_with_single_quote(self, tmp_path, prefix, payload):
        report = _make_report(hostname=payload)
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert payload not in content or f"'{payload.lstrip()}" in content or f"'{payload}" in content

    def test_formula_injection_with_leading_spaces_neutralized(self, tmp_path):
        payload = "   =1+1"
        report = _make_report(hostname=payload)
        save_scan(report, data_dir=tmp_path)

        content = (tmp_path / HISTORY_FILE_NAME).read_text(encoding="utf-8")
        assert "'   =1+1" in content or "'=1+1" in content

    def test_clean_hostnames_not_prefixed_with_quote(self, tmp_path):
        clean_hosts = ["example.com", "sub.domain.org", "192.168.1.1", "google.co.uk"]
        for host in clean_hosts:
            save_scan(_make_report(hostname=host), data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        retrieved_hosts = [r["hostname"] for r in history]
        assert retrieved_hosts == clean_hosts
        for host in retrieved_hosts:
            assert not host.startswith("'")


# ============================================================================
# 7. TestCorruptedCsvHandling
# ============================================================================

class TestHistoryCorruptedCsvHandling:
    """Tests fault tolerance when encountering damaged or malformed CSV files."""

    def test_corrupted_line_with_missing_columns_skipped(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text(
            "scan_date_time,hostname,risk_score,risk_classification\n"
            "2026-11-15T09:00:00Z,valid1.com,10,LOW RISK\n"
            "2026-11-15T09:01:00Z,broken_missing_fields\n"
            "2026-11-15T09:02:00Z,valid2.com,50,MEDIUM RISK\n",
            encoding="utf-8",
        )
        history = get_history(data_dir=tmp_path)
        assert len(history) == 2
        assert history[0]["hostname"] == "valid1.com"
        assert history[1]["hostname"] == "valid2.com"

    def test_corrupted_line_with_extra_columns_skipped_or_sanitized(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text(
            "scan_date_time,hostname,risk_score,risk_classification\n"
            "2026-11-15T09:00:00Z,valid.com,10,LOW RISK\n"
            "2026-11-15T09:01:00Z,extra.com,20,LOW RISK,unexpected,column\n",
            encoding="utf-8",
        )
        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == "valid.com"

    def test_corrupted_line_with_non_numeric_score_skipped(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text(
            "scan_date_time,hostname,risk_score,risk_classification\n"
            "2026-11-15T09:00:00Z,valid.com,10,LOW RISK\n"
            "2026-11-15T09:01:00Z,bad_score.com,NOT_AN_INT,LOW RISK\n",
            encoding="utf-8",
        )
        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == "valid.com"

    def test_corrupted_header_missing_returns_empty_list_without_crash(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_text("random_unrelated_header_a,random_b\nval1,val2\n", encoding="utf-8")
        history = get_history(data_dir=tmp_path)
        assert history == []

    def test_corrupted_null_bytes_and_binary_garbage_handled_gracefully(self, tmp_path):
        csv_file = tmp_path / HISTORY_FILE_NAME
        csv_file.write_bytes(b"\x00\x00\xff\xfe\x00scan_date_time\n")
        history = get_history(data_dir=tmp_path)
        assert isinstance(history, list)


# ============================================================================
# 8. TestEdgeCasesAndConcurrency
# ============================================================================

class TestHistoryEdgeCasesAndConcurrency:
    """Tests special hostnames, large datasets, thread safety, and OS error resilience."""

    def test_unicode_and_punycode_hostnames_saved_and_read(self, tmp_path):
        idn_hosts = ["münchen.de", "xn--mnchen-3ya.de", "日本語.jp", "тест.рф"]
        for host in idn_hosts:
            save_scan(_make_report(hostname=host), data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        assert len(history) == len(idn_hosts)
        retrieved = [r["hostname"] for r in history]
        for host in idn_hosts:
            assert host in retrieved

    def test_ipv4_and_ipv6_hostnames_handled(self, tmp_path):
        ip_hosts = ["192.168.1.1", "10.0.0.1", "[2001:db8::1]", "[::1]"]
        for host in ip_hosts:
            save_scan(_make_report(hostname=host), data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        retrieved = [r["hostname"] for r in history]
        for host in ip_hosts:
            assert host in retrieved

    def test_hostnames_with_commas_and_quotes_handled_by_csv_quoting(self, tmp_path):
        weird_host = 'suspicious,"test",domain.com'
        save_scan(_make_report(hostname=weird_host), data_dir=tmp_path)

        history = get_history(data_dir=tmp_path)
        assert len(history) == 1
        assert history[0]["hostname"] == weird_host

    def test_stress_saving_and_reading_500_records(self, tmp_path):
        total = 500
        for i in range(total):
            rep = _make_report(
                hostname=f"site-{i}.example.com",
                score=i % 101,
                classification="LOW RISK" if (i % 101) <= 20 else "MEDIUM RISK" if (i % 101) <= 50 else "HIGH RISK",
                timestamp=f"2026-11-15T{i%24:02d}:00:00Z",
            )
            assert save_scan(rep, data_dir=tmp_path) is True

        history = get_history(data_dir=tmp_path)
        assert len(history) == total
        assert history[0]["hostname"] == "site-0.example.com"
        assert history[-1]["hostname"] == f"site-{total-1}.example.com"

    def test_concurrent_writes_thread_safety(self, tmp_path):
        num_threads = 10
        records_per_thread = 5

        def worker(thread_idx: int):
            for j in range(records_per_thread):
                rep = _make_report(
                    hostname=f"thread-{thread_idx}-site-{j}.com",
                    score=thread_idx * 5,
                    timestamp=f"2026-11-15T10:{thread_idx:02d}:{j:02d}Z",
                )
                save_scan(rep, data_dir=tmp_path)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker, i) for i in range(num_threads)]
            for f in futures:
                f.result()

        history = get_history(data_dir=tmp_path)
        assert len(history) == num_threads * records_per_thread
        all_hosts = {r["hostname"] for r in history}
        assert len(all_hosts) == num_threads * records_per_thread

    def test_os_error_handling_save_and_clear_graceful_failures(self, tmp_path):
        report = _make_report(hostname="fail.com")
        with patch("builtins.open", side_effect=PermissionError("Mock Permission Denied")):
            assert save_scan(report, data_dir=tmp_path) is False
            assert get_history(data_dir=tmp_path) == []
            assert export_history_csv(data_dir=tmp_path) == "scan_date_time,hostname,risk_score,risk_classification\n"

        with patch("pathlib.Path.unlink", side_effect=OSError("Mock disk failure")):
            with patch("builtins.open", side_effect=OSError("Mock file write failure")):
                # Ensure existing file triggers clear
                (tmp_path / HISTORY_FILE_NAME).write_text("dummy", encoding="utf-8")
                assert clear_history(data_dir=tmp_path) is False
