"""
URL Guard — Local Storage & History Manager
Module: storage/history_manager.py

Handles local CSV persistence, retrieval, clearing, and export of scan history.
Enforces privacy redaction, CSV Formula Injection (DDE) prevention, and defensive
file handling against corruptions and filesystem errors.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import logging
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple, Union
import urllib.parse

logger = logging.getLogger(__name__)

# Thread lock for file operations
_FILE_LOCK = threading.Lock()

# CSV Schema Constants
CSV_HEADER = ["scan_date_time", "hostname", "risk_score", "risk_classification"]
CSV_FIELDNAMES = CSV_HEADER
CSV_HEADER_STR = ",".join(CSV_HEADER) + "\n"
CSV_HEADER_LINE = CSV_HEADER_STR

# Formula injection trigger characters (OWASP recommendation)
FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

# Default storage locations
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"
HISTORY_FILE_NAME = "scan_history.csv"
HISTORY_FILENAME = HISTORY_FILE_NAME
DEFAULT_CSV_PATH = DEFAULT_DATA_DIR / HISTORY_FILE_NAME


def get_history_file_path(data_dir: Optional[Union[Path, str]] = None) -> Path:
    """Resolve the scan_history.csv path given an optional directory or file path."""
    if data_dir is None:
        return DEFAULT_CSV_PATH
    p = Path(data_dir)
    if p.suffix.lower() == ".csv":
        return p
    return p / HISTORY_FILE_NAME


def _resolve_paths(data_dir: Optional[Union[Path, str]] = None) -> Tuple[Path, Path]:
    """Resolve target directory and CSV file path."""
    csv_path = get_history_file_path(data_dir)
    return csv_path.parent, csv_path


def sanitize_hostname_for_storage(raw_hostname: Any) -> str:
    """
    Extracts and sanitizes the hostname to guarantee that no query parameters,
    URL fragments, paths, or embedded credentials leak into CSV storage.
    Preserves formula injection payloads so they can be neutralized by neutralize_csv_injection.
    """
    if raw_hostname is None:
        return ""
    host_str = str(raw_hostname).strip()
    if not host_str:
        return ""

    # If it is a formula injection attempt, do not truncate paths or slashes
    if host_str.lstrip(" ").startswith(FORMULA_TRIGGERS):
        return host_str

    # 1. If full URL was provided
    if "://" in host_str:
        try:
            parsed = urllib.parse.urlsplit(host_str)
            if parsed.hostname:
                host_str = parsed.hostname
            else:
                host_str = host_str.split("?")[0].split("#")[0].split("/")[0]
        except Exception:
            host_str = host_str.split("?")[0].split("#")[0].split("/")[0]

    # 2. Defensively strip query, fragment, and path
    host_str = host_str.split("?")[0].split("#")[0].split("/")[0]

    # 3. Strip embedded credentials if present (user:pass@host)
    if "@" in host_str and not host_str.startswith("@"):
        host_str = host_str.rsplit("@", 1)[-1]

    # 4. Strip port from domain or IPv4 (preserving bracketed IPv6)
    if host_str.startswith("["):
        if "]" in host_str:
            host_str = host_str[:host_str.find("]") + 1]
    elif ":" in host_str:
        parts = host_str.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            host_str = parts[0]

    return host_str.strip().lower()


def neutralize_csv_injection(value: Any) -> str:
    """
    Neutralizes CSV formula injection (DDE) by prepending a single quote (')
    if the string value starts with any trigger character: =, +, -, @, \\t, \\r.
    Handles values with leading whitespace that spreadsheets trim before execution.
    """
    if value is None:
        return ""
    val_str = str(value)
    stripped = val_str.lstrip(" ")
    if stripped.startswith(FORMULA_TRIGGERS):
        if not val_str.startswith("'"):
            return "'" + val_str
    return val_str


def save_scan(report: Any, data_dir: Optional[Union[Path, str]] = None) -> bool:
    """
    Persists a completed scan report into the local scan_history.csv file.
    Accepts an AnalysisReport object or equivalent dictionary.
    Returns True if successfully saved, False on invalid input or file error.
    """
    if report is None:
        return False

    try:
        # Extract fields from AnalysisReport or dictionary
        if hasattr(report, "normalized_hostname") and hasattr(report, "total_risk_score"):
            raw_host = report.normalized_hostname
            raw_score = report.total_risk_score
            raw_level = getattr(report, "risk_classification", "LOW RISK")
            raw_time = getattr(report, "timestamp", None)
        elif isinstance(report, dict):
            if not any(k in report for k in ("normalized_hostname", "hostname", "risk_score", "total_risk_score")):
                return False
            raw_host = report.get("normalized_hostname") or report.get("hostname", "")
            raw_score = report.get("total_risk_score") if "total_risk_score" in report else report.get("risk_score", 0)
            raw_level = report.get("risk_classification", "LOW RISK")
            raw_time = report.get("timestamp") or report.get("scan_date_time")
        else:
            return False

        # Sanitize and redact hostname
        clean_host = sanitize_hostname_for_storage(raw_host)
        if not clean_host:
            clean_host = "unknown"

        # Resolve timestamp
        if not raw_time:
            raw_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Format score & classification
        try:
            score_int = int(float(str(raw_score).strip()))
            score_int = max(0, min(100, score_int))
            score_str = str(score_int)
        except Exception:
            score_str = "0"

        level_str = str(raw_level).strip() if raw_level else "LOW RISK"
        if not level_str:
            level_str = "LOW RISK"

        # CSV Formula Injection neutralization
        escaped_time = neutralize_csv_injection(raw_time)
        escaped_host = neutralize_csv_injection(clean_host)
        escaped_score = neutralize_csv_injection(score_str)
        escaped_level = neutralize_csv_injection(level_str)

        row = [escaped_time, escaped_host, escaped_score, escaped_level]

        target_dir, csv_path = _resolve_paths(data_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        with _FILE_LOCK:
            needs_header = not csv_path.exists() or csv_path.stat().st_size == 0

            # Always open with newline="" on Windows and UTF-8 encoding
            with open(csv_path, mode="a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                if needs_header:
                    writer.writerow(CSV_HEADER)
                writer.writerow(row)

        return True

    except Exception as exc:
        logger.error(f"Failed to save scan: {exc}")
        return False


def get_history(data_dir: Optional[Union[Path, str]] = None) -> List[Dict[str, Any]]:
    """
    Retrieves previous scan records from scan_history.csv in chronological order.
    Gracefully handles nonexistent directory, missing file, 0-byte file, or corrupted lines.
    Returns list of dicts: [{'scan_date_time': ..., 'hostname': ..., 'risk_score': ..., 'risk_classification': ...}]
    """
    try:
        csv_path = get_history_file_path(data_dir)
        if not csv_path.exists() or csv_path.stat().st_size == 0:
            return []

        records: List[Dict[str, Any]] = []

        with open(csv_path, mode="r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)

            try:
                first_row = next(reader, None)
            except (csv.Error, StopIteration):
                return []

            if not first_row:
                return []

            first_row_clean = [col.strip() for col in first_row]
            # Check if first row is header
            if len(first_row_clean) == 4 and first_row_clean[0].lower() == "scan_date_time":
                pass
            else:
                # If first row contains valid data (no header present)
                if len(first_row_clean) == 4:
                    try:
                        int(first_row_clean[2].lstrip("'"))
                        records.append({
                            "scan_date_time": first_row_clean[0],
                            "hostname": first_row_clean[1],
                            "risk_score": first_row_clean[2],
                            "risk_classification": first_row_clean[3],
                        })
                    except ValueError:
                        pass

            while True:
                try:
                    row = next(reader)
                except StopIteration:
                    break
                except csv.Error as csv_err:
                    logger.warning(f"Skipping line with CSV parse error: {csv_err}")
                    continue

                try:
                    if not row or not any(cell.strip() for cell in row):
                        continue
                    if len(row) != 4:
                        logger.warning(f"Skipping corrupted line with {len(row)} columns")
                        continue

                    date_time, host, score, level = [cell.strip() for cell in row]

                    try:
                        int(score.lstrip("'"))
                    except ValueError:
                        logger.warning(f"Skipping line with non-integer score: {score}")
                        continue

                    records.append({
                        "scan_date_time": date_time,
                        "hostname": host,
                        "risk_score": score,
                        "risk_classification": level,
                    })
                except Exception as row_exc:
                    logger.warning(f"Skipping unparseable line: {row_exc}")
                    continue

        return records

    except Exception as exc:
        logger.error(f"Failed to read scan history: {exc}")
        return []


def clear_history(data_dir: Optional[Union[Path, str]] = None) -> bool:
    """
    Clears all scan history records.
    Returns True if successfully cleared (or already absent/empty), False on error.
    """
    try:
        csv_path = get_history_file_path(data_dir)
        with _FILE_LOCK:
            if not csv_path.exists():
                return True

            try:
                csv_path.unlink(missing_ok=True)
            except OSError:
                with open(csv_path, mode="w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(CSV_HEADER)

            return True

    except Exception as exc:
        logger.error(f"Failed to clear scan history: {exc}")
        return False


def export_history_csv(data_dir: Optional[Union[Path, str]] = None) -> str:
    """
    Exports current scan history as a formatted CSV string for user download.
    Returns standard CSV header line if history is empty, missing, or unreadable.
    """
    try:
        csv_path = get_history_file_path(data_dir)
        if not csv_path.exists() or csv_path.stat().st_size == 0:
            return CSV_HEADER_STR

        content = csv_path.read_text(encoding="utf-8", errors="replace")
        if not content.strip():
            return CSV_HEADER_STR

        return content

    except Exception as exc:
        logger.error(f"Failed to export history CSV: {exc}")
        return CSV_HEADER_STR
