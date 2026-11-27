"""
URL Guard — Storage Module
Provides CSV-based local persistence for URL scan history.
"""

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
    HISTORY_FILENAME,
    CSV_HEADER,
    CSV_FIELDNAMES,
)

__all__ = [
    "save_scan",
    "get_history",
    "clear_history",
    "export_history_csv",
    "neutralize_csv_injection",
    "sanitize_hostname_for_storage",
    "get_history_file_path",
    "DEFAULT_DATA_DIR",
    "DEFAULT_CSV_PATH",
    "HISTORY_FILE_NAME",
    "HISTORY_FILENAME",
    "CSV_HEADER",
    "CSV_FIELDNAMES",
]
