"""
URL Guard - Pytest Configuration and Path Setup
Ensures the workspace root is on sys.path for direct module resolution.
"""

import sys
from pathlib import Path

# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
