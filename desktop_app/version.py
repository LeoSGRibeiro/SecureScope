"""
Single source of truth: the repo-root VERSION file.
Bump that file (and CHANGELOG.md) whenever something ships.
"""
from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"

try:
    APP_VERSION = _VERSION_FILE.read_text().strip()
except OSError:
    APP_VERSION = "0.0.0"

APP_AUTHOR = "Leonardo Ribeiro"
