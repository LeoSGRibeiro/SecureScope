import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from PySide6.QtCore import QThread, Signal
from app.services.scanners.orchestrator import run_scan


class ScanWorker(QThread):
    finished_ok = Signal(dict)
    finished_error = Signal(str)

    def __init__(self, url: str, modules: list[str] | None, parent=None):
        super().__init__(parent)
        self.url = url
        self.modules = modules

    def run(self):
        try:
            result = asyncio.run(run_scan(self.url, self.modules))
            self.finished_ok.emit(result)
        except Exception as e:
            self.finished_error.emit(str(e))
