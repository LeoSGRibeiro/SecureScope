from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QCheckBox, QGroupBox, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QStatusBar, QFileDialog, QFrame,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

from scan_worker import ScanWorker
from security_utils import is_blocked_target, SEVERITY_COLORS, SEVERITY_ORDER
from export_utils import export_csv, export_pdf
from translations import translate_finding
from version import APP_VERSION, APP_AUTHOR

MODULES = ["headers", "tls", "cookies", "cors", "fingerprint", "subdomains", "owasp", "port_scan"]

STYLESHEET = """
QMainWindow, QWidget {
    background-color: #f7f4f1;
    color: #3a3733;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QLabel#HeaderTitle {
    font-size: 21px;
    font-weight: 700;
    color: #2a2724;
    letter-spacing: 1px;
}
QLabel#HeaderSubtitle {
    color: #8a857d;
    font-size: 12px;
}
QLineEdit {
    background-color: #ffffff;
    border: 1px solid #ddd7d0;
    border-radius: 6px;
    padding: 9px 12px;
    color: #2a2724;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #c4716b;
}
QPushButton {
    background-color: #c4716b;
    color: #fffaf9;
    border: none;
    border-radius: 6px;
    padding: 9px 18px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #d18d87;
}
QPushButton:pressed {
    background-color: #a85c56;
}
QPushButton:disabled {
    background-color: #e6e1da;
    color: #a8a39a;
}
QPushButton#SecondaryButton {
    background-color: #ffffff;
    color: #5c5750;
    border: 1px solid #ddd7d0;
}
QPushButton#SecondaryButton:hover {
    background-color: #f0ece6;
    border: 1px solid #ccc4ba;
}
QPushButton#SecondaryButton:disabled {
    background-color: #f0ece6;
    color: #b3ada3;
    border: 1px solid #e6e1da;
}
QGroupBox {
    border: 1px solid #ddd7d0;
    border-radius: 8px;
    margin-top: 8px;
    padding-top: 14px;
    font-weight: 600;
    color: #5c5750;
    background-color: #fbf9f7;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
    color: #8a857d;
}
QGroupBox#intrusiveGroup {
    border: 1px solid #d4956f;
}
QGroupBox#intrusiveGroup::title {
    color: #b9714a;
}
QCheckBox {
    color: #3a3733;
    spacing: 8px;
    padding: 2px;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1px solid #ccc4ba;
    background-color: #ffffff;
}
QCheckBox::indicator:checked {
    background-color: #c4716b;
    border: 1px solid #c4716b;
}
QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f7f4f1;
    border: 1px solid #ddd7d0;
    border-radius: 8px;
    gridline-color: #ece7e1;
    selection-background-color: #f3ddd9;
}
QTableWidget::item {
    padding: 6px;
}
QHeaderView::section {
    background-color: #f0ece6;
    color: #6f6a62;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #ddd7d0;
    font-weight: 600;
}
QStatusBar {
    background-color: #f0ece6;
    color: #8a857d;
    border-top: 1px solid #ddd7d0;
}
QScrollBar:vertical {
    background: #f7f4f1;
    width: 10px;
}
QScrollBar::handle:vertical {
    background: #ddd7d0;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #ccc4ba;
}
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"ThreatLens Desktop v{APP_VERSION}")
        self.resize(1080, 700)
        self.setStyleSheet(STYLESHEET)
        self.worker: ScanWorker | None = None
        self.last_result: dict | None = None
        self.last_url: str = ""
        self.translated: bool = False

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 18, 20, 14)
        layout.setSpacing(12)

        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("ThreatLens")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Enxergando ameaças antes que elas virem incidentes — digite uma URL e pressione Enter ou clique em Scan")
        subtitle.setObjectName("HeaderSubtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("background-color: #ddd7d0; max-height: 1px; border: none;")
        layout.addWidget(divider)

        url_row = QHBoxLayout()
        url_row.setSpacing(10)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://exemplo.com.br")
        self.url_input.setMinimumHeight(38)
        self.url_input.returnPressed.connect(self.start_scan)
        url_row.addWidget(self.url_input)
        self.scan_button = QPushButton("Scan")
        self.scan_button.setMinimumHeight(38)
        self.scan_button.setMinimumWidth(100)
        self.scan_button.setDefault(True)
        self.scan_button.clicked.connect(self.start_scan)
        url_row.addWidget(self.scan_button)
        layout.addLayout(url_row)

        modules_box = QGroupBox("Módulos de scan")
        modules_grid = QGridLayout(modules_box)
        modules_grid.setHorizontalSpacing(20)
        modules_grid.setVerticalSpacing(6)
        self.module_checks: dict[str, QCheckBox] = {}
        for i, name in enumerate(MODULES):
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.module_checks[name] = cb
            modules_grid.addWidget(cb, i // 4, i % 4)
        layout.addWidget(modules_box)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severidade", "CVE", "Título", "Descrição", "Recomendação"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        layout.addWidget(self.table)

        export_row = QHBoxLayout()
        self.translate_button = QPushButton("Traduzir para PT-BR")
        self.translate_button.setObjectName("SecondaryButton")
        self.translate_button.setEnabled(False)
        self.translate_button.clicked.connect(self.toggle_translation)
        export_row.addWidget(self.translate_button)
        export_row.addStretch()
        self.export_csv_button = QPushButton("Exportar CSV")
        self.export_csv_button.setObjectName("SecondaryButton")
        self.export_csv_button.setEnabled(False)
        self.export_csv_button.clicked.connect(self.export_csv_clicked)
        export_row.addWidget(self.export_csv_button)
        self.export_pdf_button = QPushButton("Exportar PDF")
        self.export_pdf_button.setObjectName("SecondaryButton")
        self.export_pdf_button.setEnabled(False)
        self.export_pdf_button.clicked.connect(self.export_pdf_clicked)
        export_row.addWidget(self.export_pdf_button)
        layout.addLayout(export_row)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Pronto. — ThreatLens v{APP_VERSION} — desenvolvido por {APP_AUTHOR}")

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "URL ausente", "Digite uma URL para escanear.")
            return
        if is_blocked_target(url):
            QMessageBox.critical(
                self, "Alvo bloqueado",
                "Endereços internos/privados (localhost, IPs RFC-1918, etc.) não podem ser escaneados.",
            )
            return

        selected = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        if not selected:
            QMessageBox.warning(self, "Nenhum módulo", "Selecione ao menos um módulo de scan.")
            return

        self.table.setRowCount(0)
        self.scan_button.setEnabled(False)
        self.url_input.setEnabled(False)
        self.export_csv_button.setEnabled(False)
        self.export_pdf_button.setEnabled(False)
        self.translate_button.setEnabled(False)
        self.translated = False
        self.translate_button.setText("Traduzir para PT-BR")
        self.last_result = None
        self.last_url = url
        self.status_bar.showMessage(f"Escaneando {url}...")

        self.worker = ScanWorker(url, selected)
        self.worker.finished_ok.connect(self.on_scan_done)
        self.worker.finished_error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_done(self, result: dict):
        self.scan_button.setEnabled(True)
        self.url_input.setEnabled(True)
        self.last_result = result
        if result.get("findings"):
            self.export_csv_button.setEnabled(True)
            self.export_pdf_button.setEnabled(True)
            self.translate_button.setEnabled(True)
        self.render_table()

    def render_table(self):
        result = self.last_result or {}
        findings = sorted(
            result.get("findings", []),
            key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
        )
        if self.translated:
            findings = [translate_finding(f) for f in findings]

        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            severity = finding.get("severity", "informational")
            color = QColor(SEVERITY_COLORS.get(severity, "#9ca3af"))
            for col, value in enumerate([
                severity.upper(),
                finding.get("cve", "") or "—",
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("recommendation", ""),
            ]):
                item = QTableWidgetItem(value)
                if col == 0:
                    bold_font = QFont()
                    bold_font.setBold(True)
                    item.setFont(bold_font)
                    item.setForeground(color)
                self.table.setItem(row, col, item)

        risk_score = result.get("risk_score")
        duration_ms = result.get("duration_ms")
        self.status_bar.showMessage(
            f"Concluído — risk_score: {risk_score} | duração: {duration_ms} ms | achados: {len(findings)}"
        )

    def toggle_translation(self):
        self.translated = not self.translated
        self.translate_button.setText("Ver em inglês" if self.translated else "Traduzir para PT-BR")
        self.render_table()

    def on_scan_error(self, message: str):
        self.scan_button.setEnabled(True)
        self.url_input.setEnabled(True)
        self.status_bar.showMessage("Falha no scan.")
        QMessageBox.critical(self, "Erro no scan", message)

    def _result_for_export(self) -> dict:
        if not self.translated:
            return self.last_result
        result = dict(self.last_result)
        result["findings"] = [translate_finding(f) for f in result.get("findings", [])]
        return result

    def export_csv_clicked(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar CSV", "threatlens_report.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            export_csv(self._result_for_export(), path)
            self.status_bar.showMessage(f"CSV exportado: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao exportar CSV", str(e))

    def export_pdf_clicked(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar PDF", "threatlens_report.pdf", "PDF (*.pdf)")
        if not path:
            return
        try:
            export_pdf(self._result_for_export(), self.last_url, path)
            self.status_bar.showMessage(f"PDF exportado: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao exportar PDF", str(e))
