from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QLabel, QCheckBox, QGroupBox, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QStatusBar, QFileDialog, QFrame,
    QRadioButton, QButtonGroup, QInputDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont

import re
from datetime import datetime
from urllib.parse import urlparse
from scan_worker import ScanWorker
from security_utils import is_blocked_target, SEVERITY_COLORS, SEVERITY_ORDER
from export_utils import export_csv, export_pdf, export_pdf_gerencial
from translations import translate_finding
from version import APP_VERSION, APP_AUTHOR
import api_client

PASSIVE_MODULES = ["headers", "tls", "cookies", "cors", "fingerprint", "subdomains", "owasp", "port_scan"]
INTRUSIVE_MODULES = ["sqli_xss", "dirbuster", "auth_bruteforce", "port_scan_deep"]
MODULES = PASSIVE_MODULES + INTRUSIVE_MODULES
INTRUSIVE_CONFIRMATION_PHRASE = "EU ENTENDO OS RISCOS"
INFRA_PROFILE_TITLE = "Infrastructure & Technology Profile"

DARK_DIVIDER = "#2C3445"
LIGHT_DIVIDER = "#E2E8F0"

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #151A23;
    color: #F5F7FA;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QLabel#HeaderTitle {
    font-size: 21px;
    font-weight: 700;
    color: #F5F7FA;
    letter-spacing: 1px;
}
QLabel#HeaderSubtitle {
    color: #8B95A7;
    font-size: 12px;
}
QLineEdit {
    background-color: #202735;
    border: 1px solid #2C3445;
    border-radius: 6px;
    padding: 9px 12px;
    color: #F5F7FA;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #2DD4BF;
}
QPushButton {
    background-color: #2DD4BF;
    color: #151A23;
    border: none;
    border-radius: 6px;
    padding: 9px 18px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #5EEAD4;
}
QPushButton:pressed {
    background-color: #14B8A6;
}
QPushButton:disabled {
    background-color: #202735;
    color: #5b6577;
}
QPushButton#SecondaryButton {
    background-color: #202735;
    color: #F5F7FA;
    border: 1px solid #2C3445;
}
QPushButton#SecondaryButton:hover {
    background-color: #2A3344;
    border: 1px solid #84CC16;
}
QPushButton#SecondaryButton:disabled {
    background-color: #1a202c;
    color: #5b6577;
    border: 1px solid #202735;
}
QGroupBox {
    border: 1px solid #2C3445;
    border-radius: 8px;
    margin-top: 8px;
    padding-top: 14px;
    font-weight: 600;
    color: #8B95A7;
    background-color: #202735;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
    color: #8B95A7;
}
QGroupBox#intrusiveGroup {
    border: 1px solid #F43F5E;
}
QGroupBox#intrusiveGroup::title {
    color: #F43F5E;
}
QCheckBox {
    color: #F5F7FA;
    spacing: 8px;
    padding: 2px;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1px solid #2C3445;
    background-color: #202735;
}
QCheckBox::indicator:checked {
    background-color: #2DD4BF;
    border: 1px solid #2DD4BF;
}
QTableWidget {
    background-color: #1a202c;
    alternate-background-color: #202735;
    border: 1px solid #2C3445;
    border-radius: 8px;
    gridline-color: #2C3445;
    selection-background-color: #14463f;
}
QTableWidget::item {
    padding: 6px;
}
QHeaderView::section {
    background-color: #202735;
    color: #8B95A7;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #2DD4BF;
    font-weight: 600;
}
QStatusBar {
    background-color: #202735;
    color: #8B95A7;
    border-top: 1px solid #2C3445;
}
QScrollBar:vertical {
    background: #1a202c;
    width: 10px;
}
QScrollBar::handle:vertical {
    background: #2C3445;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #3a445a;
}
"""

LIGHT_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #F5F7FA;
    color: #151A23;
    font-family: "Segoe UI", sans-serif;
    font-size: 13px;
}
QLabel#HeaderTitle {
    font-size: 21px;
    font-weight: 700;
    color: #151A23;
    letter-spacing: 1px;
}
QLabel#HeaderSubtitle {
    color: #64748B;
    font-size: 12px;
}
QLineEdit {
    background-color: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-radius: 6px;
    padding: 9px 12px;
    color: #151A23;
    font-size: 13px;
}
QLineEdit:focus {
    border: 1px solid #0D9488;
}
QPushButton {
    background-color: #0D9488;
    color: #FFFFFF;
    border: none;
    border-radius: 6px;
    padding: 9px 18px;
    font-weight: 600;
}
QPushButton:hover {
    background-color: #14B8A6;
}
QPushButton:pressed {
    background-color: #0F766E;
}
QPushButton:disabled {
    background-color: #E2E8F0;
    color: #94A3B8;
}
QPushButton#SecondaryButton {
    background-color: #FFFFFF;
    color: #151A23;
    border: 1px solid #E2E8F0;
}
QPushButton#SecondaryButton:hover {
    background-color: #F1F4F8;
    border: 1px solid #65A30D;
}
QPushButton#SecondaryButton:disabled {
    background-color: #F1F4F8;
    color: #94A3B8;
    border: 1px solid #E2E8F0;
}
QGroupBox {
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    margin-top: 8px;
    padding-top: 14px;
    font-weight: 600;
    color: #64748B;
    background-color: #FFFFFF;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 4px;
    color: #64748B;
}
QGroupBox#intrusiveGroup {
    border: 1px solid #F43F5E;
}
QGroupBox#intrusiveGroup::title {
    color: #F43F5E;
}
QCheckBox {
    color: #151A23;
    spacing: 8px;
    padding: 2px;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1px solid #E2E8F0;
    background-color: #FFFFFF;
}
QCheckBox::indicator:checked {
    background-color: #0D9488;
    border: 1px solid #0D9488;
}
QTableWidget {
    background-color: #FFFFFF;
    alternate-background-color: #F5F7FA;
    border: 1px solid #E2E8F0;
    border-radius: 8px;
    gridline-color: #E2E8F0;
    selection-background-color: #CCFBF1;
}
QTableWidget::item {
    padding: 6px;
}
QHeaderView::section {
    background-color: #F1F4F8;
    color: #64748B;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #0D9488;
    font-weight: 600;
}
QStatusBar {
    background-color: #F1F4F8;
    color: #64748B;
    border-top: 1px solid #E2E8F0;
}
QScrollBar:vertical {
    background: #FFFFFF;
    width: 10px;
}
QScrollBar::handle:vertical {
    background: #E2E8F0;
    border-radius: 5px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #CBD5E1;
}
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"ThreatLens Desktop v{APP_VERSION}")
        self.resize(1080, 700)
        self.dark_mode = True
        self.setStyleSheet(DARK_STYLESHEET)
        self.worker: ScanWorker | None = None
        self.last_result: dict | None = None
        self.last_url: str = ""
        self.last_scan_time: datetime | None = None
        self.translated: bool = False
        self._api_token: str | None = None

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 18, 20, 14)
        layout.setSpacing(12)

        header_row = QHBoxLayout()
        header = QVBoxLayout()
        header.setSpacing(2)
        title = QLabel("ThreatLens")
        title.setObjectName("HeaderTitle")
        subtitle = QLabel("Enxergando ameaças antes que elas virem incidentes — digite uma URL e pressione Enter ou clique em Scan")
        subtitle.setObjectName("HeaderSubtitle")
        header.addWidget(title)
        header.addWidget(subtitle)
        header_row.addLayout(header)
        header_row.addStretch()
        self.theme_button = QPushButton("☀ Tema claro")
        self.theme_button.setObjectName("SecondaryButton")
        self.theme_button.setMinimumHeight(38)
        self.theme_button.setToolTip("Alternar entre tema claro e escuro")
        self.theme_button.clicked.connect(self.toggle_theme)
        header_row.addWidget(self.theme_button)
        self.schedule_button = QPushButton("⏰ Agendamentos")
        self.schedule_button.setObjectName("SecondaryButton")
        self.schedule_button.setMinimumHeight(38)
        self.schedule_button.setToolTip("Gerenciar scans automáticos semanais")
        self.schedule_button.clicked.connect(self.open_schedule_window)
        header_row.addWidget(self.schedule_button)
        layout.addLayout(header_row)

        self.divider = QFrame()
        self.divider.setFrameShape(QFrame.HLine)
        self.divider.setStyleSheet(f"background-color: {DARK_DIVIDER}; max-height: 1px; border: none;")
        layout.addWidget(self.divider)

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

        mode_row = QHBoxLayout()
        mode_row.setSpacing(16)
        mode_row.addWidget(QLabel("Modo de scan:"))
        self.mode_group = QButtonGroup(self)
        self.radio_standard = QRadioButton("Padrão (recomendado)")
        self.radio_standard.setChecked(True)
        self.radio_deep = QRadioButton("Profundo (intrusivo) ⚠")
        self.mode_group.addButton(self.radio_standard)
        self.mode_group.addButton(self.radio_deep)
        self.radio_standard.toggled.connect(self._on_mode_changed)
        mode_row.addWidget(self.radio_standard)
        mode_row.addWidget(self.radio_deep)
        mode_row.addStretch()
        layout.addLayout(mode_row)

        self.module_checks: dict[str, QCheckBox] = {}

        modules_box = QGroupBox("Módulos de scan")
        modules_grid = QGridLayout(modules_box)
        modules_grid.setHorizontalSpacing(20)
        modules_grid.setVerticalSpacing(6)
        for i, name in enumerate(PASSIVE_MODULES):
            cb = QCheckBox(name)
            cb.setChecked(True)
            self.module_checks[name] = cb
            modules_grid.addWidget(cb, i // 4, i % 4)
        layout.addWidget(modules_box)

        self.intrusive_box = QGroupBox("Módulos intrusivos ⚠")
        self.intrusive_box.setObjectName("intrusiveGroup")
        intrusive_grid = QGridLayout(self.intrusive_box)
        intrusive_grid.setHorizontalSpacing(20)
        intrusive_grid.setVerticalSpacing(6)
        for i, name in enumerate(INTRUSIVE_MODULES):
            cb = QCheckBox(name)
            cb.setChecked(False)
            self.module_checks[name] = cb
            intrusive_grid.addWidget(cb, i // 4, i % 4)
        self.intrusive_box.setVisible(False)
        layout.addWidget(self.intrusive_box)

        self.infra_profile_label = QLabel("")
        self.infra_profile_label.setObjectName("HeaderSubtitle")
        self.infra_profile_label.setWordWrap(True)
        self.infra_profile_label.setVisible(False)
        layout.addWidget(self.infra_profile_label)

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
        self.export_pdf_gerencial_button = QPushButton("📋 Rel. Gerencial")
        self.export_pdf_gerencial_button.setObjectName("SecondaryButton")
        self.export_pdf_gerencial_button.setEnabled(False)
        self.export_pdf_gerencial_button.clicked.connect(self.export_pdf_gerencial_clicked)
        export_row.addWidget(self.export_pdf_gerencial_button)
        layout.addLayout(export_row)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Pronto. — ThreatLens v{APP_VERSION} — desenvolvido por {APP_AUTHOR}")

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.setStyleSheet(DARK_STYLESHEET)
            self.divider.setStyleSheet(f"background-color: {DARK_DIVIDER}; max-height: 1px; border: none;")
            self.theme_button.setText("☀ Tema claro")
        else:
            self.setStyleSheet(LIGHT_STYLESHEET)
            self.divider.setStyleSheet(f"background-color: {LIGHT_DIVIDER}; max-height: 1px; border: none;")
            self.theme_button.setText("🌙 Tema escuro")

    def _on_mode_changed(self, standard_checked: bool):
        self.intrusive_box.setVisible(not standard_checked)
        if standard_checked:
            for name in INTRUSIVE_MODULES:
                self.module_checks[name].setChecked(False)

    def _confirm_intrusive(self, selected_intrusive: list[str]) -> bool:
        modules_str = ", ".join(selected_intrusive)
        text, ok = QInputDialog.getText(
            self,
            "Confirmação de Teste Intrusivo",
            (
                f"Você selecionou módulos intrusivos ({modules_str}) que enviam payloads de ataque reais "
                "(injeção SQL/XSS, brute-force, varredura ampla), podendo disparar WAF/IDS ou causar "
                "bloqueio de contas no alvo.\n\n"
                "Só prossiga se você tem autorização explícita para testes intrusivos contra este alvo.\n\n"
                f"Digite \"{INTRUSIVE_CONFIRMATION_PHRASE}\" para continuar:"
            ),
        )
        if not ok or text.strip().upper() != INTRUSIVE_CONFIRMATION_PHRASE:
            self.status_bar.showMessage("Scan intrusivo cancelado — confirmação não fornecida.")
            return False
        return True

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

        deep_mode = self.radio_deep.isChecked()
        if deep_mode:
            selected = [name for name, cb in self.module_checks.items() if cb.isChecked()]
        else:
            selected = [name for name in PASSIVE_MODULES if self.module_checks[name].isChecked()]

        if not selected:
            QMessageBox.warning(self, "Nenhum módulo", "Selecione ao menos um módulo de scan.")
            return

        selected_intrusive = [m for m in selected if m in INTRUSIVE_MODULES]
        if deep_mode and selected_intrusive and not self._confirm_intrusive(selected_intrusive):
            return

        self.table.setRowCount(0)
        self.scan_button.setEnabled(False)
        self.url_input.setEnabled(False)
        self.export_csv_button.setEnabled(False)
        self.export_pdf_button.setEnabled(False)
        self.export_pdf_gerencial_button.setEnabled(False)
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
        self.last_scan_time = datetime.now()
        if result.get("findings"):
            self.export_csv_button.setEnabled(True)
            self.export_pdf_button.setEnabled(True)
            self.export_pdf_gerencial_button.setEnabled(True)
            self.translate_button.setEnabled(True)
        self.render_table()

    def render_table(self):
        result = self.last_result or {}
        all_findings = result.get("findings", [])
        infra_profile = next((f for f in all_findings if f.get("title") == INFRA_PROFILE_TITLE), None)
        findings = sorted(
            [f for f in all_findings if f.get("title") != INFRA_PROFILE_TITLE],
            key=lambda f: SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else len(SEVERITY_ORDER),
        )
        if self.translated:
            findings = [translate_finding(f) for f in findings]
            if infra_profile:
                infra_profile = translate_finding(infra_profile)

        if infra_profile:
            self.infra_profile_label.setText(
                f"<b>Perfil de Infraestrutura e Tecnologia:</b> {infra_profile.get('description', '')}"
            )
            self.infra_profile_label.setVisible(True)
        else:
            self.infra_profile_label.setVisible(False)

        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            severity = finding.get("severity", "informational")
            color = QColor(SEVERITY_COLORS.get(severity, "#8B95A7"))
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

    def _default_export_name(self, extension: str) -> str:
        host = urlparse(self.last_url).netloc or urlparse(self.last_url).path or "threatlens"
        host = host.split(":")[0]  # drop port
        safe_host = re.sub(r"[^a-zA-Z0-9.-]", "_", host).strip("_") or "threatlens"
        timestamp = (self.last_scan_time or datetime.now()).strftime("%Y%m%d_%H%M")
        return f"{safe_host}_{timestamp}.{extension}"

    def export_csv_clicked(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar CSV", self._default_export_name("csv"), "CSV (*.csv)")
        if not path:
            return
        try:
            export_csv(self._result_for_export(), path, self.last_scan_time)
            self.status_bar.showMessage(f"CSV exportado: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao exportar CSV", str(e))

    def export_pdf_clicked(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exportar PDF", self._default_export_name("pdf"), "PDF (*.pdf)")
        if not path:
            return
        try:
            export_pdf(self._result_for_export(), self.last_url, path, self.last_scan_time)
            self.status_bar.showMessage(f"PDF exportado: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao exportar PDF", str(e))

    def _default_gerencial_name(self) -> str:
        base = self._default_export_name("pdf")
        return base.replace(".pdf", "_gerencial.pdf")

    def export_pdf_gerencial_clicked(self):
        if not self.last_result:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Exportar Relatório Gerencial", self._default_gerencial_name(), "PDF (*.pdf)"
        )
        if not path:
            return
        try:
            export_pdf_gerencial(self._result_for_export(), self.last_url, path, self.last_scan_time)
            self.status_bar.showMessage(f"Relatório gerencial exportado: {path}")
            QMessageBox.information(self, "Exportação concluída", f"Relatório gerencial salvo em:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Erro ao exportar relatório gerencial", str(e))

    def open_schedule_window(self):
        from schedule_window import ScheduleWindow

        # Ensure we have a valid API token
        if not self._api_token:
            self._api_token = self._prompt_login()
            if not self._api_token:
                return

        try:
            dlg = ScheduleWindow(self._api_token, parent=self)
            dlg.exec()
        except Exception as e:
            # Token may have expired — clear it and let the user retry
            self._api_token = None
            QMessageBox.critical(self, "Erro ao abrir agendamentos", str(e))

    def _prompt_login(self) -> str | None:
        """Ask for API credentials and return a JWT token, or None on cancel/error."""
        from PySide6.QtWidgets import QDialog, QFormLayout, QDialogButtonBox

        dlg = QDialog(self)
        dlg.setWindowTitle("Login — Backend ThreatLens")
        dlg.setMinimumWidth(360)
        form = QFormLayout(dlg)
        form.setContentsMargins(16, 16, 16, 16)
        form.setSpacing(10)

        email_field = QLineEdit("leonardo@guimaraesribeiro.com")
        password_field = QLineEdit()
        password_field.setEchoMode(QLineEdit.Password)
        form.addRow("E-mail:", email_field)
        form.addRow("Senha:", password_field)

        info = QLabel("Necessário para gerenciar agendamentos no servidor Docker.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #9ca3af; font-size: 11px;")
        form.addRow(info)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() != QDialog.Accepted:
            return None

        try:
            token = api_client.login(email_field.text().strip(), password_field.text())
            return token
        except Exception as e:
            QMessageBox.critical(self, "Falha no login", f"Não foi possível autenticar:\n{e}")
            return None
