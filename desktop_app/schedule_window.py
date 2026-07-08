from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QFrame,
    QFormLayout, QSpinBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

import api_client

DEFAULT_EMAIL = "leonardo@guimaraesribeiro.com"
DEFAULT_MODULES = [
    "headers", "tls", "cookies", "cors", "fingerprint",
    "subdomains", "owasp", "port_scan",
]

DIALOG_STYLE = """
QDialog, QWidget { background-color: #151A23; color: #e2e8f0; font-family: 'Segoe UI', Arial, sans-serif; }
QLineEdit, QSpinBox {
    background: #202735; border: 1px solid #2C3445; border-radius: 4px;
    padding: 6px 8px; color: #e2e8f0; font-size: 13px;
}
QPushButton {
    background: #2DD4BF; color: #151A23; font-weight: bold; border: none;
    border-radius: 4px; padding: 7px 16px; font-size: 12px;
}
QPushButton:hover { background: #22bfab; }
QPushButton[danger="true"] { background: #F43F5E; color: white; }
QPushButton[danger="true"]:hover { background: #e02d4e; }
QPushButton[secondary="true"] { background: #2C3445; color: #e2e8f0; }
QPushButton[secondary="true"]:hover { background: #374151; }
QTableWidget { background: #202735; border: 1px solid #2C3445; gridline-color: #2C3445; color: #e2e8f0; }
QHeaderView::section { background: #1f2937; color: #9ca3af; padding: 6px; border: none; font-size: 11px; }
QTableWidget::item { padding: 4px 8px; }
QLabel { color: #e2e8f0; }
QLabel[title="true"] { font-size: 15px; font-weight: bold; color: #2DD4BF; }
QLabel[subtitle="true"] { font-size: 11px; color: #9ca3af; }
"""


class ScheduleWindow(QDialog):
    def __init__(self, token: str, parent=None):
        super().__init__(parent)
        self.token = token
        self.setWindowTitle("Agendamentos de Scan")
        self.setMinimumSize(820, 520)
        self.setStyleSheet(DIALOG_STYLE)
        self._build_ui()
        self._load()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 16, 20, 16)

        # Header
        title = QLabel("⏰ Agendamentos de Scan Automático")
        title.setProperty("title", True)
        layout.addWidget(title)
        subtitle = QLabel("Scans são executados automaticamente pelo servidor a cada intervalo configurado. "
                          "O relatório de delta (novas/resolvidas) é enviado por e-mail ao concluir.")
        subtitle.setProperty("subtitle", True)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet("background: #2C3445;")
        layout.addWidget(divider)

        # Form to add new schedule
        form_box = QFrame()
        form_box.setStyleSheet("QFrame { background: #202735; border-radius: 6px; padding: 4px; }")
        form_layout = QFormLayout(form_box)
        form_layout.setSpacing(8)
        form_layout.setContentsMargins(12, 10, 12, 10)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://www.exemplo.com.br")
        form_layout.addRow("URL do alvo:", self.url_input)

        self.email_input = QLineEdit(DEFAULT_EMAIL)
        form_layout.addRow("E-mail para notificação:", self.email_input)

        self.interval_spin = QSpinBox()
        self.interval_spin.setMinimum(1)
        self.interval_spin.setMaximum(365)
        self.interval_spin.setValue(7)
        self.interval_spin.setSuffix(" dias")
        form_layout.addRow("Intervalo:", self.interval_spin)

        add_btn = QPushButton("+ Adicionar agendamento")
        add_btn.clicked.connect(self._add)
        form_layout.addRow("", add_btn)
        layout.addWidget(form_box)

        # Table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "URL", "E-mail", "Intervalo", "Próximo scan", "Último scan", "Ações",
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        # Bottom buttons
        bottom = QHBoxLayout()
        refresh_btn = QPushButton("↻ Atualizar")
        refresh_btn.setProperty("secondary", True)
        refresh_btn.clicked.connect(self._load)
        bottom.addWidget(refresh_btn)
        bottom.addStretch()
        close_btn = QPushButton("Fechar")
        close_btn.setProperty("secondary", True)
        close_btn.clicked.connect(self.accept)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

    def _load(self):
        try:
            schedules = api_client.list_scheduled_scans(self.token)
        except Exception as e:
            QMessageBox.warning(self, "Erro ao carregar agendamentos",
                                f"Não foi possível conectar ao backend.\n{e}")
            return

        self.table.setRowCount(0)
        self._sched_ids = []
        for row, s in enumerate(schedules):
            self.table.insertRow(row)
            self._sched_ids.append(s["id"])

            self.table.setItem(row, 0, QTableWidgetItem(s["url"]))
            self.table.setItem(row, 1, QTableWidgetItem(s["email_to"]))
            self.table.setItem(row, 2, QTableWidgetItem(f"{s['interval_days']}d"))

            next_run = s.get("next_run_at", "")
            if next_run:
                next_run = next_run[:16].replace("T", " ")
            self.table.setItem(row, 3, QTableWidgetItem(next_run))

            last_run = s.get("last_run_at") or "—"
            if last_run != "—":
                last_run = last_run[:16].replace("T", " ")
            self.table.setItem(row, 4, QTableWidgetItem(last_run))

            # Action buttons cell
            actions = QFrame()
            actions_layout = QHBoxLayout(actions)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(6)

            is_active = s.get("is_active", True)
            toggle_btn = QPushButton("Pausar" if is_active else "Ativar")
            toggle_btn.setProperty("secondary", True)
            toggle_btn.setFixedWidth(64)
            sched_id = s["id"]
            toggle_btn.clicked.connect(lambda checked, sid=sched_id, active=is_active: self._toggle(sid, active))
            actions_layout.addWidget(toggle_btn)

            del_btn = QPushButton("Remover")
            del_btn.setProperty("danger", True)
            del_btn.setFixedWidth(70)
            del_btn.clicked.connect(lambda checked, sid=sched_id: self._delete(sid))
            actions_layout.addWidget(del_btn)

            self.table.setCellWidget(row, 5, actions)
            self.table.setRowHeight(row, 40)

    def _add(self):
        url = self.url_input.text().strip()
        email = self.email_input.text().strip()
        interval = self.interval_spin.value()

        if not url:
            QMessageBox.warning(self, "Campo obrigatório", "Informe a URL do alvo.")
            return
        if not email:
            QMessageBox.warning(self, "Campo obrigatório", "Informe o e-mail de notificação.")
            return

        try:
            api_client.create_scheduled_scan(
                self.token, url, email, DEFAULT_MODULES, interval
            )
            self.url_input.clear()
            self._load()
        except Exception as e:
            QMessageBox.critical(self, "Erro ao criar agendamento", str(e))

    def _toggle(self, sched_id: str, currently_active: bool):
        try:
            api_client.toggle_scheduled_scan(self.token, sched_id, not currently_active)
            self._load()
        except Exception as e:
            QMessageBox.critical(self, "Erro ao alterar agendamento", str(e))

    def _delete(self, sched_id: str):
        reply = QMessageBox.question(
            self, "Confirmar remoção",
            "Remover este agendamento? O histórico de scans não será apagado.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        try:
            api_client.delete_scheduled_scan(self.token, sched_id)
            self._load()
        except Exception as e:
            QMessageBox.critical(self, "Erro ao remover agendamento", str(e))
