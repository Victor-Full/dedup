"""
Componentes de interface reutilizáveis com PyQt6:
- Botões estilizados (ActionButton, DangerButton, SecondaryButton)
- Diálogos e modais de confirmação
- Cards de estatísticas e métricas para o Dashboard
"""
from PyQt6.QtWidgets import (
    QPushButton,
    QMessageBox,
    QFrame,
    QVBoxLayout,
    QLabel,
    QWidget,
)
from PyQt6.QtCore import Qt


class ActionButton(QPushButton):
    """Botão de ação primário estilizado."""
    def __init__(self, text: str, parent: QWidget | None = None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: bold;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
            QPushButton:pressed {
                background-color: #1e40af;
            }
            QPushButton:disabled {
                background-color: #94a3b8;
                color: #e2e8f0;
            }
        """)


class DangerButton(QPushButton):
    """Botão para ações críticas (ex: exclusão definitiva)."""
    def __init__(self, text: str, parent: QWidget | None = None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                font-weight: bold;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 13px;
                border: none;
            }
            QPushButton:hover {
                background-color: #b91c1c;
            }
            QPushButton:pressed {
                background-color: #991b1b;
            }
        """)


class StatCard(QFrame):
    """Card de métricas para visualização rápida no Dashboard."""
    def __init__(self, title: str, value: str = "0", parent: QWidget | None = None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            StatCard {
                background-color: #ffffff;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 12px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet("color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase;")

        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet("color: #0f172a; font-size: 24px; font-weight: bold;")

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_value)

    def set_value(self, value: str):
        self.lbl_value.setText(value)


def show_confirm_dialog(parent: QWidget, title: str, message: str) -> bool:
    """Exibe modal de confirmação com opções Sim / Não."""
    reply = QMessageBox.question(
        parent,
        title,
        message,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        QMessageBox.StandardButton.No
    )
    return reply == QMessageBox.StandardButton.Yes
