"""Inicialização com auditoria obrigatória e erros visíveis."""

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox


sys.path.insert(
    0,
    str(Path(__file__).resolve().parent),
)

from gui.app import DedupApp
from utils.logger import (
    DEFAULT_LOG_PATH,
    setup_logger,
    audit_event,
)
from utils.config_parser import load_config


def main():
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Dedup v1")

    try:
        setup_logger()
        audit_event("APPLICATION_STARTED")

        config = load_config()
        window = DedupApp(config=config)
        window.show()

    except Exception as error:
        message = f"{type(error).__name__}: {error}"

        try:
            audit_event(
                "APPLICATION_START_FAILED",
                error=message,
            )

        except Exception as audit_error:
            message += f"\nAuditoria: {audit_error}"

        QMessageBox.critical(
            None,
            "Não foi possível iniciar o Dedup",
            f"{message}\n\nRegistro: {DEFAULT_LOG_PATH}",
        )
        return 1

    code = qt_app.exec()

    try:
        audit_event(
            "APPLICATION_STOPPED",
            exit_code=code,
        )

    except Exception as error:
        QMessageBox.critical(
            None,
            "Falha ao registrar encerramento",
            str(error),
        )
        return 1

    return code


if __name__ == "__main__":
    sys.exit(main())