"""Interface do módulo 6: captura, restauração e reconciliação."""

from pathlib import Path

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QFileDialog,
    QMessageBox,
)

from core.backup_catalog import (
    BackupCatalog,
    LIMITATION,
)
from core.windows_backup import SCOPE
from core.windows_recovery import RestoreResult
from utils.audit import OperationAuditError
from utils.config_parser import (
    validate_config,
    save_config,
)


class CatalogWorker(QThread):
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(
        self,
        catalog,
        *,
        operation_id=None,
        destination=None,
        action="restore",
        windows=False,
        records=(),
        parent=None,
    ):
        super().__init__(parent)

        self.catalog = catalog
        self.operation_id = operation_id
        self.destination = destination
        self.action = action
        self.windows = windows
        self.records = tuple(
            dict(row)
            for row in records
        )

    def completed(
        self,
        result,
        *,
        audit=None,
    ):
        if self.action == "reconcile":
            payload = {
                "reconciliation": result,
            }

        elif self.action == "capture":
            payload = {
                "captured": result,
            }

        else:
            destination = (
                result.destination
                if isinstance(result, RestoreResult)
                else result
            )

            payload = {
                "destination": str(destination),
                "action": self.action,
                "warnings": (
                    list(result.warnings)
                    if isinstance(
                        result,
                        RestoreResult,
                    )
                    else []
                ),
            }

        payload.update(
            audit_pending=bool(audit),
            detail=audit or "",
            windows=self.windows,
        )

        self.result_ready.emit(payload)

    def run(self):
        completed = []

        try:
            if self.action == "capture":
                for index, row in enumerate(
                    self.records,
                    1,
                ):
                    self.progress.emit(
                        "Captura e teste "
                        f"{index}/{len(self.records)}: "
                        f"{row['path']}"
                    )

                    path = (
                        self.catalog.windows.backup_complete(
                            row["path"],
                            expected_sha256=row["hash"],
                            expected_signature=(
                                row["read_signature"]
                            ),
                        )
                    )

                    completed.append(str(path))

                self.completed(completed)

            elif self.operation_id is None:
                self.result_ready.emit({
                    "entries": self.catalog.list_entries(
                        progress=self.progress.emit,
                    ),
                })

            elif self.action == "test":
                self.completed(
                    self.catalog.test_restore(
                        self.operation_id
                    )
                )

            elif self.action == "reconcile":
                self.completed(
                    self.catalog.reconcile(
                        self.operation_id
                    )
                )

            else:
                restore = (
                    self.catalog.restore
                    if self.windows
                    else self.catalog.restore_content
                )

                self.completed(
                    restore(
                        self.operation_id,
                        self.destination,
                    )
                )

        except OperationAuditError as error:
            if (
                error.completed
                and self.operation_id is not None
            ):
                self.completed(
                    error.result,
                    audit=str(error),
                )
            else:
                self.fail(
                    error,
                    completed,
                )

        except Exception as error:
            self.fail(
                error,
                completed,
            )

    def fail(self, error, completed):
        partial = getattr(
            error,
            "partial_path",
            None,
        )
        notes = " | ".join(
            getattr(error, "__notes__", ())
        )

        self.error.emit(
            f"{type(error).__name__}: {error}"
            + (
                f" Arquivo parcial preservado: {partial}"
                if partial else ""
            )
            + (
                f" | {notes}"
                if notes else ""
            )
            + (
                " Backups concluídos antes da interrupção: "
                f"{len(completed)}."
                if self.action == "capture"
                else ""
            )
        )


class BackupCatalogDialog(QDialog):
    def __init__(
        self,
        directory,
        parent=None,
        *,
        records=(),
        analysis_id=None,
    ):
        super().__init__(parent)

        self.setWindowTitle(
            "Backups e recuperação"
        )
        self.setWindowModality(
            Qt.WindowModality.ApplicationModal
        )
        self.resize(1050, 550)

        self.catalog = BackupCatalog(
            directory,
            analysis_id=analysis_id,
        )

        self.worker = None
        self.running = False
        self.restore_failed = False
        self.entries = {}
        self.records = tuple(
            dict(row)
            for row in records
        )

        layout = QVBoxLayout(self)

        notice = QLabel(
            f"Destino dos backups: {self.catalog.directory}\n"
            "O formato Windows confere conteúdo, ADS, segurança, "
            "criação, acesso, modificação e atributos no perfil "
            "suportado. O horário interno de mudança registra "
            "a nova operação de recuperação. Backups antigos "
            "preservam somente conteúdo. Os originais são mantidos."
        )
        notice.setWordWrap(True)
        layout.addWidget(notice)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Estado",
            "Arquivo de origem",
            "Bytes",
            "Operação",
        ])
        self.tree.setColumnWidth(0, 195)
        self.tree.setColumnWidth(1, 430)
        self.tree.itemSelectionChanged.connect(
            self.update_controls
        )
        layout.addWidget(self.tree)

        self.status = QLabel(
            "Consulte os registros ou crie backups "
            "dos arquivos marcados."
        )
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QHBoxLayout()

        self.refresh = QPushButton(
            "Conferir backups"
        )
        self.restore = QPushButton(
            "Restaurar em arquivo novo..."
        )
        self.test = QPushButton(
            "Testar restauração"
        )
        self.reconcile = QPushButton(
            "Conferir interrupções"
        )
        self.capture = QPushButton(
            "Criar backups dos marcados "
            f"({len(self.records)})"
        )
        self.finish = QPushButton(
            "Fechar"
        )

        self.refresh.clicked.connect(
            self.reload
        )
        self.restore.clicked.connect(
            self.restore_selected
        )
        self.test.clicked.connect(
            lambda: self.selected_action("test")
        )
        self.reconcile.clicked.connect(
            lambda: self.selected_action("reconcile")
        )
        self.capture.clicked.connect(
            self.capture_selected
        )
        self.finish.clicked.connect(
            self.close
        )

        for button in (
            self.refresh,
            self.restore,
            self.test,
            self.reconcile,
            self.capture,
            self.finish,
        ):
            buttons.addWidget(button)

        layout.addLayout(buttons)
        self.update_controls()

    def selected_entry(self):
        items = self.tree.selectedItems()

        if not items:
            return None

        return self.entries.get(
            items[0].data(
                0,
                Qt.ItemDataRole.UserRole,
            )
        )

    def update_controls(self):
        entry = self.selected_entry()

        available = (
            not self.running
            and not self.restore_failed
        )
        valid = (
            entry is not None
            and entry.state in (
                "CONTENT_VERIFIED",
                "WINDOWS_CAPTURED",
                "WINDOWS_VERIFIED",
            )
        )
        modern = (
            valid
            and entry.scope == SCOPE
        )

        self.refresh.setEnabled(
            not self.running
        )
        self.finish.setEnabled(
            not self.running
        )
        self.tree.setEnabled(
            not self.running
        )
        self.restore.setEnabled(
            available and valid
        )
        self.test.setEnabled(
            available and modern
        )
        self.reconcile.setEnabled(
            available and modern
        )
        self.capture.setEnabled(
            available and bool(self.records)
        )

    def start_worker(self, worker):
        if self.running:
            return

        if self.worker is not None:
            self.worker.deleteLater()

        self.worker = worker
        self.running = True

        parent = self.parentWidget()

        if (
            parent is not None
            and hasattr(
                parent,
                "_backup_running",
            )
        ):
            parent._backup_running = True
            parent._update_controls()

        worker.progress.connect(
            self.status.setText
        )
        worker.result_ready.connect(
            self.show_result
        )
        worker.error.connect(
            self.show_error
        )
        worker.finished.connect(
            self.finished_work
        )

        self.update_controls()
        worker.start()

    def reload(self):
        if self.running:
            return

        self.entries = {}
        self.tree.clear()

        self.status.setText(
            "Conferindo os backups..."
        )

        self.start_worker(CatalogWorker(
            self.catalog,
            parent=self,
        ))

    def show_result(self, result):
        if "entries" in result:
            states = {
                "CONTENT_VERIFIED": "Somente conteúdo",
                "WINDOWS_CAPTURED": (
                    "Teste de restauração pendente"
                ),
                "WINDOWS_VERIFIED": (
                    "Restauração testada"
                ),
                "INCOMPLETE": "Incompleto",
                "UNAVAILABLE": "Indisponível",
            }

            for entry in result["entries"]:
                self.entries[
                    entry.operation_id
                ] = entry

                item = QTreeWidgetItem(
                    self.tree,
                    [
                        states[entry.state],
                        entry.source_path,
                        (
                            ""
                            if entry.size_bytes is None
                            else str(entry.size_bytes)
                        ),
                        entry.operation_id,
                    ],
                )

                item.setData(
                    0,
                    Qt.ItemDataRole.UserRole,
                    entry.operation_id,
                )

                for column in range(4):
                    item.setToolTip(
                        column,
                        entry.detail,
                    )

            self.status.setText(
                f"{len(self.entries)} registros examinados."
            )
            return

        if "captured" in result:
            message = (
                f"{len(result['captured'])} backups "
                "com restauração testada. "
                "Use Conferir backups."
            )
            self.records = ()

        elif "reconciliation" in result:
            labels = {
                "COMPLETED": "Concluída",
                "CONFLICT": (
                    "Destino substituído; confira manualmente"
                ),
                "MISSING": "Destino não encontrado",
                "INTERRUPTED_PROBE": (
                    "Teste interrompido"
                ),
                "PARTIAL_OR_INACCESSIBLE": (
                    "Parcial ou inacessível; confira manualmente"
                ),
                "MANUAL_REVIEW": (
                    "Revisão manual necessária"
                ),
            }

            message = "\n".join(
                f"{destination}: {labels.get(state, state)}"
                for destination, state
                in result["reconciliation"]
            )

            message = (
                message
                or "Nenhuma restauração anterior registrada."
            )

        elif result.get("action") == "test":
            message = (
                "Restauração de teste conferida. "
                "O arquivo temporário foi descartado."
            )

        else:
            message = (
                "Arquivo restaurado em: "
                f"{result['destination']}."
            )

            if not result.get("windows"):
                message = (
                    "Cópia de conteúdo restaurada em: "
                    f"{result['destination']}. "
                    f"{LIMITATION}"
                )

        warnings = result.get(
            "warnings",
            [],
        )

        if warnings:
            message += (
                " Pendências: "
                + "; ".join(warnings)
            )

        if result.get("audit_pending"):
            message += (
                " AUDITORIA PENDENTE: "
                + result["detail"]
            )

        self.status.setText(message)

        self.restore_failed = bool(
            warnings
            or result.get("audit_pending")
        )

    def show_error(self, message):
        self.restore_failed = True

        self.status.setText(
            "Operação não concluída. "
            "Confira a ocorrência antes de outra ação. "
            + message
        )

    def finished_work(self):
        self.running = False

        parent = self.parentWidget()

        if (
            parent is not None
            and hasattr(
                parent,
                "_backup_running",
            )
        ):
            parent._backup_running = False
            parent._update_controls()

        self.capture.setText(
            "Criar backups dos marcados "
            f"({len(self.records)})"
        )

        self.update_controls()

    def restore_selected(self):
        entry = self.selected_entry()

        if (
            self.running
            or self.restore_failed
            or entry is None
        ):
            return

        if entry.state not in (
            "CONTENT_VERIFIED",
            "WINDOWS_CAPTURED",
            "WINDOWS_VERIFIED",
        ):
            return

        destination, _ = QFileDialog.getSaveFileName(
            self,
            "Restaurar em arquivo novo — sem substituir",
            "copia_recuperada",
        )

        if not destination:
            return

        modern = entry.scope == SCOPE

        detail = (
            "Serão restauradas as permissões do arquivo. "
            "Escolha uma pasta de destino restrita; "
            "as permissões das pastas de origem "
            "não são recriadas."
            if modern
            else LIMITATION
            + " A cópia herdará as permissões do destino; "
            "escolha uma pasta restrita."
        )

        answer = QMessageBox.warning(
            self,
            "Confirmar restauração",
            f"Destino: {destination}\n\n"
            f"{detail}\n"
            "Um arquivo existente não será substituído.",
            (
                QMessageBox.StandardButton.Ok
                | QMessageBox.StandardButton.Cancel
            ),
            QMessageBox.StandardButton.Cancel,
        )

        if answer != QMessageBox.StandardButton.Ok:
            return

        self.start_worker(CatalogWorker(
            self.catalog,
            operation_id=entry.operation_id,
            destination=Path(destination),
            windows=modern,
            parent=self,
        ))

    def selected_action(self, action):
        entry = self.selected_entry()

        if (
            self.running
            or self.restore_failed
            or entry is None
            or entry.scope != SCOPE
        ):
            return

        self.start_worker(CatalogWorker(
            self.catalog,
            operation_id=entry.operation_id,
            action=action,
            windows=True,
            parent=self,
        ))

    def capture_selected(self):
        if (
            self.running
            or self.restore_failed
            or not self.records
        ):
            return

        self.start_worker(CatalogWorker(
            self.catalog,
            action="capture",
            records=self.records,
            windows=True,
            parent=self,
        ))

    def closeEvent(self, event):
        if (
            self.running
            or (
                self.worker is not None
                and self.worker.isRunning()
            )
        ):
            self.status.setText(
                "Aguarde a operação terminar antes de fechar."
            )
            event.ignore()
            return

        super().closeEvent(event)


def update_backup_controls(window):
    if not hasattr(
        window,
        "btn_backup_catalog",
    ):
        return

    available = (
        not window._busy()
        and window.config is not None
    )

    window.btn_backup_catalog.setEnabled(
        available
    )
    window.btn_backup_destination.setEnabled(
        available
    )
    window.btn_backup_complete.setEnabled(
        available
        and not window._historical
        and window.last_report is not None
        and bool(
            window.obter_arquivos_marcados()
        )
    )


def setup_backup_catalog(window):
    window.btn_backup_catalog = QPushButton(
        "Consultar e restaurar backups..."
    )

    window.btn_backup_complete = (
        window.btn_backup
    )
    window.btn_backup_complete.setText(
        "Backup completo dos marcados..."
    )

    window.btn_backup_destination = QPushButton(
        "Destino dos backups..."
    )

    controls = QHBoxLayout()

    for button in (
        window.btn_backup_catalog,
        window.btn_backup_destination,
    ):
        controls.addWidget(button)

    window.centralWidget().layout().insertLayout(
        2,
        controls,
    )

    def open_catalog():
        if (
            not window._busy()
            and window.config is not None
        ):
            BackupCatalogDialog(
                window.config["backup_path"],
                window,
            ).exec()

    def capture():
        if (
            window._busy()
            or window.config is None
            or window._historical
        ):
            return

        try:
            from gui.app import BackupWorker

            records = window._backup_records()

            if not records:
                return

            persistence = (
                window.last_report["persistence"]
            )

            config = validate_config({
                **persistence["config"],
                "backup_path": (
                    window.config["backup_path"]
                ),
            })

            prepared = BackupWorker(
                config,
                records,
                analysis_id=persistence.get(
                    "attempt_id"
                ),
            )

            dialog = BackupCatalogDialog(
                config["backup_path"],
                window,
                records=prepared.records,
                analysis_id=persistence.get(
                    "attempt_id"
                ),
            )

            prepared.deleteLater()
            dialog.exec()

        except Exception as error:
            window.backup_label.setText(
                "Backup completo não iniciado: "
                f"{error}"
            )

    def destination():
        if (
            window._busy()
            or window.config is None
        ):
            return

        path = QFileDialog.getExistingDirectory(
            window,
            "Escolha a pasta de backup "
            "em armazenamento independente",
        )

        if not path:
            return

        try:
            config = validate_config({
                **window.config,
                "backup_path": path,
            })

            save_config(config)
            window.config = config

            window.backup_label.setText(
                "Destino dos próximos backups completos: "
                f"{path}"
            )

            update_backup_controls(window)

        except Exception as error:
            window.backup_label.setText(
                f"Destino não alterado: {error}"
            )

    window.btn_backup_catalog.clicked.connect(
        open_catalog
    )

    window.btn_backup_complete.clicked.disconnect()
    window.btn_backup_complete.clicked.connect(
        capture
    )

    window.btn_backup_destination.clicked.connect(
        destination
    )