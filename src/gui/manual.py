"""Controles gráficos de análise, cancelamento e recuperação."""

import json
import stat
from pathlib import Path

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QPushButton,
    QHBoxLayout,
    QDialog,
    QVBoxLayout,
    QListWidget,
    QListWidgetItem,
    QDialogButtonBox,
)

from core.analysis import run_analysis
from core.cancellation import Cancellation, AnalysisCancelled
from core.run_journal import RunJournal, StateError, _json
from core.run_lock import RunLock
from utils.config_parser import PROJECT_ROOT, validate_config
from utils.logger import AuditError


RUNS_DIRECTORY = PROJECT_ROOT / "data" / "execucoes"


def checkpoint_matches(report):
    try:
        persistence = report["persistence"]
        journal = RunJournal.read(
            persistence["recovery_path"]
        )
        snapshot = journal.data["snapshot"]

        return (
            snapshot["analysis_id"]
            == persistence["attempt_id"]
            and snapshot["started_at"]
            == persistence["started_at"]
            and snapshot["finished_at"]
            == persistence["finished_at"]
            and snapshot["config"]
            == persistence["config"]
            and snapshot["report"]
            == json.loads(_json({
                key: value
                for key, value in report.items()
                if key != "persistence"
            }))
        )

    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
    ):
        return False


class ManualScanWorker(QThread):
    progress = pyqtSignal(str)
    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)
    cancelled = pyqtSignal(str)

    def __init__(
        self,
        config,
        store,
        directory,
        parent=None,
    ):
        super().__init__(parent)
        self.config = validate_config(config)
        self.store = store
        self.directory = Path(directory)
        self.control = Cancellation()

    def run(self):
        journal = None

        try:
            with RunLock():
                self.control.check()

                journal = RunJournal.create(
                    self.directory,
                    profile="interface",
                    database=self.store.database_path,
                )

                def progress(message):
                    self.control.check()
                    journal.update(phase=message)
                    self.progress.emit(message)

                def checkpoint(snapshot):
                    self.control.check()
                    journal.update(
                        state="REPORT_READY",
                        snapshot=snapshot,
                    )

                report = run_analysis(
                    self.config,
                    report_store=self.store,
                    progress=progress,
                    checkpoint=checkpoint,
                    check_cancel=self.control.check,
                    analysis_id=journal.data["run_id"],
                    extra_exclusions=(self.directory,),
                )

                persistence = report["persistence"]
                persistence["recovery_path"] = str(
                    journal.path
                )

                pending = bool(
                    report["pending_files"]
                    or report["scan_pending_errors"]
                )

                state = (
                    "AUDIT_PENDING"
                    if persistence.get("audit_error")
                    else "REPORT_UNSAVED"
                    if not persistence["saved"]
                    else "CONCLUDED_WITH_PENDING"
                    if pending
                    else "CONCLUDED"
                )

                try:
                    journal.update(
                        state=state,
                        persistence=persistence,
                    )

                except StateError as error:
                    persistence["state_error"] = str(error)

                self.result_ready.emit(report)

        except Exception as error:
            message = f"{type(error).__name__}: {error}"

            if journal is not None:
                try:
                    journal = RunJournal.read(
                        journal.path
                    )
                    journal.update(
                        state=(
                            "INTERRUPTED"
                            if isinstance(error, AnalysisCancelled)
                            else "FAILED"
                        ),
                        error=message,
                    )
                    message += (
                        f" Registro preservado: {journal.path}"
                    )

                except Exception as state_error:
                    message += f" | Estado: {state_error}"

            if isinstance(error, AnalysisCancelled):
                self.cancelled.emit(message)
            else:
                self.error.emit(message)


class RecoveryWorker(QThread):
    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, path, store, parent=None):
        super().__init__(parent)
        self.path = Path(path)
        self.store = store

    def run(self):
        try:
            with RunLock():
                journal = RunJournal.read(self.path)
                snapshot = journal.data.get("snapshot")

                if (
                    not isinstance(snapshot, dict)
                    or snapshot.get("analysis_id")
                    != journal.data["run_id"]
                ):
                    raise StateError(
                        "Esta execução não tem relatório completo. "
                        "Analise a pasta novamente."
                    )

                identifier = snapshot["analysis_id"]
                config = validate_config(
                    snapshot["config"]
                )
                audit_error = None

                try:
                    self.store.save_report(
                        snapshot["report"],
                        config,
                        report_id=identifier,
                        started_at=snapshot["started_at"],
                        finished_at=snapshot["finished_at"],
                    )

                except Exception as save_error:
                    existing = self.store.get_report(
                        identifier
                    )

                    if (
                        existing["report"]
                        != snapshot["report"]
                        or existing["config"] != config
                        or existing["started_at"]
                        != snapshot["started_at"]
                        or existing["finished_at"]
                        != snapshot["finished_at"]
                    ):
                        raise StateError(
                            "O identificador pertence "
                            "a outro relatório."
                        ) from save_error

                    if isinstance(save_error, AuditError):
                        audit_error = str(save_error)

                saved = self.store.get_report(
                    identifier
                )

                notice = (
                    audit_error
                    or "Relatório recuperado no histórico."
                )

                try:
                    journal.update(
                        state="RECOVERED",
                        report_id=identifier,
                    )

                except StateError as error:
                    notice += (
                        " Estado da execução pendente: "
                        f"{error}"
                    )

                self.result_ready.emit({
                    "snapshot": saved,
                    "recovery_notice": notice,
                })

        except Exception as error:
            self.error.emit(
                f"Recuperação não concluída: {error}"
            )


class RunListWorker(QThread):
    result_ready = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, directory, parent=None):
        super().__init__(parent)
        self.directory = Path(directory)

    def run(self):
        rows = []

        try:
            try:
                info = self.directory.stat()

            except FileNotFoundError:
                self.result_ready.emit([])
                return

            if not stat.S_ISDIR(info.st_mode):
                raise StateError(
                    "A pasta de execuções não é um diretório."
                )

            for path in self.directory.glob("*.json"):
                try:
                    journal = RunJournal.read(path)
                    snapshot = journal.data.get("snapshot")

                    roots = (
                        snapshot.get(
                            "config", {}
                        ).get("monitored_paths", [])
                        if isinstance(snapshot, dict)
                        else []
                    )

                    rows.append({
                        "path": path,
                        "date": journal.data.get(
                            "created_at", ""
                        ),
                        "roots": (
                            ", ".join(roots)
                            or "Análise sem relatório completo"
                        ),
                        "state": journal.data.get(
                            "state", ""
                        ),
                        "recoverable": isinstance(
                            snapshot, dict
                        ),
                    })

                except StateError:
                    rows.append({
                        "path": path,
                        "date": "",
                        "roots": "Registro ilegível",
                        "state": "",
                        "recoverable": False,
                    })

            rows.sort(
                key=lambda row: row["date"],
                reverse=True,
            )

            self.result_ready.emit(rows)

        except Exception as error:
            self.error.emit(str(error))


class RecoveryDialog(QDialog):
    @staticmethod
    def choose(rows, parent=None):
        dialog = RecoveryDialog(parent)
        dialog.setWindowTitle(
            "Recuperar relatório de análise"
        )
        dialog.resize(850, 360)

        layout = QVBoxLayout(dialog)
        listing = QListWidget()

        states = {
            "RUNNING": "Sem conclusão registrada",
            "REPORT_READY": "Relatório pronto para salvar",
            "REPORT_UNSAVED": "Pendente de gravação",
            "AUDIT_PENDING": "Auditoria pendente",
            "INTERRUPTED": "Interrompida",
            "FAILED": "Falhou",
            "CONCLUDED": "Concluída",
            "CONCLUDED_WITH_PENDING": (
                "Concluída com pendências"
            ),
            "RECOVERED": "Recuperada",
        }

        for row in rows:
            item = QListWidgetItem(
                f"{row['date']} | {row['roots']} | "
                + states.get(
                    row["state"],
                    "Registro indisponível",
                )
            )

            item.setData(
                Qt.ItemDataRole.UserRole,
                row["path"],
            )

            if not row["recoverable"]:
                item.setFlags(
                    item.flags()
                    & ~Qt.ItemFlag.ItemIsEnabled
                )

            listing.addItem(item)

        layout.addWidget(listing)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )

        buttons.button(
            QDialogButtonBox.StandardButton.Ok
        ).setText("Recuperar relatório")

        buttons.button(
            QDialogButtonBox.StandardButton.Cancel
        ).setText("Fechar")

        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        listing.itemSelectionChanged.connect(
            lambda: buttons.button(
                QDialogButtonBox.StandardButton.Ok
            ).setEnabled(
                bool(listing.selectedItems())
            )
        )

        layout.addWidget(buttons)

        buttons.button(
            QDialogButtonBox.StandardButton.Ok
        ).setEnabled(False)

        for index, row in enumerate(rows):
            if row["recoverable"]:
                listing.setCurrentRow(index)
                break

        if (
            dialog.exec()
            == QDialog.DialogCode.Accepted
            and listing.selectedItems()
        ):
            return listing.selectedItems()[0].data(
                Qt.ItemDataRole.UserRole
            )

        return None


class ManualControls:
    def setup_manual_controls(self):
        self.manual_directory = RUNS_DIRECTORY
        self._pending_run_rows = []
        self._run_list_error = None

        self.btn_cancel_scan = QPushButton(
            "Cancelar análise"
        )
        self.btn_cancel_scan.clicked.connect(
            self.cancel_manual_analysis
        )

        self.btn_recover_run = QPushButton(
            "Recuperar relatório..."
        )
        self.btn_recover_run.clicked.connect(
            self.recover_manual_report
        )

        layout = self.centralWidget().layout()
        controls = QHBoxLayout()

        controls.addWidget(self.btn_cancel_scan)
        controls.addWidget(self.btn_recover_run)
        controls.addStretch()

        layout.insertLayout(1, controls)

    def update_manual_controls(self):
        self.btn_cancel_scan.setEnabled(
            self._scan_running
            and isinstance(self.worker, ManualScanWorker)
            and not self.worker.control.requested()
        )

        self.btn_recover_run.setEnabled(
            not self._busy()
        )

    def start_manual_analysis(self):
        if (
            self._busy()
            or self.config is None
            or not self._allow_report_change()
        ):
            return

        paths = [
            self.list_folders.item(i).text()
            for i in range(self.list_folders.count())
        ]

        if not paths:
            self.status_label.setText(
                "Escolha pelo menos uma pasta."
            )
            return

        try:
            config = validate_config({
                **self.config,
                "monitored_paths": paths,
            })

            worker = ManualScanWorker(
                config,
                self.report_store,
                self.manual_directory,
                self,
            )

        except Exception as error:
            self.status_label.setText(
                f"Análise não iniciada: {error}"
            )
            return

        self.config = config
        self._clear_report()

        if self.worker is not None:
            self.worker.deleteLater()

        self.worker = worker
        self._scan_running = True

        worker.progress.connect(
            self.status_label.setText
        )
        worker.result_ready.connect(
            self.apresentar_relatorio
        )
        worker.error.connect(
            self._scan_error
        )
        worker.cancelled.connect(
            self.manual_analysis_cancelled
        )
        worker.finished.connect(
            self._scan_finished
        )

        self.status_label.setText(
            "Preparando análise de todas as subpastas..."
        )
        self._update_controls()
        worker.start()

    def cancel_manual_analysis(self):
        if (
            self._scan_running
            and isinstance(self.worker, ManualScanWorker)
        ):
            self.worker.control.request()

            self.status_label.setText(
                "Cancelamento solicitado. "
                "Aguarde a leitura atual terminar."
            )

            self.update_manual_controls()

    def manual_analysis_cancelled(self, message):
        self.status_label.setText(message)

    def recover_manual_report(self):
        if (
            self._busy()
            or not self._allow_report_change()
        ):
            return

        if self.history_worker is not None:
            self.history_worker.deleteLater()

        worker = RunListWorker(
            self.manual_directory,
            self,
        )

        self.history_worker = worker
        self._history_running = True
        self._pending_run_rows = []
        self._run_list_error = None

        self.status_label.setText(
            "Consultando análises disponíveis "
            "para recuperação..."
        )

        worker.result_ready.connect(
            lambda rows: setattr(
                self,
                "_pending_run_rows",
                rows,
            )
        )
        worker.error.connect(
            lambda message: setattr(
                self,
                "_run_list_error",
                message,
            )
        )
        worker.finished.connect(
            self.choose_manual_recovery
        )

        self._update_controls()
        worker.start()

    def choose_manual_recovery(self):
        self._history_finished()

        if self._run_list_error:
            self.status_label.setText(
                "Não foi possível consultar as análises: "
                + self._run_list_error
            )
            return

        if not self._pending_run_rows:
            self.status_label.setText(
                "Nenhuma análise disponível para recuperação."
            )
            return

        path = RecoveryDialog.choose(
            self._pending_run_rows,
            self,
        )

        if path is not None:
            self.tabs.setCurrentWidget(
                self.history_tree.parentWidget()
            )

            self._start_history_worker(
                RecoveryWorker(
                    path,
                    self.report_store,
                    self,
                )
            )

        else:
            self.status_label.setText(
                "Recuperação cancelada."
            )