"""Catálogo compatível com backups de conteúdo e backups Windows."""

import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from core.action_manager import (
    ActionManager,
    BackupError,
    DATA_NAME,
    OPERATION_NAME,
    VERIFIED_NAME,
)
from core.windows_backup import (
    ARCHIVE_NAME,
    SCOPE,
)
from core.windows_recovery import RecoveryVault
from core.run_lock import exclusive
from core.run_journal import RunJournal


LIMITATION = (
    "Somente conteúdo principal. Permissões, proprietário, ADS e "
    "metadados Windows completos não estão incluídos."
)


@dataclass(frozen=True)
class BackupEntry:
    operation_id: str
    source_path: str
    state: str
    size_bytes: int | None
    detail: str
    scope: str = "MAIN_DATA_STREAM_ONLY"


class BackupCatalog:
    def __init__(
        self,
        backup_dir,
        *,
        analysis_id=None,
    ):
        self.manager = ActionManager(
            backup_dir,
            analysis_id=analysis_id,
        )
        self.windows = RecoveryVault(
            backup_dir,
            analysis_id=analysis_id,
        )
        self.directory = self.manager.backup_dir

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str):
            raise BackupError(
                "Identificador de backup inválido."
            )

        try:
            valid = str(UUID(value)) == value
        except ValueError:
            valid = False

        if not valid:
            raise BackupError(
                "Identificador de backup inválido."
            )

        return value

    def _path(
        self,
        identifier,
        name=DATA_NAME,
    ):
        return (
            self.directory
            / self._identifier(identifier)
            / name
        )

    @exclusive
    def list_entries(
        self,
        *,
        progress=lambda text: None,
        check=lambda: None,
    ):
        try:
            info = self.directory.stat(
                follow_symlinks=False
            )
        except FileNotFoundError:
            return []

        self.manager._plain(
            info,
            directory=True,
        )
        self.manager._directory(
            self.directory
        )

        with os.scandir(
            self.directory
        ) as listing:
            names = sorted(
                entry.name
                for entry in listing
            )

        rows = []

        for name in names:
            check()
            progress(
                f"Conferindo backup: {name}"
            )

            source = ""
            size = None
            scope = "MAIN_DATA_STREAM_ONLY"

            try:
                self._identifier(name)

                folder = self.directory / name
                self.manager._directory(folder)

                with self.manager._protected(
                    folder / OPERATION_NAME
                ) as stream:
                    operation, _ = (
                        self.manager._read_manifest(
                            stream
                        )
                    )

                source = operation.get(
                    "source_path",
                    "",
                )

                if not isinstance(source, str):
                    source = ""

                size = operation.get(
                    "source_metadata",
                    {},
                ).get("size_bytes")

                if type(size) is not int or size < 0:
                    size = None

                scope = operation.get(
                    "metadata_scope",
                    "",
                )

                try:
                    (folder / VERIFIED_NAME).stat(
                        follow_symlinks=False
                    )

                except FileNotFoundError:
                    rows.append(BackupEntry(
                        name,
                        source,
                        "INCOMPLETE",
                        size,
                        "Captura interrompida. Artefatos "
                        "preservados; refaça a partir da origem.",
                        scope,
                    ))
                    continue

                if scope == SCOPE:
                    path = self._path(
                        name,
                        ARCHIVE_NAME,
                    )
                    receipt = (
                        self.windows.verify_windows(path)
                    )
                    proven = self.windows.has_proof(
                        path,
                        receipt,
                    )

                    state = (
                        "WINDOWS_VERIFIED"
                        if proven
                        else "WINDOWS_CAPTURED"
                    )

                    detail = (
                        "Conteúdo, ADS, segurança, datas "
                        "e atributos conferidos em "
                        "restauração de teste."
                        if proven
                        else "Captura íntegra; prova de "
                        "restauração ainda pendente."
                    )

                elif scope == "MAIN_DATA_STREAM_ONLY":
                    self.manager.verify_backup(
                        self._path(name)
                    )
                    state = "CONTENT_VERIFIED"
                    detail = LIMITATION

                else:
                    raise BackupError(
                        "Formato de backup não suportado."
                    )

                rows.append(BackupEntry(
                    name,
                    source,
                    state,
                    size,
                    detail,
                    scope,
                ))

            except (
                OSError,
                BackupError,
                ValueError,
                TypeError,
                AttributeError,
                KeyError,
                RecursionError,
            ) as error:
                rows.append(BackupEntry(
                    name,
                    source,
                    "UNAVAILABLE",
                    size,
                    f"{type(error).__name__}: {error}",
                    scope,
                ))

        return rows

    def restore_content(
        self,
        operation_id,
        destination,
    ):
        return self.manager.restore_backup(
            self._path(operation_id),
            Path(destination),
        )

    def restore(
        self,
        operation_id,
        destination,
    ):
        path = self._path(operation_id)

        with self.manager._protected(
            path.parent / OPERATION_NAME
        ) as stream:
            operation, _ = (
                self.manager._read_manifest(stream)
            )

        if operation.get("metadata_scope") == SCOPE:
            return self.windows.restore_windows(
                self._path(
                    operation_id,
                    ARCHIVE_NAME,
                ),
                destination,
            )

        if (
            operation.get("metadata_scope")
            != "MAIN_DATA_STREAM_ONLY"
        ):
            raise BackupError(
                "Formato não suportado."
            )

        return self.restore_content(
            operation_id,
            destination,
        )

    def test_restore(self, operation_id):
        return self.windows.test_restore(
            self._path(
                operation_id,
                ARCHIVE_NAME,
            )
        )

    def reconcile(self, operation_id):
        path = self._path(
            operation_id,
            ARCHIVE_NAME,
        )
        rows = self.windows.reconcile(path)
        result = []

        for identifier, state in rows:
            journal = RunJournal.read(
                path.parent
                / "restores"
                / f"{identifier}.json"
            )

            destination = (
                "Teste temporário"
                if journal.data.get("probe")
                else journal.data.get(
                    "destination",
                    "Destino não informado",
                )
            )

            result.append((
                f"{journal.data['created_at']} | {destination}",
                state,
            ))

        return result