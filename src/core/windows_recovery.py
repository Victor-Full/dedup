"""Backup Windows, prova de restauração e reconciliação sem sobrescrita."""

import ctypes as C
import hashlib
import io
import os
import shutil
import tempfile
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from core.action_manager import (
    BackupError,
    OPERATION_NAME,
    VERIFIED_NAME,
    _now,
)
from core.windows_backup import (
    WindowsBackup,
    ARCHIVE_NAME,
    SCOPE,
    HEADER,
    inspect_archive,
    ALLOWED_ATTRIBUTES,
)
from core.windows_native import (
    NativeRecovery,
    SecurityAttributes,
)
from core.run_journal import RunJournal
from core.run_lock import exclusive
from utils.audit import audited_operation


@dataclass(frozen=True)
class RestoreResult:
    destination: Path
    restoration_id: str
    warnings: tuple = ()


def positions(stream):
    result = {}

    stream.seek(0, os.SEEK_END)
    total = stream.tell()
    stream.seek(0)

    while stream.tell() < total:
        header = stream.read(HEADER.size)

        if len(header) != HEADER.size:
            raise BackupError(
                "Cabeçalho truncado."
            )

        kind, attributes, size, name_size = (
            HEADER.unpack(header)
        )

        name_bytes = stream.read(name_size)

        if len(name_bytes) != name_size:
            raise BackupError(
                "Nome truncado."
            )

        name = name_bytes.decode("utf-16-le")

        result[(kind, name)] = (
            stream.tell(),
            size,
            header + name_bytes,
        )

        stream.seek(size, os.SEEK_CUR)

    return result


class RecoveryVault(WindowsBackup):
    native_class = NativeRecovery
    reserve_bytes = 1024 ** 3

    def _dump(
        self,
        api,
        source,
        destination=None,
    ):
        if destination is None:
            return super()._dump(api, source)

        directory = self.backup_dir
        reserve = self.reserve_bytes

        class GuardedWriter:
            remaining = 0

            def write(inner, data):
                if inner.remaining <= 0:
                    if (
                        shutil.disk_usage(directory).free
                        < reserve + 64 * 1024 * 1024
                    ):
                        raise BackupError(
                            "Reserva de espaço do backup insuficiente."
                        )

                    inner.remaining = 64 * 1024 * 1024

                count = destination.write(data)

                if count is not None:
                    inner.remaining -= count

                return count

        return super()._dump(
            api,
            source,
            GuardedWriter(),
        )

    def native(self):
        return self.native_class()

    def _new_operation_directory(self, path):
        native = self.native()
        api = self._api()

        with self._parents(api, path.parent):
            with native.private_descriptor() as security:
                attributes = SecurityAttributes(
                    C.sizeof(SecurityAttributes),
                    security,
                    False,
                )

                native.check(
                    native.k.CreateDirectoryW(
                        str(path),
                        C.byref(attributes),
                    )
                )

    def _write_manifest(self, path, data):
        if (
            path.name == OPERATION_NAME
            and data.get("metadata_scope") == SCOPE
        ):
            estimate = data.get(
                "source_metadata",
                {},
            ).get("size_bytes", 0)

            if (
                shutil.disk_usage(path.parent).free
                < estimate + self.reserve_bytes
            ):
                raise BackupError(
                    "Espaço insuficiente para iniciar a captura."
                )

            native = self.native()
            api = self._api()

            handle = api.CreateFileW(
                str(path.parent),
                0xE0081,
                3,
                None,
                3,
                0x02200000,
                None,
            )

            if handle == C.c_void_p(-1).value:
                raise C.WinError(
                    C.get_last_error()
                )

            try:
                native.secure(
                    handle,
                    directory=True,
                )
            finally:
                api.CloseHandle(handle)

        return super()._write_manifest(
            path,
            data,
        )

    def _archive_path(self, value):
        path = self._path(value)
        parts = path.relative_to(
            self.backup_dir
        ).parts

        if (
            len(parts) != 2
            or parts[1] != ARCHIVE_NAME
            or str(UUID(parts[0])) != parts[0]
        ):
            raise BackupError(
                "Arquivo fora da estrutura do backup Windows."
            )

        return path

    @contextmanager
    def verified_archive(self, value):
        path = self._archive_path(value)
        api = self._api()

        with ExitStack() as stack:
            stack.enter_context(
                self._parents(api, path.parent)
            )

            op_stream = stack.enter_context(
                self._protected(
                    path.parent / OPERATION_NAME
                )
            )
            verified_stream = stack.enter_context(
                self._protected(
                    path.parent / VERIFIED_NAME
                )
            )
            archive = stack.enter_context(
                self._protected(path)
            )

            operation, checksum = (
                self._read_manifest(op_stream)
            )
            receipt, _ = self._read_manifest(
                verified_stream
            )

            if (
                type(
                    operation.get("format_version")
                ) is not int
                or operation["format_version"] != 1
                or operation.get("operation_id")
                != path.parent.name
                or operation.get("state") != "CREATING"
                or operation.get("data_file")
                != ARCHIVE_NAME
                or operation.get("metadata_scope")
                != SCOPE
                or operation.get("deletion_authorized")
                is not False
                or receipt.get("state")
                != "WINDOWS_STREAMS_VERIFIED"
                or receipt.get("operation_sha256")
                != checksum
                or any(
                    receipt.get(key) != value
                    for key, value in operation.items()
                    if key != "state"
                )
            ):
                raise BackupError(
                    "Manifestos Windows inconsistentes."
                )

            size = operation.get(
                "source_metadata",
                {},
            ).get("size_bytes")

            basic = operation.get("native_basic")

            keys = {
                "creation_time",
                "access_time",
                "write_time",
                "change_time",
                "attributes",
            }

            if (
                type(size) is not int
                or size < 0
                or not isinstance(basic, dict)
                or set(basic) != keys
                or any(
                    type(basic[key]) is not int
                    or basic[key] <= 0
                    for key in keys
                )
                or basic["attributes"]
                & ~ALLOWED_ATTRIBUTES
            ):
                raise BackupError(
                    "Metadados Windows inválidos ou fora do perfil."
                )

            index = inspect_archive(
                archive,
                size,
            )

            if any(
                receipt.get(key) != data
                for key, data in index.items()
            ):
                raise BackupError(
                    "Backup corrompido ou diferente do manifesto."
                )

            main = next(
                (
                    row
                    for row in index["streams"]
                    if row["id"] == 1
                ),
                None,
            )

            digest = (
                main["sha256"]
                if main
                else hashlib.sha256(b"").hexdigest()
            )

            if receipt.get("main_sha256") != digest:
                raise BackupError(
                    "Hash principal inconsistente."
                )

            self._security_packet(
                archive,
                self.native(),
            )

            yield archive, receipt

    def verify_windows(self, value):
        with self.verified_archive(value) as (
            _,
            receipt,
        ):
            return dict(receipt)

    @staticmethod
    def _security_packet(archive, native):
        offset, size, header = (
            positions(archive)[(3, "")]
        )

        archive.seek(offset)
        data = archive.read(size)

        if len(data) != size:
            raise BackupError(
                "Descritor de segurança truncado."
            )

        return (
            header + data,
            native.security_text(data),
        )

    def _compare(
        self,
        archive,
        target,
        receipt,
        native,
        *,
        security,
    ):
        directory = (
            self.backup_dir
            / receipt["operation_id"]
        )

        with tempfile.TemporaryFile(
            dir=directory
        ) as observed:
            self._dump(
                self._api(),
                target,
                observed,
            )

            index = inspect_archive(
                observed,
                receipt["source_metadata"]["size_bytes"],
            )

            left = positions(archive)
            right = positions(observed)

            # O Windows pode omitir o fluxo principal vazio.
            left = {
                key: value
                for key, value in left.items()
                if (
                    key[0] != 3
                    and not (
                        key[0] == 1
                        and value[1] == 0
                    )
                )
            }
            right = {
                key: value
                for key, value in right.items()
                if (
                    key[0] != 3
                    and not (
                        key[0] == 1
                        and value[1] == 0
                    )
                )
            }

            if set(left) != set(right):
                raise BackupError(
                    "Fluxos restaurados diferentes do backup."
                )

            for key, (offset, size, _) in left.items():
                other_offset, other_size, _ = right[key]

                if size != other_size:
                    raise BackupError(
                        "Tamanho de fluxo restaurado divergente."
                    )

                archive.seek(offset)
                observed.seek(other_offset)

                remaining = size

                while remaining:
                    count = min(
                        65536,
                        remaining,
                    )
                    a = archive.read(count)
                    b = observed.read(count)

                    if (
                        len(a) != count
                        or len(b) != count
                        or a != b
                    ):
                        raise BackupError(
                            "Bytes restaurados diferentes do backup."
                        )

                    remaining -= count

            if security:
                expected = self._security_packet(
                    archive,
                    native,
                )[1]

                actual = self._security_packet(
                    observed,
                    native,
                )[1]

                if expected != actual:
                    raise BackupError(
                        "Permissões/proprietário/SACL "
                        "restaurados divergem."
                    )

            return index

    @contextmanager
    def _target(
        self,
        api,
        native,
        path,
        *,
        probe=False,
    ):
        import msvcrt

        descriptor = None
        stream = None
        handle = None
        succeeded = False
        created_new = False
        primary_error = None

        with self._parents(api, path.parent):
            try:
                with native.private_descriptor(
                    inherit=False
                ) as security:
                    attributes = SecurityAttributes(
                        C.sizeof(SecurityAttributes),
                        security,
                        False,
                    )

                    flags = (
                        0x0A200000
                        | (
                            0x04000000
                            if probe
                            else 0
                        )
                    )

                    handle = api.CreateFileW(
                        str(path),
                        native.target_access,
                        0,
                        C.byref(attributes),
                        1,
                        flags,
                        None,
                    )

                if handle == C.c_void_p(-1).value:
                    handle = None
                    raise C.WinError(
                        C.get_last_error()
                    )

                created_new = True

                descriptor = msvcrt.open_osfhandle(
                    handle,
                    (
                        os.O_RDWR
                        | os.O_BINARY
                        | os.O_NOINHERIT
                    ),
                )
                handle = None

                stream = os.fdopen(
                    descriptor,
                    "r+b",
                    buffering=0,
                )
                descriptor = None

                self._plain(
                    os.fstat(stream.fileno())
                )

                native.secure(
                    msvcrt.get_osfhandle(
                        stream.fileno()
                    )
                )

                yield stream
                succeeded = True

            except Exception as error:
                primary_error = BackupError(
                    str(error),
                    partial_path=(
                        path
                        if created_new
                        else None
                    ),
                )
                raise primary_error from error

            finally:
                if stream is not None:
                    raw = msvcrt.get_osfhandle(
                        stream.fileno()
                    )

                    try:
                        try:
                            if not succeeded or probe:
                                native.secure(raw)

                            if probe:
                                basic = self._basic(
                                    api,
                                    raw,
                                )
                                basic["attributes"] = 0x80

                                native.set_basic(
                                    raw,
                                    basic,
                                )

                        except Exception as cleanup_error:
                            if primary_error is not None:
                                primary_error.add_note(
                                    "Proteção do parcial: "
                                    f"{cleanup_error}"
                                )
                            else:
                                raise BackupError(
                                    "Não foi possível finalizar "
                                    "a proteção: "
                                    f"{cleanup_error}",
                                    partial_path=path,
                                ) from cleanup_error

                    finally:
                        stream.close()

                if descriptor is not None:
                    os.close(descriptor)

                if handle is not None:
                    api.CloseHandle(handle)

    @staticmethod
    def _basic_equal(a, b):
        return all(
            a[key] == b[key]
            for key in (
                "creation_time",
                "access_time",
                "write_time",
                "attributes",
            )
        )

    def _proof(self, path, receipt, journal):
        proof = {
            "format_version": 1,
            "state": "ROUNDTRIP_VERIFIED",
            "operation_id": receipt["operation_id"],
            "archive_sha256": receipt["archive_sha256"],
            "restoration_id": journal.data["run_id"],
            "target_identity": journal.data["target_identity"],
            "verified_at": _now(),
            "deletion_authorized": False,
        }

        proof_path = (
            path.parent
            / f"restore-proof-{journal.data['run_id']}.json"
        )

        try:
            with self._protected(
                proof_path
            ) as stream:
                existing, _ = (
                    self._read_manifest(stream)
                )

        except FileNotFoundError:
            self._write_manifest(
                proof_path,
                proof,
            )

        else:
            if any(
                existing.get(key) != value
                for key, value in proof.items()
                if key != "verified_at"
            ):
                raise BackupError(
                    "Prova existente pertence a outra restauração."
                )

    def _restore_core(
        self,
        backup_path,
        destination,
        *,
        probe=False,
    ):
        import msvcrt

        path = self._archive_path(
            backup_path
        )
        destination = self._path(
            destination
        )

        if (
            destination.is_relative_to(
                self.backup_dir
            )
            and not probe
        ):
            raise BackupError(
                "A restauração deve ficar fora da área de backup."
            )

        native = self.native()
        api = self._api()
        journal = None
        created = False
        completed = False

        try:
            with self.verified_archive(path) as (
                archive,
                receipt,
            ):
                required = receipt["archive_size_bytes"]

                if (
                    shutil.disk_usage(path.parent).free
                    < 2 * required + self.reserve_bytes
                ):
                    raise BackupError(
                        "Espaço insuficiente para a prova de restauração."
                    )

                if (
                    shutil.disk_usage(destination.parent).free
                    < required + self.reserve_bytes
                ):
                    raise BackupError(
                        "Espaço insuficiente no destino da restauração."
                    )

                journal = RunJournal.create(
                    path.parent / "restores",
                    profile="windows_restore",
                    database="",
                )

                journal.update(
                    state="PREPARING",
                    destination=str(destination),
                    probe=probe,
                    operation_id=receipt["operation_id"],
                    archive_sha256=receipt["archive_sha256"],
                )

                packet, _ = self._security_packet(
                    archive,
                    native,
                )

                with self._target(
                    api,
                    native,
                    destination,
                    probe=probe,
                ) as target:
                    created = True

                    identity = list(
                        self._signature(
                            os.fstat(target.fileno())
                        )[:2]
                    )

                    journal.update(
                        state="WRITING",
                        target_identity=identity,
                    )

                    raw = msvcrt.get_osfhandle(
                        target.fileno()
                    )

                    # Só aplica a segurança original depois
                    # de conferir os dados restaurados.
                    native.write_archive(
                        raw,
                        archive,
                        security=False,
                    )

                    native.check(
                        native.k.FlushFileBuffers(raw)
                    )

                    self._compare(
                        archive,
                        target,
                        receipt,
                        native,
                        security=False,
                    )

                    journal.update(
                        state="DATA_VERIFIED"
                    )

                    native.write_archive(
                        raw,
                        io.BytesIO(packet),
                        security=True,
                    )

                    self._compare(
                        archive,
                        target,
                        receipt,
                        native,
                        security=True,
                    )

                    native.set_basic(
                        raw,
                        receipt["native_basic"],
                    )

                    native.check(
                        native.k.FlushFileBuffers(raw)
                    )

                    if not self._basic_equal(
                        self._basic(api, raw),
                        receipt["native_basic"],
                    ):
                        raise BackupError(
                            "Datas/atributos restaurados divergem."
                        )

                    journal.update(
                        state="METADATA_VERIFIED"
                    )

                completed = True

            warnings = []

            try:
                self._proof(
                    path,
                    receipt,
                    journal,
                )
            except Exception as error:
                warnings.append(
                    f"Prova não registrada: {error}"
                )

            try:
                journal.update(
                    state="COMPLETED",
                    warnings=warnings,
                )
            except Exception as error:
                warnings.append(
                    f"Estado final não registrado: {error}"
                )

            return RestoreResult(
                destination,
                journal.data["run_id"],
                tuple(warnings),
            )

        except Exception as error:
            if journal is not None and not completed:
                try:
                    journal = RunJournal.read(
                        journal.path
                    )
                    journal.update(
                        state="FAILED",
                        error=str(error),
                    )

                except Exception as journal_error:
                    error.add_note(
                        "Estado de restauração: "
                        f"{journal_error}"
                    )

            raise BackupError(
                f"Restauração não concluída: {error}",
                operation_dir=path.parent,
                partial_path=(
                    destination
                    if (
                        created
                        or getattr(
                            error,
                            "partial_path",
                            None,
                        )
                    ) and not probe
                    else None
                ),
            ) from error

    @exclusive
    @audited_operation("RESTORE_WINDOWS")
    def restore_windows(
        self,
        backup_path,
        destination,
    ):
        with self.native().privileges():
            return self._restore_core(
                backup_path,
                destination,
            )

    @exclusive
    def backup_complete(
        self,
        file_path,
        *,
        expected_sha256=None,
        expected_signature=None,
    ):
        with self.native().privileges():
            path = super().backup_windows(
                file_path,
                expected_sha256=expected_sha256,
                expected_signature=expected_signature,
            )

            try:
                result = self._test_restore(path)

            except Exception as error:
                error.add_note(
                    f"Captura preservada em: {path}"
                )
                raise

            if result.warnings:
                raise BackupError(
                    "Captura preservada, mas a prova "
                    "de restauração tem pendências: "
                    + "; ".join(result.warnings),
                    operation_dir=path.parent,
                    partial_path=path,
                )

            return path

    @audited_operation("TEST_RESTORE_WINDOWS")
    def _test_restore(self, backup_path):
        path = self._archive_path(
            backup_path
        )

        return self._restore_core(
            path,
            path.parent / f"probe-{uuid4()}.tmp",
            probe=True,
        )

    @exclusive
    def test_restore(self, backup_path):
        with self.native().privileges():
            return self._test_restore(
                backup_path
            )

    def has_proof(
        self,
        backup_path,
        receipt=None,
        *,
        restoration_id=None,
    ):
        path = self._archive_path(
            backup_path
        )

        receipt = (
            receipt
            or self.verify_windows(path)
        )

        for candidate in path.parent.glob(
            "restore-proof-*.json"
        ):
            try:
                with self._protected(
                    candidate
                ) as stream:
                    proof, _ = self._read_manifest(
                        stream
                    )

                identifier = str(
                    UUID(
                        proof["restoration_id"]
                    )
                )

                if (
                    candidate.name
                    == f"restore-proof-{identifier}.json"
                    and (
                        restoration_id is None
                        or restoration_id == identifier
                    )
                    and type(
                        proof.get("format_version")
                    ) is int
                    and proof["format_version"] == 1
                    and proof.get("state")
                    == "ROUNDTRIP_VERIFIED"
                    and proof.get("operation_id")
                    == receipt["operation_id"]
                    and proof.get("archive_sha256")
                    == receipt["archive_sha256"]
                    and proof.get("deletion_authorized")
                    is False
                ):
                    return True

            except (
                OSError,
                BackupError,
                ValueError,
                KeyError,
                TypeError,
            ):
                continue

        return False

    @exclusive
    @audited_operation("RECONCILE_WINDOWS")
    def reconcile(self, backup_path):
        path = self._archive_path(
            backup_path
        )
        rows = []

        with self.native().privileges():
            with self.verified_archive(path) as (
                archive,
                receipt,
            ):
                for state_path in sorted(
                    (
                        path.parent / "restores"
                    ).glob("*.json")
                ):
                    journal = RunJournal.read(
                        state_path
                    )
                    data = journal.data

                    if (
                        data.get("operation_id")
                        != receipt["operation_id"]
                        or data.get("archive_sha256")
                        != receipt["archive_sha256"]
                    ):
                        raise BackupError(
                            "Estado de restauração "
                            "pertence a outro backup."
                        )

                    if (
                        data.get("state") == "COMPLETED"
                        and self.has_proof(
                            path,
                            receipt,
                            restoration_id=data["run_id"],
                        )
                    ):
                        rows.append((
                            data["run_id"],
                            "COMPLETED",
                        ))
                        continue

                    target = self._path(
                        data["destination"]
                    )
                    status = "MANUAL_REVIEW"

                    if data.get("probe") is True:
                        status = "INTERRUPTED_PROBE"

                    elif target.is_relative_to(
                        self.backup_dir
                    ):
                        raise BackupError(
                            "Destino inválido no estado."
                        )

                    else:
                        try:
                            api = self._api()

                            with self._source(
                                api,
                                target,
                            ) as stream:
                                identity = list(
                                    self._signature(
                                        os.fstat(
                                            stream.fileno()
                                        )
                                    )[:2]
                                )

                                if (
                                    identity
                                    != data.get(
                                        "target_identity"
                                    )
                                ):
                                    status = "CONFLICT"

                                else:
                                    basic = self._basic(
                                        api,
                                        __import__(
                                            "msvcrt"
                                        ).get_osfhandle(
                                            stream.fileno()
                                        ),
                                    )

                                    self._compare(
                                        archive,
                                        stream,
                                        receipt,
                                        self.native(),
                                        security=True,
                                    )

                                    if not self._basic_equal(
                                        basic,
                                        receipt["native_basic"],
                                    ):
                                        raise BackupError(
                                            "Metadados ainda "
                                            "não correspondem."
                                        )

                                    self._proof(
                                        path,
                                        receipt,
                                        journal,
                                    )
                                    status = "COMPLETED"

                        except FileNotFoundError:
                            status = "MISSING"

                        except (
                            OSError,
                            BackupError,
                        ) as error:
                            status = (
                                "PARTIAL_OR_INACCESSIBLE"
                            )
                            journal.update(
                                last_error=str(error)
                            )

                    journal.update(
                        state=status,
                        warnings=(
                            []
                            if status == "COMPLETED"
                            else data.get(
                                "warnings",
                                [],
                            )
                        ),
                    )

                    rows.append((
                        data["run_id"],
                        status,
                    ))

        return rows