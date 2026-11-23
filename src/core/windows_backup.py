"""Captura nativa Windows.

Ainda não autoriza restauração ou exclusão.
"""

import ctypes
import hashlib
import os
import struct
from contextlib import contextmanager, ExitStack
from ctypes import wintypes
from pathlib import Path
from uuid import uuid4

from core.action_manager import (
    ActionManager,
    BackupError,
    OPERATION_NAME,
    VERIFIED_NAME,
    _now,
    _digest,
)
from core.run_lock import exclusive
from utils.audit import audited_operation


ARCHIVE_NAME = "windows.bin"
SCOPE = "WINDOWS_STREAMS_V1"

HEADER = struct.Struct("<IIQI")
BLOCK = 65536

MAX_STREAMS = 1024
MAX_NAME_BYTES = 65536
MAX_ARCHIVE_BYTES = 1024 ** 4

# Perfil conservador.
# Os demais atributos exigem implementação própria.
ALLOWED_ATTRIBUTES = (
    0x01
    | 0x02
    | 0x04
    | 0x20
    | 0x80
    | 0x100
    | 0x2000
)


def inspect_archive(stream, expected_size):
    """Valida enquadramento e hashes.

    Não interpreta nem aplica permissões.
    """
    if (
        type(expected_size) is not int
        or expected_size < 0
    ):
        raise BackupError(
            "Tamanho original inválido."
        )

    stream.seek(0, os.SEEK_END)
    total = stream.tell()

    if total <= 0 or total > MAX_ARCHIVE_BYTES:
        raise BackupError(
            "Tamanho do arquivo de backup fora do limite."
        )

    stream.seek(0)

    whole = hashlib.sha256()
    records = []
    seen = set()

    def exact(count):
        data = stream.read(count)

        if len(data) != count:
            raise BackupError(
                "Backup truncado."
            )

        whole.update(data)
        return data

    while stream.tell() < total:
        if (
            len(records) >= MAX_STREAMS
            or total - stream.tell() < HEADER.size
        ):
            raise BackupError(
                "Quantidade de fluxos ou cabeçalho inválido."
            )

        kind, attributes, size, name_size = (
            HEADER.unpack(exact(HEADER.size))
        )

        if kind not in (1, 2, 3, 4):
            raise BackupError(
                "Tipo de fluxo ainda não suportado: "
                f"{kind}."
            )

        allowed = 2 if kind == 3 else 0

        if attributes & ~allowed:
            raise BackupError(
                "Atributos do fluxo ainda não suportados."
            )

        if (
            name_size > MAX_NAME_BYTES
            or name_size % 2
        ):
            raise BackupError(
                "Comprimento do nome de fluxo inválido."
            )

        if kind != 4 and name_size:
            raise BackupError(
                "Nome inesperado em fluxo sem nome."
            )

        if name_size + size > total - stream.tell():
            raise BackupError(
                "Fluxo maior que o backup disponível."
            )

        try:
            name = exact(name_size).decode(
                "utf-16-le"
            )

        except UnicodeDecodeError as error:
            raise BackupError(
                "Nome de fluxo não é UTF-16 válido."
            ) from error

        if kind == 4:
            if (
                not name.startswith(":")
                or not name.endswith(":$DATA")
            ):
                raise BackupError(
                    "Nome ADS fora do formato suportado."
                )

            short = name[1:-6]

            if (
                not short
                or short in (".", "..")
                or any(
                    c in ':\\/' or ord(c) < 32
                    for c in short
                )
                or short.endswith((" ", "."))
            ):
                raise BackupError(
                    "Nome ADS ambíguo ou inválido."
                )

        key = (kind, name.casefold())

        if key in seen:
            raise BackupError(
                "Fluxo repetido ou nome ADS conflitante."
            )

        seen.add(key)

        if kind == 3 and (
            size == 0
            or size > 1024 * 1024
        ):
            raise BackupError(
                "Descritor de segurança vazio "
                "ou muito grande."
            )

        digest = hashlib.sha256()
        remaining = size

        while remaining:
            block = exact(
                min(BLOCK, remaining)
            )
            digest.update(block)
            remaining -= len(block)

        records.append({
            "id": kind,
            "attributes": attributes,
            "name": name,
            "size_bytes": size,
            "sha256": digest.hexdigest(),
        })

    if (3, "") not in seen:
        raise BackupError(
            "O backup não contém descritor de segurança."
        )

    data = [
        item
        for item in records
        if item["id"] == 1
    ]

    if (
        not data and expected_size != 0
    ) or (
        data
        and data[0]["size_bytes"] != expected_size
    ):
        raise BackupError(
            "Conteúdo principal incompatível com a origem."
        )

    stream.seek(0)

    return {
        "archive_size_bytes": total,
        "archive_sha256": whole.hexdigest(),
        "streams": sorted(
            records,
            key=lambda row: (
                row["id"],
                row["name"],
            ),
        ),
    }


class BasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", wintypes.DWORD),
    ]


class WindowsBackup(ActionManager):
    def _new_operation_directory(self, path):
        path.mkdir(exist_ok=False)

    def _api(self):
        if os.name != "nt":
            raise BackupError(
                "Esta captura exige Windows."
            )

        api = ctypes.WinDLL(
            "kernel32",
            use_last_error=True,
        )

        api.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        api.CreateFileW.restype = wintypes.HANDLE

        api.CloseHandle.argtypes = (
            wintypes.HANDLE,
        )
        api.CloseHandle.restype = wintypes.BOOL

        api.GetFileInformationByHandleEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        api.GetFileInformationByHandleEx.restype = (
            wintypes.BOOL
        )

        api.BackupRead.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
            wintypes.BOOL,
            ctypes.POINTER(ctypes.c_void_p),
        )
        api.BackupRead.restype = wintypes.BOOL

        return api

    def _basic(self, api, handle):
        value = BasicInfo()

        if not api.GetFileInformationByHandleEx(
            handle,
            0,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise ctypes.WinError(
                ctypes.get_last_error()
            )

        return {
            "creation_time": value.CreationTime,
            "access_time": value.LastAccessTime,
            "write_time": value.LastWriteTime,
            "change_time": value.ChangeTime,
            "attributes": value.FileAttributes,
        }

    @contextmanager
    def _parents(self, api, directory):
        # Mantém ancestrais abertos sem compartilhar
        # exclusão, recusando renomeação/substituição.
        with ExitStack() as stack:
            for path in reversed((
                directory,
                *directory.parents,
            )):
                # FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES.
                # Somente FILE_READ_ATTRIBUTES não bastou
                # para bloquear renomeação no teste real.
                handle = api.CreateFileW(
                    str(path),
                    0x81,
                    3,
                    None,
                    3,
                    0x02200000,
                    None,
                )

                if handle == ctypes.c_void_p(-1).value:
                    raise ctypes.WinError(
                        ctypes.get_last_error()
                    )

                stack.callback(
                    api.CloseHandle,
                    handle,
                )

                attrs = self._basic(
                    api,
                    handle,
                )["attributes"]

                if (
                    not attrs & 0x10
                    or attrs & 0x400
                ):
                    raise BackupError(
                        "Ancestral inválido ou reparse point."
                    )

            yield

    @contextmanager
    def _source(self, api, path):
        import msvcrt

        with self._parents(api, path.parent):
            before = self._file_info(path)

            # GENERIC_READ | READ_CONTROL |
            # ACCESS_SYSTEM_SECURITY.
            #
            # Não reduz os direitos solicitados
            # em caso de acesso negado.
            handle = api.CreateFileW(
                str(path),
                0x81020000,
                1,
                None,
                3,
                0x0A200000,
                None,
            )

            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(
                    ctypes.get_last_error()
                )

            descriptor = None
            stream = None

            try:
                descriptor = msvcrt.open_osfhandle(
                    handle,
                    (
                        os.O_RDONLY
                        | os.O_BINARY
                        | os.O_NOINHERIT
                    ),
                )
                handle = None

                stream = os.fdopen(
                    descriptor,
                    "rb",
                    buffering=0,
                )
                descriptor = None

                info = os.fstat(
                    stream.fileno()
                )

                self._plain(info)

                signature = self._signature(info)

                if (
                    signature != self._signature(before)
                    or signature != self._signature(
                        self._file_info(path)
                    )
                    or info.st_nlink != 1
                ):
                    raise BackupError(
                        "Origem alterada ou com "
                        "múltiplos vínculos."
                    )

                yield stream

                if (
                    self._signature(
                        os.fstat(stream.fileno())
                    ) != signature
                    or self._signature(
                        self._file_info(path)
                    ) != signature
                ):
                    raise BackupError(
                        "A origem mudou durante a captura."
                    )

            finally:
                if stream is not None:
                    stream.close()

                if descriptor is not None:
                    os.close(descriptor)

                if handle is not None:
                    api.CloseHandle(handle)

    def _dump(
        self,
        api,
        source,
        destination=None,
    ):
        import msvcrt

        source.seek(0)

        handle = msvcrt.get_osfhandle(
            source.fileno()
        )

        context = ctypes.c_void_p()
        buffer = ctypes.create_string_buffer(BLOCK)
        count = wintypes.DWORD()

        digest = hashlib.sha256()
        total = 0
        failure = None

        try:
            while True:
                if not api.BackupRead(
                    handle,
                    buffer,
                    BLOCK,
                    ctypes.byref(count),
                    False,
                    True,
                    ctypes.byref(context),
                ):
                    raise ctypes.WinError(
                        ctypes.get_last_error()
                    )

                if count.value > BLOCK:
                    raise BackupError(
                        "Tamanho de leitura nativa inválido."
                    )

                if count.value == 0:
                    break

                block = buffer.raw[:count.value]
                total += len(block)

                if total > MAX_ARCHIVE_BYTES:
                    raise BackupError(
                        "Backup ultrapassou o limite "
                        "de captura."
                    )

                digest.update(block)

                if destination is not None:
                    self._write_all(
                        destination,
                        block,
                    )

            return total, digest.hexdigest()

        except BaseException as error:
            failure = error
            raise

        finally:
            # Libera o contexto inclusive após falha.
            if not api.BackupRead(
                handle,
                None,
                0,
                ctypes.byref(count),
                True,
                True,
                ctypes.byref(context),
            ):
                error = ctypes.WinError(
                    ctypes.get_last_error()
                )

                if failure is not None:
                    failure.add_note(
                        "Liberação de BackupRead: "
                        f"{error}"
                    )
                else:
                    raise error

    @staticmethod
    def _stable(basic):
        # A leitura pode atualizar o acesso.
        # Não restaura datas na origem.
        return {
            key: value
            for key, value in basic.items()
            if key != "access_time"
        }

    @exclusive
    @audited_operation("BACKUP_WINDOWS")
    def backup_windows(
        self,
        file_path,
        *,
        expected_sha256=None,
        expected_signature=None,
    ):
        source_path = self._path(file_path)

        if source_path.is_relative_to(
            self.backup_dir
        ):
            raise BackupError(
                "Origem dentro da área de backup."
            )

        if expected_sha256 is not None:
            _digest(expected_sha256)

        if expected_signature is not None:
            if (
                not isinstance(
                    expected_signature,
                    (tuple, list),
                )
                or len(expected_signature) != 5
                or any(
                    type(item) is not int
                    for item in expected_signature[:4]
                )
                or (
                    expected_signature[4] is not None
                    and type(
                        expected_signature[4]
                    ) is not int
                )
            ):
                raise BackupError(
                    "Assinatura esperada inválida."
                )

            expected_signature = tuple(
                expected_signature
            )

        operation_dir = None
        archive = None

        try:
            api = self._api()
            import msvcrt

            with self._source(
                api,
                source_path,
            ) as source:
                info = os.fstat(
                    source.fileno()
                )
                signature = self._signature(info)

                if (
                    expected_signature is not None
                    and signature != expected_signature
                ):
                    raise BackupError(
                        "Origem diferente da versão revisada."
                    )

                basic = self._basic(
                    api,
                    msvcrt.get_osfhandle(
                        source.fileno()
                    ),
                )

                if (
                    basic["attributes"]
                    & ~ALLOWED_ATTRIBUTES
                ):
                    raise BackupError(
                        "Atributos da origem fora "
                        "do perfil suportado."
                    )

                self._directory(
                    self.backup_dir,
                    create=True,
                )

                operation_id = str(uuid4())

                operation_dir = (
                    self.backup_dir
                    / operation_id
                )
                self._new_operation_directory(
                    operation_dir
                )

                archive = (
                    operation_dir
                    / ARCHIVE_NAME
                )

                with self._parents(
                    api,
                    operation_dir,
                ):
                    operation = {
                        "format_version": 1,
                        "operation_id": operation_id,
                        "state": "CREATING",
                        "data_file": ARCHIVE_NAME,
                        "metadata_scope": SCOPE,
                        "deletion_authorized": False,
                        "source_path": str(source_path),
                        "source_signature": list(signature),
                        "source_metadata": {
                            "size_bytes": info.st_size,
                        },
                        "native_basic": basic,
                        "created_at": _now(),
                    }

                    operation_digest = (
                        self._write_manifest(
                            operation_dir / OPERATION_NAME,
                            operation,
                        )
                    )

                    with self._protected(
                        archive,
                        create=True,
                    ) as target:
                        first = self._dump(
                            api,
                            source,
                            target,
                        )

                        target.flush()
                        os.fsync(
                            target.fileno()
                        )

                        index = inspect_archive(
                            target,
                            info.st_size,
                        )

                    second = self._dump(
                        api,
                        source,
                    )

                    current_basic = self._basic(
                        api,
                        msvcrt.get_osfhandle(
                            source.fileno()
                        ),
                    )

                    if (
                        first != second
                        or first != (
                            index["archive_size_bytes"],
                            index["archive_sha256"],
                        )
                        or self._stable(basic)
                        != self._stable(current_basic)
                    ):
                        raise BackupError(
                            "Dados ou metadados mudaram "
                            "na captura."
                        )

                    main = next(
                        (
                            row
                            for row in index["streams"]
                            if row["id"] == 1
                        ),
                        None,
                    )

                    main_hash = (
                        main["sha256"]
                        if main
                        else hashlib.sha256(b"").hexdigest()
                    )

                    if (
                        expected_sha256 is not None
                        and main_hash != expected_sha256
                    ):
                        raise BackupError(
                            "Conteúdo diferente do "
                            "SHA-256 revisado."
                        )

                # _source precisa concluir todas as
                # verificações antes do marcador final.

            with self._parents(
                api,
                operation_dir,
            ):
                with self._protected(
                    archive
                ) as saved:
                    confirmed = inspect_archive(
                        saved,
                        info.st_size,
                    )

                    if confirmed != index:
                        raise BackupError(
                            "O backup mudou antes "
                            "da publicação."
                        )

                    self._write_manifest(
                        operation_dir / VERIFIED_NAME,
                        {
                            **operation,
                            **index,
                            "main_sha256": main_hash,
                            "state": "WINDOWS_STREAMS_VERIFIED",
                            "operation_sha256": operation_digest,
                            "verified_at": _now(),
                            "restore_validated": False,
                        },
                    )

            return archive

        except (
            OSError,
            BackupError,
            ValueError,
            TypeError,
        ) as error:
            raise BackupError(
                "Captura Windows não concluída: "
                f"{error}. Artefatos: {operation_dir}",
                operation_dir=operation_dir,
                partial_path=archive,
            ) from error