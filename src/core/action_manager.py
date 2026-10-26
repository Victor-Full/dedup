"""Backup/restauração do conteúdo principal, sem autorização de exclusão.

Os caminhos antigos de remoção/atalho estão bloqueados. Cópias são exclusivas,
conferidas por SHA-256 e bytes, com manifesto por operação. ACLs, proprietário,
ADS e restauração de metadados Windows ainda não estão cobertos.
"""

import ctypes
from ctypes import wintypes
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import stat
from uuid import UUID, uuid4


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_NAME = 'content.bin'
OPERATION_NAME = 'operation.json'
VERIFIED_NAME = 'verified.json'
MANIFEST_LIMIT = 1024 * 1024


class BackupError(RuntimeError):
    """Falha explícita; artefatos parciais são preservados para inspeção."""

    def __init__(self, message, *, operation_dir=None, partial_path=None):
        super().__init__(message)
        self.operation_dir = operation_dir
        self.partial_path = partial_path


def _now():
    return datetime.now(timezone.utc).isoformat()


def _digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise BackupError('Informe um SHA-256 completo em hexadecimal minúsculo.')
    return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BackupError(f'Campo repetido no manifesto: {key}.')
        result[key] = value
    return result


def _reject_constant(value):
    raise BackupError(f'Valor JSON inválido no manifesto: {value}.')


class ActionManager:
    def __init__(self, backup_dir, logger=None, *, chunk_size=65536):
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
            raise BackupError('O tamanho do bloco deve ser um inteiro positivo.')
        self.backup_dir = self._path(backup_dir, relative=True)
        self.chunk_size = chunk_size
        self.logger = logger or logging.getLogger('dedup_audit')

    @staticmethod
    def _path(value, *, relative=False):
        try:
            raw = os.fspath(value)
            if not isinstance(raw, str) or not raw.strip() or any(ord(c) < 32 for c in raw):
                raise ValueError('Caminho vazio ou com caracteres de controle.')
            if raw.startswith(('\\\\?\\', '\\\\.\\')):
                raise ValueError('Namespaces de dispositivos/estendidos não são aceitos nesta versão.')
            path = Path(raw)
            if os.name == 'nt' and bool(path.drive) != bool(path.root):
                raise ValueError('Caminho Windows incompleto.')
            if not path.is_absolute():
                if not relative:
                    raise ValueError('Informe um caminho absoluto completo.')
                path = PROJECT_ROOT / path
            path = Path(os.path.normpath(str(path)))
            if os.name == 'nt' and (os.path.isreserved(path) or any(
                ':' in part or part.endswith((' ', '.')) for part in path.parts[1:]
            )):
                raise ValueError('Nome reservado, fluxo alternativo ou componente ambíguo.')
            return path
        except (TypeError, ValueError) as error:
            raise BackupError(f'Caminho inválido: {error}') from error

    @staticmethod
    def _signature(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                getattr(info, 'st_birthtime_ns', None))

    @staticmethod
    def _plain(info, *, directory=False):
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (not expected or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise BackupError('Link, reparse point ou tipo de arquivo não suportado.')

    def _directory(self, path, *, create=False):
        for parent in reversed((path, *path.parents)):
            try:
                info = parent.stat(follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    parent.mkdir()
                except FileExistsError:
                    pass
                info = parent.stat(follow_symlinks=False)
            self._plain(info, directory=True)

    def _file_info(self, path):
        info = path.stat(follow_symlinks=False)
        self._plain(info)
        if not info.st_ino:
            raise BackupError('O armazenamento não forneceu identidade de arquivo verificável.')
        return info

    @contextmanager
    def _protected(self, path, *, create=False):
        if os.name != 'nt':
            raise BackupError('A abertura protegida desta versão exige Windows.')
        import msvcrt

        self._directory(path.parent)
        before = None if create else self._file_info(path)
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
        api.CreateFileW.restype = wintypes.HANDLE
        api.CloseHandle.argtypes = (wintypes.HANDLE,)
        api.CloseHandle.restype = wintypes.BOOL
        # FILE_SHARE_READ: recusa aberturas incompatíveis existentes e novas
        # escritas/exclusões de conteúdo enquanto o objeto está aberto.
        handle = api.CreateFileW(
            str(path), 0xC0000000 if create else 0x80000000, 1, None,
            1 if create else 3, 0x00200000 | 0x08000000, None,
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = None
        stream = None
        try:
            descriptor = msvcrt.open_osfhandle(
                handle, os.O_BINARY | os.O_NOINHERIT | (os.O_RDWR if create else os.O_RDONLY),
            )
            handle = None  # O descritor passa a ser dono do HANDLE.
            stream = os.fdopen(descriptor, 'r+b' if create else 'rb', buffering=0)
            descriptor = None
            info = os.fstat(stream.fileno())
            self._plain(info)
            current = self._file_info(path)
            signature = self._signature(info)
            if (signature != self._signature(current)
                    or (before is not None and signature != self._signature(before))):
                raise BackupError('Arquivo substituído/alterado entre a conferência e a abertura.')
            yield stream
            after = os.fstat(stream.fileno())
            self._directory(path.parent)
            current = self._file_info(path)
            if (self._signature(after) != self._signature(current)
                    or self._signature(after)[:2] != signature[:2]
                    or (not create and self._signature(after) != signature)):
                raise BackupError('Arquivo ou caminho alterado durante a operação.')
        except (OSError, BackupError) as error:
            raise BackupError(
                str(error), partial_path=path if create else getattr(error, 'partial_path', None),
            ) from error
        finally:
            if stream is not None:
                stream.close()
            if descriptor is not None:
                os.close(descriptor)
            if handle is not None:
                api.CloseHandle(handle)

    @staticmethod
    def _write_all(stream, block):
        remaining = memoryview(block)
        while remaining:
            written = stream.write(remaining)
            if written is None or written <= 0:
                raise BackupError('Gravação incompleta no destino.')
            remaining = remaining[written:]

    @staticmethod
    def _exact(stream, count):
        block = stream.read(count)
        if len(block) != count:
            raise BackupError('Leitura incompleta; conteúdo alterado ou indisponível.')
        return block

    def _stream_digest(self, stream, size):
        stream.seek(0)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            count = min(self.chunk_size, remaining)
            digest.update(self._exact(stream, count))
            remaining -= count
        if stream.read(1):
            raise BackupError('Conteúdo cresceu durante a validação.')
        stream.seek(0)
        return digest.hexdigest()

    def _copy_and_verify(self, source, destination, *, expected_sha256=None):
        source.seek(0)
        size = os.fstat(source.fileno()).st_size
        first = hashlib.sha256()
        remaining = size
        while remaining:
            count = min(self.chunk_size, remaining)
            block = self._exact(source, count)
            first.update(block)
            self._write_all(destination, block)
            remaining -= count
        if source.read(1):
            raise BackupError('Origem cresceu durante a cópia.')
        destination.flush()
        os.fsync(destination.fileno())
        if os.fstat(destination.fileno()).st_size != size:
            raise BackupError('Tamanho do destino diverge da origem.')
        source.seek(0)
        destination.seek(0)
        a, b = hashlib.sha256(), hashlib.sha256()
        remaining = size
        while remaining:
            count = min(self.chunk_size, remaining)
            left, right = self._exact(source, count), self._exact(destination, count)
            if left != right:
                raise BackupError('Conteúdo do destino difere da origem na comparação de bytes.')
            a.update(left)
            b.update(right)
            remaining -= count
        if source.read(1) or destination.read(1):
            raise BackupError('Conteúdo cresceu durante a validação.')
        digest = first.hexdigest()
        if a.hexdigest() != digest or b.hexdigest() != digest:
            raise BackupError('SHA-256 diverge entre cópia e validação.')
        if expected_sha256 is not None and digest != expected_sha256:
            raise BackupError('O conteúdo atual difere do SHA-256 esperado.')
        return size, digest

    def _write_manifest(self, path, data):
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True, allow_nan=False).encode('utf-8')
        if len(raw) > MANIFEST_LIMIT:
            raise BackupError('Manifesto excedeu o limite permitido.')
        with self._protected(path, create=True) as stream:
            self._write_all(stream, raw)
            stream.flush()
            os.fsync(stream.fileno())
        return hashlib.sha256(raw).hexdigest()

    def backup_file(self, file_path, *, expected_sha256=None, expected_signature=None):
        """Copia/valida o conteúdo principal e retorna content.bin, sem remover.

        Hash/assinatura opcionais vinculam à versão revisada. Sucesso não autoriza
        exclusão, nem afirma preservar todos os metadados NTFS.
        """
        source_path = self._path(file_path)
        if source_path.is_relative_to(self.backup_dir):
            raise BackupError('A origem não pode estar dentro da própria área de backup.')
        if expected_sha256 is not None:
            _digest(expected_sha256)
        if expected_signature is not None:
            if (not isinstance(expected_signature, (tuple, list)) or len(expected_signature) != 5
                    or any(type(item) is not int for item in expected_signature[:4])
                    or (expected_signature[4] is not None and type(expected_signature[4]) is not int)):
                raise BackupError('Assinatura de versão inválida.')
            expected_signature = tuple(expected_signature)
        operation_dir = None
        try:
            with self._protected(source_path) as source:
                info = os.fstat(source.fileno())
                signature = self._signature(info)
                if expected_signature is not None and signature != expected_signature:
                    raise BackupError('A origem não corresponde à identidade/versão revisada.')
                self._directory(self.backup_dir, create=True)
                operation_id = str(uuid4())
                candidate = self.backup_dir / operation_id
                candidate.mkdir(exist_ok=False)
                operation_dir = candidate
                data_path = operation_dir / DATA_NAME
                operation = {
                    'format_version': 1, 'operation_id': operation_id, 'state': 'CREATING',
                    'source_path': str(source_path), 'source_signature': list(signature),
                    'source_metadata': {
                        'size_bytes': info.st_size, 'modified_time_ns': info.st_mtime_ns,
                        'creation_time_ns': getattr(info, 'st_birthtime_ns', None),
                        'access_time_ns': info.st_atime_ns, 'mode': info.st_mode,
                    },
                    'created_at': _now(), 'data_file': DATA_NAME,
                    'metadata_scope': 'MAIN_DATA_STREAM_ONLY', 'deletion_authorized': False,
                }
                operation_digest = self._write_manifest(operation_dir / OPERATION_NAME, operation)
                with self._protected(data_path, create=True) as destination:
                    size, digest = self._copy_and_verify(source, destination, expected_sha256=expected_sha256)
            # Só publica após fechar/conferir os contextos da cópia. Reabre e
            # confere o backup antes do marcador, mantendo seu conteúdo protegido.
            with self._protected(data_path) as copied:
                if self._stream_digest(copied, size) != digest:
                    raise BackupError('O backup mudou antes de concluir o manifesto.')
                verified = {
                    **operation, 'state': 'CONTENT_VERIFIED', 'size_bytes': size,
                    'sha256': digest, 'operation_sha256': operation_digest, 'verified_at': _now(),
                }
                self._write_manifest(operation_dir / VERIFIED_NAME, verified)
            self.logger.info('BACKUP_CONTENT_VERIFIED: %s -> %s', source_path, data_path)
            return data_path
        except (OSError, BackupError, ValueError, TypeError) as error:
            raise BackupError(
                f'Backup não concluído: {error}. Artefatos: {operation_dir}',
                operation_dir=operation_dir,
                partial_path=operation_dir / DATA_NAME if operation_dir is not None else None,
            ) from error

    def _backup_path(self, value):
        path = self._path(value)
        try:
            parts = path.relative_to(self.backup_dir).parts
            if len(parts) != 2 or parts[1] != DATA_NAME or str(UUID(parts[0])) != parts[0]:
                raise ValueError('Estrutura de operação inválida.')
        except ValueError as error:
            raise BackupError('Informe content.bin de uma operação desta área de backup.') from error
        return path

    def _read_manifest(self, stream):
        raw = stream.read(MANIFEST_LIMIT + 1)
        if len(raw) > MANIFEST_LIMIT:
            raise BackupError('Manifesto excedeu o limite permitido.')
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant, parse_float=_reject_constant)
        if not isinstance(data, dict):
            raise BackupError('Manifesto deve ser um objeto JSON.')
        return data, hashlib.sha256(raw).hexdigest()

    @contextmanager
    def _verified_backup(self, backup_path):
        path = self._backup_path(backup_path)
        try:
            with ExitStack() as stack:
                op_stream = stack.enter_context(self._protected(path.parent / OPERATION_NAME))
                verified_stream = stack.enter_context(self._protected(path.parent / VERIFIED_NAME))
                data_stream = stack.enter_context(self._protected(path))
                operation, operation_digest = self._read_manifest(op_stream)
                verified, _ = self._read_manifest(verified_stream)
                if (type(operation.get('format_version')) is not int or operation['format_version'] != 1
                        or operation.get('operation_id') != path.parent.name
                        or operation.get('state') != 'CREATING' or operation.get('data_file') != DATA_NAME
                        or operation.get('metadata_scope') != 'MAIN_DATA_STREAM_ONLY'
                        or operation.get('deletion_authorized') is not False
                        or verified.get('state') != 'CONTENT_VERIFIED'
                        or verified.get('operation_sha256') != operation_digest
                        or any(verified.get(k) != v for k, v in operation.items() if k != 'state')):
                    raise BackupError('Manifestos inconsistentes ou operação não validada.')
                digest = _digest(verified.get('sha256'))
                size = verified.get('size_bytes')
                if (type(size) is not int or size < 0
                        or size != operation.get('source_metadata', {}).get('size_bytes')
                        or os.fstat(data_stream.fileno()).st_size != size):
                    raise BackupError('Tamanho do backup/manifesto inválido.')
                if self._stream_digest(data_stream, size) != digest:
                    raise BackupError('SHA-256 do conteúdo do backup não confere.')
                yield data_stream, dict(verified, backup_path=path)
        except (OSError, BackupError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
            raise BackupError(
                f'Não foi possível verificar/utilizar o backup: {error}',
                operation_dir=path.parent, partial_path=getattr(error, 'partial_path', None),
            ) from error

    def verify_backup(self, backup_path):
        """Confere manifesto/conteúdo salvo; não consulta a origem atual."""
        with self._verified_backup(backup_path) as (_, receipt):
            return receipt

    def restore_backup(self, backup_path, destination):
        """Restaura conteúdo para novo arquivo; nunca substitui um existente.

        Em falha após criar o destino, conserva o parcial e informa seu caminho.
        Metadados Windows completos/restauração de permissões ficam pendentes.
        """
        destination = self._path(destination)
        if destination.is_relative_to(self.backup_dir):
            raise BackupError('O destino de restauração deve ficar fora da área de backup.')
        partial_path = None
        try:
            with self._verified_backup(backup_path) as (source, receipt):
                with self._protected(destination, create=True) as target:
                    partial_path = destination
                    self._copy_and_verify(source, target, expected_sha256=receipt['sha256'])
            self.logger.info('RESTORE_CONTENT_VERIFIED: %s -> %s', backup_path, destination)
            return destination
        except (OSError, BackupError, ValueError, TypeError) as error:
            partial_path = partial_path or getattr(error, 'partial_path', None)
            raise BackupError(
                f'Restauração não concluída: {error}. Destino parcial: {partial_path}',
                partial_path=partial_path,
            ) from error

    def delete_duplicate(self, file_path, make_backup=True):
        self.logger.warning('Remoção bloqueada: executor protegido/referência/apontamento ainda pendentes.')
        return False

    def replace_with_shortcut(self, duplicate_path, original_path):
        self.logger.warning('Substituição bloqueada: executor protegido/referência/apontamento ainda pendentes.')
        return False

    def _create_windowas_shortcut(self, location_path, target_path):
        self.logger.warning('Criação de atalho bloqueada até o fluxo recuperável estar integrado.')
        return False
