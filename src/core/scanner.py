"""Inventário somente de leitura e nova tentativa dos locais com falha.

scan_directory() inicia uma rodada; retry_errors() repete suas pendências
uma única vez por local. Nenhum resultado autoriza exclusão de arquivos.
"""

import errno
import os
import stat
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set


class Scanner:
    DEFAULT_IGNORED_DIRS = {
        '$recycle.bin', 'windows', 'system32', '.git',
        'node_modules', 'appdata', '__pycache__',
    }
    DEFAULT_IGNORED_EXTS = {
        '.tmp', '.sys', '.ini', '.dll', '.log', '.bak', '.cab',
    }

    def __init__(
        self, target_dirs: List[str], ignored_dirs: Optional[Set[str]] = None,
        ignored_exts: Optional[Set[str]] = None, *,
        excluded_paths: Optional[List[str]] = None, min_file_size_bytes: int = 1,
    ):
        if min_file_size_bytes < 0:
            raise ValueError('O tamanho mínimo não pode ser negativo.')
        self.target_dirs = list(target_dirs)
        self.ignored_dirs = {
            name.lower() for name in (
                self.DEFAULT_IGNORED_DIRS if ignored_dirs is None else ignored_dirs
            )
        }
        self.ignored_exts = {
            ext.lower() for ext in (
                self.DEFAULT_IGNORED_EXTS if ignored_exts is None else ignored_exts
            )
        }
        self.excluded_paths = list(excluded_paths or [])
        self.min_file_size_bytes = min_file_size_bytes
        self._reset()

    def _reset(self):
        self.inventory = []
        self.errors = []
        self.skipped = []
        self.pending_errors = []
        self.recovered_errors = []
        self.summary = {}
        self._files = {}
        self._failed = {}
        self._recovered = {}
        self._attempts = {}
        self._processed_retry = set()
        self._excluded = []
        self._unresolved_exclusions = []
        self._roots = []
        self._visited_dirs = set()
        self._visited_dir_ids = set()
        self._current_root = None
        self._ready = False
        self._retry_done = False
        self._retrying = False

    @staticmethod
    def _path_key(path: Path) -> str:
        # Preserva caixa, inclusive para diretórios Windows case-sensitive.
        return os.path.normpath(str(path))

    @staticmethod
    def _absolute(path) -> Path:
        return Path(os.path.abspath(path))

    @staticmethod
    def _file_id(info):
        return (info.st_dev, info.st_ino) if info.st_ino else None

    @staticmethod
    def _is_link(info):
        return (
            stat.S_ISLNK(info.st_mode)
            or bool(getattr(info, 'st_file_attributes', 0)
                    & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))
        )

    @staticmethod
    def _is_hidden_or_system(info):
        mask = getattr(stat, 'FILE_ATTRIBUTE_HIDDEN', 0) | getattr(stat, 'FILE_ATTRIBUTE_SYSTEM', 0)
        return bool(getattr(info, 'st_file_attributes', 0) & mask)

    def _touch(self, path):
        key = self._path_key(path)
        if self._retrying and key in self._failed and key not in self._processed_retry:
            self._attempts[key] = 2
            self._processed_retry.add(key)

    def _record_error(self, path, stage, error):
        path = self._absolute(path)
        key = self._path_key(path)
        winerror = getattr(error, 'winerror', None)
        if winerror in (32, 33):
            reason = 'SHARING_VIOLATION'
        elif isinstance(error, PermissionError):
            reason = 'PERMISSION_DENIED'
        elif isinstance(error, FileNotFoundError):
            reason = 'NOT_FOUND'
        elif isinstance(error, NotADirectoryError):
            reason = 'NOT_A_DIRECTORY'
        else:
            reason = 'IO_ERROR'
        event = {
            'path': path, 'root': self._current_root,
            'stage': stage, 'reason': reason, 'message': str(error),
            'errno': error.errno, 'winerror': winerror,
            'attempt': self._attempts.setdefault(key, 1),
            'occurred_at': datetime.now(timezone.utc).isoformat(),
        }
        self.errors.append(event)
        self._failed[key] = event
        self._recovered.pop(key, None)

    def _resolved(self, path, resolution):
        key = self._path_key(path)
        previous = self._failed.pop(key, None)
        if previous is not None:
            self._recovered[key] = {
                'path': previous['path'], 'root': previous['root'],
                'stage': previous['stage'], 'attempts': self._attempts[key],
                'resolution': resolution,
            }

    def _skip(self, path, reason):
        self.skipped.append({'path': path, 'reason': reason})
        self._resolved(path, 'SKIPPED')

    def _is_excluded(self, path):
        key = self._path_key(path)
        return any(key == item or key.startswith(item.rstrip(os.sep) + os.sep)
                   for item in self._excluded)

    def _resolve_exclusions(self, paths):
        self._current_root = None
        unresolved = []
        for path in paths:
            self._touch(path)
            try:
                resolved = self._path_key(path.resolve())
            except OSError as error:
                self._record_error(path, 'exclude', error)
                unresolved.append(path)
            else:
                if resolved not in self._excluded:
                    self._excluded.append(resolved)
                self._resolved(path, 'EXCLUSION_RESOLVED')
        self._unresolved_exclusions = unresolved

    def _resolve_roots(self):
        roots = {}
        for path in self._selected_roots:
            self._current_root = path
            try:
                resolved = path.resolve()
            except OSError as error:
                self._record_error(path, 'root', error)
                # Uma nova tentativa não resolve redirecionamentos em silêncio.
                roots.setdefault(self._path_key(path), path)
            else:
                roots.setdefault(self._path_key(resolved), resolved)
        self._roots = sorted(roots.values(), key=lambda item: len(item.parts))

    def _collect_file(self, path, owner):
        key = self._path_key(path)
        if key in self._files:
            return  # Não relê metadados de um arquivo já inventariado.
        self._touch(path)
        if self._is_excluded(path):
            self._skip(path, 'EXCLUDED_PATH')
            return
        if path.name.startswith('.') or path.suffix.lower() in self._filter_exts:
            self._skip(path, 'FILE_FILTER')
            return
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as error:
            self._record_error(path, 'file', error)
            return
        if self._is_link(info) or not stat.S_ISREG(info.st_mode):
            self._skip(path, 'LINK_OR_SPECIAL_FILE')
            return
        if self._is_hidden_or_system(info):
            self._skip(path, 'HIDDEN_OR_SYSTEM')
            return
        creation = getattr(info, 'st_birthtime_ns', None)
        if creation is None and os.name == 'nt':
            creation = info.st_ctime_ns
        record = {
            'path': path, 'directory': path.parent, 'root': owner,
            'name': path.name, 'size_bytes': info.st_size,
            'creation_time_ns': creation, 'modified_time_ns': info.st_mtime_ns,
            'file_id': self._file_id(info), 'same_file_as': None,
        }
        self.inventory.append(record)
        self._files[key] = record
        self._resolved(path, 'INVENTORIED')

    def _walk(self, directories):
        def on_error(error):
            path = self._absolute(error.filename) if error.filename else directory
            self._touch(path)
            self._record_error(path, 'walk', error)

        for directory, owner in directories:
            self._current_root = owner
            self._touch(directory)
            if self._is_excluded(directory):
                self._skip(directory, 'EXCLUDED_PATH')
                continue
            if self._path_key(directory) in self._visited_dirs:
                continue
            try:
                info = directory.stat(follow_symlinks=False)
                if self._is_link(info):
                    self._skip(directory, 'LINK_OR_REPARSE_POINT')
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    raise NotADirectoryError(errno.ENOTDIR, 'A raiz não é um diretório', str(directory))
                identity = self._file_id(info)
                if identity and identity in self._visited_dir_ids:
                    self._resolved(directory, 'SAME_DIRECTORY')
                    continue
            except OSError as error:
                stage = 'root' if directory == owner else 'directory'
                self._record_error(directory, stage, error)
                continue

            for root, dirs, files in os.walk(directory, onerror=on_error, followlinks=False):
                root_path = Path(root)
                key = self._path_key(root_path)
                if key in self._visited_dirs:
                    dirs[:] = []
                    continue
                self._touch(root_path)
                try:
                    info = root_path.stat(follow_symlinks=False)
                    if self._is_link(info):
                        self._skip(root_path, 'LINK_OR_REPARSE_POINT')
                        dirs[:] = []
                        continue
                    if not stat.S_ISDIR(info.st_mode):
                        raise NotADirectoryError(errno.ENOTDIR, 'O diretório foi substituído', str(root_path))
                    identity = self._file_id(info)
                except OSError as error:
                    self._record_error(root_path, 'directory', error)
                    dirs[:] = []
                    continue
                if identity:
                    if identity in self._visited_dir_ids:
                        self._resolved(root_path, 'SAME_DIRECTORY')
                        dirs[:] = []
                        continue
                    self._visited_dir_ids.add(identity)
                self._visited_dirs.add(key)
                # O yield do os.walk demonstra que a enumeração desse local ocorreu.
                self._resolved(root_path, 'ENUMERATED')
                allowed = []
                for name in dirs:
                    path = root_path / name
                    self._touch(path)
                    if self._is_excluded(path):
                        self._skip(path, 'EXCLUDED_PATH')
                    elif name.lower() in self._filter_dirs or name.startswith('.'):
                        self._skip(path, 'DIRECTORY_FILTER')
                    else:
                        try:
                            info = path.stat(follow_symlinks=False)
                            if self._is_link(info):
                                self._skip(path, 'LINK_OR_REPARSE_POINT')
                            elif self._is_hidden_or_system(info):
                                self._skip(path, 'HIDDEN_OR_SYSTEM')
                            else:
                                allowed.append(name)
                        except OSError as error:
                            self._record_error(path, 'directory', error)
                dirs[:] = allowed
                for name in files:
                    self._collect_file(root_path / name, owner)

    def _guard_retry(self, event):
        """Confere o escopo e os ancestrais sem seguir novos links."""
        path, owner = event['path'], event['root']
        self._current_root = owner
        self._touch(path)
        try:
            relative = path.relative_to(owner)
        except (ValueError, TypeError):
            self._record_error(path, event['stage'], OSError(
                errno.EINVAL, 'Caminho sem raiz de análise válida', str(path)))
            return False
        parents = [owner]
        for part in relative.parts[:-1]:
            parents.append(parents[-1] / part)
        # Para uma subpasta, o próprio alvo também passa nos filtros de pasta.
        if event['stage'] != 'file' and path != owner:
            parents.append(path)
        for parent in parents:
            if self._is_excluded(parent):
                self._skip(path, 'EXCLUDED_PATH')
                return False
            if parent != owner and (parent.name.startswith('.') or parent.name.lower() in self._filter_dirs):
                self._skip(path, 'DIRECTORY_FILTER')
                return False
            try:
                info = parent.stat(follow_symlinks=False)
                if self._is_link(info):
                    self._skip(path, 'LINK_OR_REPARSE_POINT')
                    return False
                if not stat.S_ISDIR(info.st_mode):
                    raise NotADirectoryError(errno.ENOTDIR, 'Um ancestral deixou de ser diretório', str(parent))
                if parent != owner and self._is_hidden_or_system(info):
                    self._skip(path, 'HIDDEN_OR_SYSTEM')
                    return False
            except OSError as error:
                self._record_error(path, event['stage'], error)
                return False
        return True

    def _finish(self):
        identities = {}
        groups = {}
        for record in self.inventory:
            identity = record['file_id']
            alias = identities.get(identity) if identity else None
            record['same_file_as'] = alias
            if identity:
                identities.setdefault(identity, record['path'])
            if alias is None and record['size_bytes'] >= self._minimum:
                groups.setdefault(record['size_bytes'], []).append(record)
        groups = {size: records for size, records in groups.items() if len(records) > 1}
        self.pending_errors = list(self._failed.values())
        self.recovered_errors = list(self._recovered.values())
        for event in self.errors:
            key = self._path_key(event['path'])
            if key in self._failed:
                event['outcome'] = 'PENDING' if self._retry_done else 'PENDING_RETRY'
            else:
                event['outcome'] = self._recovered.get(key, {}).get('resolution', 'RESOLVED')
        self.summary = {
            'inventory_files': len(self.inventory),
            'candidate_files': sum(map(len, groups.values())),
            'pending_locations': len(self.pending_errors),
            'recovered_locations': sum(item['resolution'] != 'SKIPPED' for item in self.recovered_errors),
            'skipped_failed_locations': sum(item['resolution'] == 'SKIPPED' for item in self.recovered_errors),
            'retry_performed': self._retry_done,
        }
        self._ready = True
        return groups

    def scan_directory(self) -> Dict[int, List[Dict]]:
        """Inicia uma nova rodada; não repete falhas automaticamente."""
        self._reset()
        # Congela as opções e caminhos desta rodada, inclusive o diretório base.
        self._filter_dirs = set(self.ignored_dirs)
        self._filter_exts = set(self.ignored_exts)
        self._minimum = self.min_file_size_bytes
        self._selected_roots = [self._absolute(path) for path in self.target_dirs]
        self._resolve_exclusions([self._absolute(path) for path in self.excluded_paths])
        if not self._unresolved_exclusions:
            self._resolve_roots()
            # Raízes com erro de resolução ficam para a fase final.
            roots = [(path, path) for path in self._roots if self._path_key(path) not in self._failed]
            self._walk(roots)
        return self._finish()

    def retry_errors(self) -> Dict[int, List[Dict]]:
        """Repete somente pendências, no máximo duas tentativas por local.

        Repetir esta chamada é idempotente, sem I/O adicional. Falhas descobertas
        ao enumerar uma subpasta recuperada também recebem uma única repetição.
        Retorna todos os candidatos do inventário acumulado, sem calcular hash.
        """
        if not self._ready:
            raise RuntimeError('Execute scan_directory() antes de retry_errors().')
        if self._retry_done:
            return self._finish()
        self._retry_done = True
        self._retrying = True
        self._visited_dirs.clear()
        self._visited_dir_ids.clear()
        if self._unresolved_exclusions:
            self._resolve_exclusions(list(self._unresolved_exclusions))
            if self._unresolved_exclusions:
                return self._finish()
            # A coleta não havia começado enquanto o escopo estava indefinido.
            self._resolve_roots()
            self._walk([(path, path) for path in self._roots
                        if self._path_key(path) not in self._failed])

        queue = deque(self._failed)
        queued = set(queue)
        while queue:
            key = queue.popleft()
            event = self._failed.get(key)
            if event is None or self._attempts[key] >= 2:
                continue
            if self._guard_retry(event):
                if event['stage'] == 'file':
                    self._collect_file(event['path'], event['root'])
                else:
                    self._walk([(event['path'], event['root'])])
            # Filhos recém-descobertos podem falhar em sua primeira coleta.
            for new_key in self._failed:
                if new_key not in queued and self._attempts[new_key] < 2:
                    queued.add(new_key)
                    queue.append(new_key)
        return self._finish()
