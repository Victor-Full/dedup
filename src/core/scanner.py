"""Inventário somente de leitura e seleção de candidatos por tamanho.

O inventário não confirma duplicidade nem autoriza exclusões. Depois de
``scan_directory()``, ``inventory``, ``errors`` e ``skipped`` ficam disponíveis
para os próximos módulos de persistência e apresentação.
"""

import errno
import os
import stat
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
        self,
        target_dirs: List[str],
        ignored_dirs: Optional[Set[str]] = None,
        ignored_exts: Optional[Set[str]] = None,
        *,
        excluded_paths: Optional[List[str]] = None,
        min_file_size_bytes: int = 1,
    ):
        if min_file_size_bytes < 0:
            raise ValueError('O tamanho mínimo não pode ser negativo.')

        self.target_dirs = list(target_dirs)
        # None usa os padrões; um conjunto vazio desativa aquele filtro.
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
        self.inventory: List[Dict] = []
        self.errors: List[Dict] = []
        self.skipped: List[Dict] = []

    @staticmethod
    def _path_key(path: Path) -> str:
        # Não altera a caixa dos nomes, inclusive em diretórios case-sensitive.
        return os.path.normpath(str(path))

    @staticmethod
    def _file_id(file_stats: os.stat_result):
        if file_stats.st_ino:
            return file_stats.st_dev, file_stats.st_ino
        return None

    @staticmethod
    def _is_link(file_stats: os.stat_result) -> bool:
        attributes = getattr(file_stats, 'st_file_attributes', 0)
        return (
            stat.S_ISLNK(file_stats.st_mode)
            or bool(attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0))
        )

    @staticmethod
    def _is_hidden_or_system(file_stats: os.stat_result) -> bool:
        attributes = getattr(file_stats, 'st_file_attributes', 0)
        mask = (
            getattr(stat, 'FILE_ATTRIBUTE_HIDDEN', 0)
            | getattr(stat, 'FILE_ATTRIBUTE_SYSTEM', 0)
        )
        return bool(attributes & mask)

    def _record_error(self, path: Path, stage: str, error: OSError) -> None:
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
        self.errors.append({
            'path': path,
            'stage': stage,
            'reason': reason,
            'message': str(error),
            'errno': error.errno,
            'winerror': winerror,
        })

    def _skip(self, path: Path, reason: str) -> None:
        self.skipped.append({'path': path, 'reason': reason})

    def scan_directory(self) -> Dict[int, List[Dict]]:
        """Inventaria o escopo e retorna candidatos de mesmo tamanho.

        ``inventory`` inclui arquivos exclusivos e abaixo do tamanho mínimo.
        ``same_file_as`` identifica outro caminho para o mesmo arquivo físico;
        esses aliases não contam como cópias independentes nos candidatos.
        Links/reparse points encontrados no percurso não são seguidos.
        Erros são registrados; repetição de leitura de conteúdo pertence ao
        futuro fluxo de análise, não a esta coleta de metadados.
        """
        self.inventory = []
        self.errors = []
        self.skipped = []
        size_map: Dict[int, List[Dict]] = {}
        roots: Dict[str, Path] = {}
        excluded = []

        for value in self.excluded_paths:
            try:
                excluded.append(self._path_key(Path(value).resolve()))
            except OSError as error:
                # Uma exclusão inválida não pode ampliar o escopo em silêncio.
                self._record_error(Path(value), 'exclude', error)
                return {}

        def is_excluded(path: Path) -> bool:
            key = self._path_key(path)
            return any(
                key == item or key.startswith(item.rstrip(os.sep) + os.sep)
                for item in excluded
            )

        for value in self.target_dirs:
            try:
                path = Path(value).resolve()
                roots.setdefault(self._path_key(path), path)
            except OSError as error:
                self._record_error(Path(value), 'root', error)

        visited_dirs: Set[str] = set()
        visited_dir_ids = set()
        visited_paths: Set[str] = set()
        physical_files = {}

        def on_walk_error(error: OSError) -> None:
            self._record_error(Path(error.filename or '.'), 'walk', error)

        # A pasta mais abrangente vem primeiro para evitar percorrer subraízes
        # novamente. Identidades físicas também cobrem aliases de diretórios.
        for directory in sorted(roots.values(), key=lambda item: len(item.parts)):
            if is_excluded(directory):
                self._skip(directory, 'EXCLUDED_PATH')
                continue
            if self._path_key(directory) in visited_dirs:
                continue
            try:
                root_stats = directory.stat(follow_symlinks=False)
                if not stat.S_ISDIR(root_stats.st_mode):
                    raise NotADirectoryError(
                        errno.ENOTDIR, 'A raiz não é um diretório', str(directory),
                    )
                if self._is_link(root_stats):
                    self._skip(directory, 'LINK_OR_REPARSE_POINT')
                    continue
                root_id = self._file_id(root_stats)
                if root_id and root_id in visited_dir_ids:
                    continue
            except OSError as error:
                self._record_error(directory, 'root', error)
                continue

            for root, dirs, files in os.walk(
                directory, onerror=on_walk_error, followlinks=False,
            ):
                root_path = Path(root)
                root_key = self._path_key(root_path)
                if root_key in visited_dirs:
                    dirs[:] = []
                    continue
                visited_dirs.add(root_key)
                try:
                    current_stats = root_path.stat(follow_symlinks=False)
                    if self._is_link(current_stats):
                        self._skip(root_path, 'LINK_OR_REPARSE_POINT')
                        dirs[:] = []
                        continue
                    if not stat.S_ISDIR(current_stats.st_mode):
                        raise NotADirectoryError(
                            errno.ENOTDIR, 'O diretório foi substituído', str(root_path),
                        )
                    current_id = self._file_id(current_stats)
                except OSError as error:
                    self._record_error(root_path, 'directory', error)
                    dirs[:] = []
                    continue
                if current_id:
                    if current_id in visited_dir_ids:
                        dirs[:] = []
                        continue
                    visited_dir_ids.add(current_id)

                allowed_dirs = []
                for name in dirs:
                    path = root_path / name
                    if is_excluded(path):
                        self._skip(path, 'EXCLUDED_PATH')
                    elif name.lower() in self.ignored_dirs or name.startswith('.'):
                        self._skip(path, 'DIRECTORY_FILTER')
                    else:
                        try:
                            info = path.stat(follow_symlinks=False)
                            if self._is_link(info):
                                self._skip(path, 'LINK_OR_REPARSE_POINT')
                            elif self._is_hidden_or_system(info):
                                self._skip(path, 'HIDDEN_OR_SYSTEM')
                            else:
                                allowed_dirs.append(name)
                        except OSError as error:
                            self._record_error(path, 'directory', error)
                dirs[:] = allowed_dirs

                for name in files:
                    path = root_path / name
                    key = self._path_key(path)
                    if key in visited_paths:
                        continue
                    if is_excluded(path):
                        self._skip(path, 'EXCLUDED_PATH')
                        continue
                    if name.startswith('.') or path.suffix.lower() in self.ignored_exts:
                        self._skip(path, 'FILE_FILTER')
                        continue
                    try:
                        info = path.stat(follow_symlinks=False)
                    except OSError as error:
                        self._record_error(path, 'file', error)
                        continue
                    if self._is_link(info) or not stat.S_ISREG(info.st_mode):
                        self._skip(path, 'LINK_OR_SPECIAL_FILE')
                        continue
                    if self._is_hidden_or_system(info):
                        self._skip(path, 'HIDDEN_OR_SYSTEM')
                        continue

                    visited_paths.add(key)
                    file_id = self._file_id(info)
                    same_file_as = physical_files.get(file_id) if file_id else None
                    creation_time = getattr(info, 'st_birthtime_ns', None)
                    if creation_time is None and os.name == 'nt':
                        creation_time = info.st_ctime_ns
                    file_info = {
                        'path': path,
                        'directory': path.parent,
                        'root': directory,
                        'name': name,
                        'size_bytes': info.st_size,
                        'creation_time_ns': creation_time,
                        'modified_time_ns': info.st_mtime_ns,
                        'file_id': file_id,
                        'same_file_as': same_file_as,
                    }
                    self.inventory.append(file_info)
                    if file_id:
                        physical_files.setdefault(file_id, path)
                    if same_file_as is None and info.st_size >= self.min_file_size_bytes:
                        size_map.setdefault(info.st_size, []).append(file_info)

        return {size: files for size, files in size_map.items() if len(files) > 1}
