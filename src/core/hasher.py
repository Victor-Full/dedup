"""SHA-256 completo, igualdade observada por bytes e nova tentativa limitada.

Resultados descrevem as leituras realizadas. Sem snapshot ou proteção contra
escrita, não constituem autorização para apagar os arquivos ativos.
"""

import hashlib
import os
import stat
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


MAX_ATTEMPTS = 2
RecoveryBatch = Tuple[Dict[int, List[Dict]], Optional[Dict]]


class _ReadFailure(Exception):
    def __init__(self, path: Path, reason: str, message: str, cause=None):
        super().__init__(message)
        self.path = path
        self.reason = reason
        self.cause = cause


class Hasher:
    def __init__(self, chunk_size: int = 65536):
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size <= 0:
            raise ValueError('O tamanho do bloco deve ser um inteiro positivo.')
        self.chunk_size = chunk_size
        self.records: List[Dict] = []
        self.errors: List[Dict] = []
        self.pending_files: List[Dict] = []
        self.recovered_files: List[Dict] = []
        self.hash_table: Dict[tuple, List[Dict]] = {}
        self.summary: Dict[str, int] = {}

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _signature(info: os.stat_result) -> tuple:
        # No Windows, ctime é legado e pode divergir entre stat e fstat.
        # Birth time tem semântica explícita; sua ausência não vira ctime.
        version_time = (
            getattr(info, 'st_birthtime_ns', None)
            if os.name == 'nt' else info.st_ctime_ns
        )
        return (
            info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, version_time,
        )

    @staticmethod
    def _changed(path: Path) -> _ReadFailure:
        return _ReadFailure(
            path, 'FILE_CHANGED',
            'Arquivo alterado ou substituído entre a coleta de dados e a leitura.',
        )

    @staticmethod
    def _io_failure(path: Path, error: OSError) -> _ReadFailure:
        if getattr(error, 'winerror', None) in (32, 33):
            reason = 'SHARING_VIOLATION'
        elif isinstance(error, PermissionError):
            reason = 'PERMISSION_DENIED'
        elif isinstance(error, FileNotFoundError):
            reason = 'NOT_FOUND'
        else:
            reason = 'IO_ERROR'
        return _ReadFailure(path, reason, str(error), error)

    def _path_info(self, path: Path) -> os.stat_result:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as error:
            raise self._io_failure(path, error) from error
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, 'st_file_attributes', 0)
            & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)
        ):
            raise _ReadFailure(path, 'UNSUPPORTED_FILE', 'O caminho não é um arquivo regular independente de links.')
        return info

    @contextmanager
    def _reader(self, record: Dict, *, refresh: bool = False):
        path = record['path']
        before = self._path_info(path)
        signature = self._signature(before)
        expected = record.get('read_signature')
        if not refresh:
            if expected is not None and signature != expected:
                raise self._changed(path)
            file_id = record.get('file_id')
            if file_id is not None and file_id != signature[:2]:
                raise self._changed(path)
            if record.get('size_bytes', before.st_size) != before.st_size:
                raise self._changed(path)
            if record.get('modified_time_ns', before.st_mtime_ns) != before.st_mtime_ns:
                raise self._changed(path)

        try:
            with path.open('rb') as stream:
                if self._signature(os.fstat(stream.fileno())) != signature:
                    raise self._changed(path)
                yield stream, before
                if self._signature(os.fstat(stream.fileno())) != signature:
                    raise self._changed(path)
                if self._signature(self._path_info(path)) != signature:
                    raise self._changed(path)
        except OSError as error:
            raise self._io_failure(path, error) from error

    def _read(self, stream, path: Path, count: int) -> bytes:
        # Atribui uma falha de leitura ao arquivo correto, mesmo com dois
        # contextos de leitura abertos durante uma comparação.
        try:
            return stream.read(count)
        except OSError as error:
            raise self._io_failure(path, error) from error

    def _block(self, stream, path: Path, count: int) -> bytes:
        block = self._read(stream, path, count)
        if len(block) != count:
            raise self._changed(path)
        return block

    def _hash_record(self, record: Dict, *, refresh: bool = False) -> Dict:
        path = record['path']
        digest = hashlib.sha256()
        with self._reader(record, refresh=refresh) as (stream, info):
            remaining = info.st_size
            while remaining:
                count = min(self.chunk_size, remaining)
                digest.update(self._block(stream, path, count))
                remaining -= count
            if self._read(stream, path, 1):
                raise self._changed(path)
        creation = getattr(info, 'st_birthtime_ns', None)
        if creation is None and os.name == 'nt':
            creation = info.st_ctime_ns
        return {
            'hash': digest.hexdigest(),
            'size_bytes': info.st_size,
            'modified_time_ns': info.st_mtime_ns,
            'creation_time_ns': creation,
            'file_id': (info.st_dev, info.st_ino) if info.st_ino else None,
            'read_signature': self._signature(info),
            'hashed_at': self._now(),
        }

    def _compare_records(self, left: Dict, right: Dict) -> bool:
        with self._reader(left) as (first, first_info):
            with self._reader(right) as (second, second_info):
                if first_info.st_size != second_info.st_size:
                    return False
                first_hash, second_hash = hashlib.sha256(), hashlib.sha256()
                equal = True
                remaining = first_info.st_size
                while remaining:
                    count = min(self.chunk_size, remaining)
                    a = self._block(first, left['path'], count)
                    b = self._block(second, right['path'], count)
                    if a != b:
                        equal = False
                    first_hash.update(a)
                    second_hash.update(b)
                    remaining -= count
                for stream, record, digest in (
                    (first, left, first_hash), (second, right, second_hash),
                ):
                    if self._read(stream, record['path'], 1):
                        raise self._changed(record['path'])
                    # Liga os bytes comparados ao hash obtido anteriormente,
                    # detectando também conteúdo trocado com metadados iguais.
                    if record.get('hash') is not None and digest.hexdigest() != record['hash']:
                        raise self._changed(record['path'])
        return equal

    def _report(self, record: Dict, failure: _ReadFailure, stage: str) -> None:
        error = {
            'path': failure.path,
            'root': record.get('root'),
            'stage': stage,
            'reason': failure.reason,
            'message': str(failure),
            'attempt': record.get('attempts', 1),
            'occurred_at': self._now(),
            'errno': getattr(failure.cause, 'errno', None),
            'winerror': getattr(failure.cause, 'winerror', None),
        }
        if 'content_attempts' in record:
            error.update(
                content_attempt=record['content_attempts'],
                prior_failures=record['prior_failures'],
            )
        self.errors.append(error)
        record['last_error'] = error

    def compute_sha256(self, file_path: str) -> Optional[str]:
        """Hash de uma leitura validada; retorna None e registra falhas.

        A repetição ao fim da rodada é coordenada por ``find_duplicates``.
        """
        record = {'path': Path(os.path.abspath(file_path))}
        try:
            return self._hash_record(record)['hash']
        except _ReadFailure as failure:
            self._report(record, failure, 'hash')
            return None

    def compare_byte_to_byte(self, file1: str, file2: str) -> bool:
        """Compara sem cache; falhas retornam False e ficam em ``errors``."""
        records = [
            {'path': Path(os.path.abspath(path))} for path in (file1, file2)
        ]
        try:
            return self._compare_records(*records)
        except _ReadFailure as failure:
            record = next(item for item in records if item['path'] == failure.path)
            self._report(record, failure, 'compare')
            return False

    @staticmethod
    def _prior_failures(size_grups: Dict, prior_failures: Optional[Dict]) -> Dict:
        """Valida o orçamento informado sem consultar o sistema de arquivos."""
        if prior_failures is None:
            return {}
        if not isinstance(prior_failures, dict):
            raise ValueError('prior_failures deve ser um dicionário de caminho para falhas anteriores.')
        paths = {
            str(Path(os.path.abspath(record['path'])))
            for files in size_grups.values() for record in files
        }
        normalized = {}
        for path, count in prior_failures.items():
            if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_ATTEMPTS:
                raise ValueError('Cada contagem de prior_failures deve ser um inteiro entre 0 e 2.')
            try:
                value = os.fspath(path)
            except TypeError as error:
                raise ValueError('As chaves de prior_failures devem ser caminhos de arquivo.') from error
            if not isinstance(value, str) or not value.strip() or '\x00' in value:
                raise ValueError('As chaves de prior_failures devem ser caminhos de arquivo não vazios.')
            key = str(Path(os.path.abspath(value)))
            if key not in paths:
                raise ValueError(f'prior_failures contém caminho fora dos candidatos: {key}')
            if key in normalized and normalized[key] != count:
                raise ValueError(f'Contagens conflitantes em prior_failures: {key}')
            normalized[key] = count
        return normalized

    def find_duplicates(
        self, size_grups: Dict[int, List[Dict]], *, prior_failures: Optional[Dict] = None,
        recover_candidates: Optional[Callable[[], RecoveryBatch]] = None,
        candidates_for_size: Optional[Callable[[int], RecoveryBatch]] = None,
    ) -> List[List[Dict]]:
        """Retorna grupos sem sobreposição de igualdade observada.

        Copia os registros de entrada, agrupa por (tamanho atual, SHA-256),
        confirma por bytes e repete ao final apenas os itens que falharam.
        prior_failures informa falhas já consumidas por candidato em uma fase
        anterior. O total lógico é limitado a dois; sem esse argumento mantém
        as duas tentativas de conteúdo anteriores. A primeira leitura sempre
        confere os metadados recebidos, mesmo continuando a tentativa global 2.
        Comparações dependentes podem ser refeitas dentro da mesma tentativa.

        recover_candidates, quando fornecido, é chamado uma vez após a primeira
        comparação/rechecagem e antes de repetir conteúdo. Retorna (candidatos,
        falhas_anteriores) para incorporar arquivos recuperados sem reiniciar os
        já conhecidos. O chamador pode assim adiar a recuperação do inventário.

        candidates_for_size consulta candidatos do inventário pelo novo tamanho
        após um hash de repetição bem-sucedido que altere o tamanho conhecido.
        Retorna (grupos, falhas_anteriores), somente para o tamanho solicitado.
        Cada tamanho é consultado no máximo uma vez por chamada. O fornecedor
        deve respeitar o escopo/filtros e incluir exclusivos elegíveis; o hasher
        não enumera pastas nem reinicia candidatos já conhecidos.
        """
        # Rejeita um orçamento inválido antes de qualquer leitura e sem apagar
        # os resultados de uma chamada anterior válida deste comparador.
        if recover_candidates is not None and not callable(recover_candidates):
            raise ValueError('recover_candidates deve ser uma função sem argumentos ou None.')
        if candidates_for_size is not None and not callable(candidates_for_size):
            raise ValueError('candidates_for_size deve ser uma função de tamanho ou None.')
        inherited = self._prior_failures(size_grups, prior_failures)
        self.records = []
        self.errors = []
        self.pending_files = []
        self.recovered_files = []
        self.hash_table = {}
        self.summary = {}
        by_path = {}
        retry_queue = deque()
        queued = set()
        verified = {}
        recovery_calls = 0
        supplemental_count = 0
        requested_sizes = set()
        size_candidate_count = 0

        def add_records(groups: Dict, budgets: Dict) -> List[Dict]:
            # Reapresentar um caminho não pode reiniciar sua contagem nem
            # substituir as evidências da primeira análise por outro snapshot.
            for key, count in budgets.items():
                if key in by_path and count != by_path[key]['prior_failures']:
                    raise ValueError(f'A recuperação não pode alterar o orçamento de um candidato conhecido: {key}')
            added = []
            for size, files in groups.items():
                for original in files:
                    path = Path(os.path.abspath(original['path']))
                    key = str(path)
                    if key in by_path:
                        continue
                    record = dict(original)
                    for field in ('hash', 'read_signature', 'last_error', 'hashed_at', 'compared_at'):
                        record.pop(field, None)
                    prior = budgets.get(key, 0)
                    record.update(
                        path=path, attempts=prior, prior_failures=prior,
                        content_attempts=0, analysis_status='PENDING',
                    )
                    record['requires_revalidation'] = True
                    record.setdefault('size_bytes', size)
                    by_path[key] = record
                    self.records.append(record)
                    added.append(record)
            return added

        def fail(record: Dict, failure: _ReadFailure, stage: str) -> None:
            self._report(record, failure, stage)
            old_hash = record.pop('hash', None)
            record.pop('read_signature', None)
            record.pop('hashed_at', None)
            record.pop('compared_at', None)
            if old_hash is not None:
                key = (record['size_bytes'], old_hash)
                self.hash_table[key] = [item for item in self.hash_table[key] if item is not record]
            if record['attempts'] < MAX_ATTEMPTS:
                record['analysis_status'] = 'PENDING_RETRY'
                key = str(record['path'])
                if key not in queued:
                    queued.add(key)
                    retry_queue.append(record)
            else:
                record['analysis_status'] = 'FAILED'

        def hash_one(record: Dict) -> Optional[tuple]:
            record['attempts'] += 1
            record['content_attempts'] += 1
            try:
                record.update(self._hash_record(record, refresh=record['content_attempts'] > 1))
            except _ReadFailure as failure:
                fail(record, failure, 'hash')
                return None
            record['analysis_status'] = 'HASHED'
            key = (record['size_bytes'], record['hash'])
            self.hash_table.setdefault(key, []).append(record)
            return key

        def check_current(record: Dict) -> None:
            if self._signature(self._path_info(record['path'])) != record['read_signature']:
                raise self._changed(record['path'])

        def rebuild(key: tuple) -> None:
            # Uma falha invalida só o item e as relações do seu bloco. Recomeçar
            # o bloco evita conservar matches dependentes de uma referência ruim.
            while True:
                groups = []
                identities = {}
                active = list(self.hash_table.get(key, []))
                try:
                    for record in active:
                        check_current(record)
                        record.pop('compared_at', None)
                        record['analysis_status'] = 'HASHED'
                        identity = record.get('file_id')
                        if identity and identity in identities:
                            record['same_file_as'] = identities[identity]
                            record['analysis_status'] = 'SAME_FILE'
                            continue
                        if identity:
                            identities[identity] = record['path']
                        record['same_file_as'] = None
                        for group in groups:
                            if self._compare_records(record, group[0]):
                                group.append(record)
                                record['compared_at'] = group[0]['compared_at'] = self._now()
                                break
                        else:
                            groups.append([record])
                    for record in active:
                        check_current(record)
                except _ReadFailure as failure:
                    fail(by_path[str(failure.path)], failure, 'compare')
                    continue
                verified[key] = [group for group in groups if len(group) > 1]
                return

        def recheck_all() -> None:
            affected = set()
            for record in self.records:
                if 'hash' not in record:
                    continue
                try:
                    check_current(record)
                except _ReadFailure as failure:
                    affected.add((record['size_bytes'], record['hash']))
                    fail(record, failure, 'recheck')
            for key in affected:
                rebuild(key)

        def analyze_records(records: List[Dict], *, extra_keys=()) -> None:
            affected = dict.fromkeys(extra_keys)
            for record in records:
                if record['attempts'] == MAX_ATTEMPTS:
                    # Uma decisão de orçamento, não uma leitura que teria falhado.
                    fail(record, _ReadFailure(
                        record['path'], 'ATTEMPT_LIMIT_REACHED',
                        'As duas tentativas da análise já foram consumidas antes da leitura do conteúdo.',
                    ), 'budget')
                elif record.get('same_file_as') is not None:
                    record['analysis_status'] = 'SAME_FILE'
                else:
                    key = hash_one(record)
                    if key is not None:
                        affected[key] = None
            for key in affected:
                rebuild(key)
            recheck_all()

        def candidates_at_size(size: int) -> List[Dict]:
            batch = candidates_for_size(size)
            if not isinstance(batch, tuple) or len(batch) != 2 or not isinstance(batch[0], dict):
                raise ValueError('candidates_for_size deve retornar (grupos por tamanho, falhas anteriores).')
            groups, prior = batch
            # Rejeita o lote inteiro antes de admitir ou ler novos caminhos.
            # O inventário é a fonte do escopo; o lote não pode ampliar a
            # consulta para outros tamanhos ou esconder metadados divergentes.
            for group_size, files in groups.items():
                if (not isinstance(group_size, int) or isinstance(group_size, bool)
                        or group_size != size or not isinstance(files, list)):
                    raise ValueError('candidates_for_size deve fornecer listas apenas para o tamanho solicitado.')
                for record in files:
                    if not isinstance(record, dict) or 'path' not in record:
                        raise ValueError('Cada candidato por tamanho deve ser um registro com caminho.')
                    record_size = record.get('size_bytes', group_size)
                    if (not isinstance(record_size, int) or isinstance(record_size, bool)
                            or record_size != size):
                        raise ValueError('O tamanho dos metadados deve coincidir com o tamanho solicitado.')
            budgets = self._prior_failures(groups, prior)
            additional = add_records(groups, budgets)
            requested_sizes.add(size)
            return additional

        analyze_records(add_records(size_grups, inherited))

        if recover_candidates is not None:
            batch = recover_candidates()
            recovery_calls = 1
            if not isinstance(batch, tuple) or len(batch) != 2 or not isinstance(batch[0], dict):
                raise ValueError('recover_candidates deve retornar (grupos por tamanho, falhas anteriores).')
            groups, prior = batch
            budgets = self._prior_failures(groups, prior)
            additional = add_records(groups, budgets)
            supplemental_count = len(additional)
            # Somente novos candidatos recebem hash; os blocos afetados podem
            # precisar de nova comparação por bytes com seus representantes.
            # Mesmo sem adições, confere mudanças ocorridas durante a recuperação.
            analyze_records(additional)

        # Fase final: apenas os itens com falha são hasheados novamente. Falhas
        # novas em referências dependentes também entram na fila, uma única vez.
        while retry_queue:
            record = retry_queue.popleft()
            previous_size = record['size_bytes']
            key = hash_one(record)
            if key is not None:
                size = record['size_bytes']
                if (candidates_for_size is not None and size != previous_size
                        and size not in requested_sizes):
                    additional = candidates_at_size(size)
                    size_candidate_count += len(additional)
                    # Inclui o bloco do arquivo repetido mesmo se o fornecedor
                    # não trouxer candidatos ou trouxer conteúdo diferente.
                    analyze_records(additional, extra_keys=(key,))
                else:
                    rebuild(key)
            if not retry_queue:
                recheck_all()

        duplicates = [group for groups in verified.values() for group in groups]
        for record in self.records:
            if record['analysis_status'] == 'HASHED':
                record['analysis_status'] = 'NO_CONFIRMED_MATCH'
        for group in duplicates:
            group.sort(key=lambda item: (
                item.get('creation_time_ns') is None,
                item.get('creation_time_ns') or 0,
                str(item['path']),
            ))
            for record in group:
                record['analysis_status'] = 'MATCH_OBSERVED'
        self.pending_files = [item for item in self.records if item['analysis_status'] == 'FAILED']
        self.recovered_files = [
            item for item in self.records if item['content_attempts'] > 1 and 'hash' in item
        ]
        self.hash_table = {key: files for key, files in self.hash_table.items() if files}
        self.summary = {
            'candidate_files': len(self.records),
            'hashed_files': sum('hash' in item for item in self.records),
            'recovered_files': len(self.recovered_files),
            'pending_files': len(self.pending_files),
            'same_file_paths': sum(item['analysis_status'] == 'SAME_FILE' for item in self.records),
            'duplicate_groups': len(duplicates),
            'inherited_failure_files': sum(item['prior_failures'] > 0 for item in self.records),
            'blocked_by_prior_failures': sum(
                item['prior_failures'] == MAX_ATTEMPTS for item in self.records
            ),
            'content_attempts': sum(item['content_attempts'] for item in self.records),
            'total_attempts': sum(item['attempts'] for item in self.records),
            'recovery_callback_calls': recovery_calls,
            'supplemental_candidate_files': supplemental_count,
            'size_candidate_callback_calls': len(requested_sizes),
            'size_candidate_files': size_candidate_count,
        }
        return duplicates
