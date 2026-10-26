"""Relatórios históricos em SQLite; não armazenam autorização de exclusão.

Cada gravação é uma transação completa. Caminhos viram textos e tuplas viram
listas JSON; ler um relatório não consulta nem revalida os arquivos analisados.
O módulo não abre banco ou cria diretórios na importação/construção.
"""

import hashlib
import json
import math
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from utils.config_parser import ConfigError, validate_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATABASE_PATH = PROJECT_ROOT / 'data' / 'relatorios.sqlite'
FORMAT_VERSION = 1
_LIST_FIELDS = (
    'duplicates', 'inventory', 'scan_errors', 'scan_pending_errors',
    'scan_recovered_errors', 'skipped', 'records', 'comparison_errors',
    'pending_files', 'recovered_files',
)
_DICT_FIELDS = ('scan_summary', 'summary')
_COLUMNS = (
    'report_id', 'format_version', 'started_at', 'finished_at', 'saved_at',
    'outcome', 'inventory_files', 'duplicate_groups', 'pending_files',
    'pending_locations',
)


class ReportStoreError(RuntimeError):
    """Contrato inválido, versão incompatível ou falha de armazenamento/leitura."""


def _timestamp(value):
    if not isinstance(value, str):
        raise ReportStoreError('Informe horários ISO 8601 com fuso explícito.')
    try:
        instant = datetime.fromisoformat(value)
        if instant.utcoffset() is None:
            raise ValueError('Horário sem fuso.')
        return instant.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError) as error:
        raise ReportStoreError(f'Horário inválido: {value!r}.') from error


def _identifier(value):
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError('Use UUID em sua representação canônica.')
    except (ValueError, AttributeError) as error:
        raise ReportStoreError('Identificador de relatório inválido.') from error
    return value


def _json_value(value):
    # Não usa pickle, reconstrução de classes ou acesso aos caminhos do relato.
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key: _json_value(item) for key, item in value.items()}
    raise ReportStoreError(f'Tipo não suportado no relatório: {type(value).__name__}.')


def _counts(report):
    if not isinstance(report, dict):
        raise ReportStoreError('O relatório deve ser um dicionário completo do worker.')
    for field in _LIST_FIELDS:
        if not isinstance(report.get(field), list):
            raise ReportStoreError(f'Relatório inválido: {field} deve ser uma lista.')
    for field in _DICT_FIELDS:
        if not isinstance(report.get(field), dict):
            raise ReportStoreError(f'Relatório inválido: {field} deve ser um dicionário.')
    for field in _LIST_FIELDS[1:]:
        if any(not isinstance(item, dict) for item in report[field]):
            raise ReportStoreError(f'Relatório inválido: registros de {field} devem ser dicionários.')
    if any(not isinstance(group, list) or len(group) < 2
           or any(not isinstance(item, dict) for item in group)
           for group in report['duplicates']):
        raise ReportStoreError('Grupos de duplicatas devem conter ao menos dois registros.')
    return {
        'outcome': ('CONCLUDED_WITH_PENDING' if report['pending_files']
                    or report['scan_pending_errors'] else 'CONCLUDED'),
        'inventory_files': len(report['inventory']),
        'duplicate_groups': len(report['duplicates']),
        'pending_files': len(report['pending_files']),
        'pending_locations': len(report['scan_pending_errors']),
    }


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReportStoreError(f'Campo repetido no relatório armazenado: {key}.')
        result[key] = value
    return result


def _constant(value):
    raise ReportStoreError(f'Valor JSON inválido no relatório armazenado: {value}.')


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ReportStoreError('Número não finito no relatório armazenado.')
    return number


class ReportStore:
    def __init__(self, database_path=None):
        value = DATABASE_PATH if database_path is None else database_path
        try:
            raw = os.fspath(value)
            if (not isinstance(raw, str) or not raw.strip()
                    or any(ord(char) < 32 for char in raw)):
                raise ValueError('Caminho de banco vazio ou com caracteres de controle.')
            path = Path(raw)
            if os.name == 'nt' and bool(path.drive) != bool(path.root):
                raise ValueError('Caminho Windows incompleto.')
            self.database_path = Path(os.path.normpath(str(
                path if path.is_absolute() else PROJECT_ROOT / path
            )))
        except (TypeError, ValueError) as error:
            raise ReportStoreError(f'Caminho de banco inválido: {error}') from error

    def _exists(self):
        try:
            self.database_path.stat()
            return True
        except FileNotFoundError:
            return False
        except OSError as error:
            raise ReportStoreError(f'Não foi possível acessar o banco: {error}') from error

    @contextmanager
    def _connection(self, *, write=False):
        connection = None
        try:
            if write:
                self.database_path.parent.mkdir(parents=True, exist_ok=True)
                connection = sqlite3.connect(str(self.database_path), timeout=5)
                connection.execute('PRAGMA synchronous = FULL')
                connection.execute('BEGIN IMMEDIATE')
            else:
                connection = sqlite3.connect(
                    self.database_path.as_uri() + '?mode=ro', uri=True, timeout=5,
                )
            connection.row_factory = sqlite3.Row
            yield connection
            if write:
                connection.commit()
        except (sqlite3.Error, OSError) as error:
            raise ReportStoreError(f'Falha no banco de relatórios {self.database_path}: {error}') from error
        finally:
            # Fechar sem commit desfaz a transação em caso de qualquer exceção,
            # inclusive validação de contrato/versão ou interrupção do chamador.
            if connection is not None:
                connection.close()

    @staticmethod
    def _schema(connection, *, create=False):
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN (?, ?)",
            ('dedup_report_schema', 'dedup_reports'),
        )}
        if not tables:
            if not create:
                return False
            connection.execute('''CREATE TABLE dedup_report_schema (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                version INTEGER NOT NULL
            )''')
            connection.execute('INSERT INTO dedup_report_schema VALUES (1, ?)', (FORMAT_VERSION,))
            connection.execute('''CREATE TABLE dedup_reports (
                report_id TEXT PRIMARY KEY NOT NULL,
                format_version INTEGER NOT NULL CHECK (format_version = 1),
                started_at TEXT NOT NULL, finished_at TEXT NOT NULL, saved_at TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('CONCLUDED', 'CONCLUDED_WITH_PENDING')),
                inventory_files INTEGER NOT NULL CHECK (inventory_files >= 0),
                duplicate_groups INTEGER NOT NULL CHECK (duplicate_groups >= 0),
                pending_files INTEGER NOT NULL CHECK (pending_files >= 0),
                pending_locations INTEGER NOT NULL CHECK (pending_locations >= 0),
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64)
            )''')
            connection.execute('CREATE INDEX dedup_reports_finished ON dedup_reports (finished_at DESC, report_id)')
            return True
        if tables != {'dedup_report_schema', 'dedup_reports'}:
            raise ReportStoreError('Estrutura de relatórios incompleta; banco preservado.')
        versions = connection.execute('SELECT singleton, version FROM dedup_report_schema').fetchall()
        if len(versions) != 1 or tuple(versions[0]) != (1, FORMAT_VERSION):
            raise ReportStoreError('Versão do banco de relatórios incompatível; banco preservado.')
        return True

    def save_report(self, report, config, *, started_at, finished_at, report_id=None):
        """Insere um snapshot completo e imutável pelo identificador; nunca sobrescreve.

        Validação/serialização terminam antes de abrir o banco para escrita.
        Commit retornado não promete durabilidade além do armazenamento SQLite.
        """
        identifier = _identifier(str(uuid4()) if report_id is None else report_id)
        start, finish = _timestamp(started_at), _timestamp(finished_at)
        if datetime.fromisoformat(start) > datetime.fromisoformat(finish):
            raise ReportStoreError('O término da análise não pode anteceder o início.')
        try:
            payload = {
                'report_id': identifier, 'format_version': FORMAT_VERSION,
                'started_at': start, 'finished_at': finish,
                'saved_at': datetime.now(timezone.utc).isoformat(),
                'historical': True, 'requires_revalidation': True,
                'config': validate_config(config), 'report': _json_value(report),
            }
            payload.update(_counts(payload['report']))
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
            digest = hashlib.sha256(encoded.encode('utf-8')).hexdigest()
        except (ConfigError, ValueError, TypeError, UnicodeError, RecursionError) as error:
            raise ReportStoreError(f'Não foi possível serializar o relatório: {error}') from error
        values = [payload[column] for column in _COLUMNS] + [encoded, digest]
        with self._connection(write=True) as connection:
            self._schema(connection, create=True)
            connection.execute(
                'INSERT INTO dedup_reports (' + ','.join(_COLUMNS)
                + ',payload_json,payload_sha256) VALUES (' + ','.join('?' for _ in values) + ')',
                values,
            )
        return identifier

    def list_reports(self, *, limit=50, offset=0):
        """Lista metadados paginados; a integridade do payload é conferida ao abri-lo."""
        if (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500
                or not isinstance(offset, int) or isinstance(offset, bool)
                or not 0 <= offset <= 2**63 - 1):
            raise ReportStoreError('Paginação inválida: limite entre 1 e 500 e deslocamento inteiro não negativo.')
        if not self._exists():
            return []
        with self._connection() as connection:
            if not self._schema(connection):
                return []
            rows = connection.execute(
                'SELECT ' + ','.join(_COLUMNS) + ' FROM dedup_reports '
                'ORDER BY finished_at DESC, report_id LIMIT ? OFFSET ?', (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_report(self, report_id):
        """Lê o histórico e verifica checksum/estrutura; não consulta os arquivos de origem."""
        identifier = _identifier(report_id)
        if not self._exists():
            raise ReportStoreError('Relatório não encontrado.')
        with self._connection() as connection:
            if not self._schema(connection):
                raise ReportStoreError('Relatório não encontrado.')
            row = connection.execute(
                'SELECT ' + ','.join(_COLUMNS)
                + ',payload_json,payload_sha256 FROM dedup_reports WHERE report_id = ?',
                (identifier,),
            ).fetchone()
        if row is None:
            raise ReportStoreError('Relatório não encontrado.')
        try:
            encoded = row['payload_json']
            if not isinstance(encoded, str) or hashlib.sha256(encoded.encode('utf-8')).hexdigest() != row['payload_sha256']:
                raise ReportStoreError('Checksum do relatório armazenado não confere.')
            payload = json.loads(encoded, object_pairs_hook=_object, parse_constant=_constant, parse_float=_float)
            if (not isinstance(payload, dict) or type(payload.get('format_version')) is not int
                    or payload['format_version'] != FORMAT_VERSION
                    or payload.get('historical') is not True or payload.get('requires_revalidation') is not True
                    or not isinstance(payload.get('config'), dict)):
                raise ReportStoreError('Estrutura do relatório armazenado inválida.')
            for column in _COLUMNS:
                if payload.get(column) != row[column]:
                    raise ReportStoreError(f'Metadado do relatório armazenado divergente: {column}.')
            for name, count in _counts(payload.get('report')).items():
                if payload[name] != count:
                    raise ReportStoreError(f'Contagem do relatório armazenado divergente: {name}.')
            if any(_timestamp(payload[name]) != payload[name] for name in ('started_at', 'finished_at', 'saved_at')):
                raise ReportStoreError('Horários armazenados não estão normalizados em UTC.')
            if datetime.fromisoformat(payload['started_at']) > datetime.fromisoformat(payload['finished_at']):
                raise ReportStoreError('Período do relatório armazenado inválido.')
            return payload
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
            raise ReportStoreError(f'Relatório armazenado inválido: {error}') from error
