"""Interface de análise. Ações destrutivas aguardam o executor seguro."""

from datetime import datetime, timezone
import json
from pathlib import Path
from uuid import uuid4
from utils.logger import AuditError, audit_event
from utils.audit import OperationAuditError

from PyQt6.QtCore import Qt, QThread, QSignalBlocker, QDateTime, QTimeZone, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QFileDialog,
    QListWidget, QFrame, QMenu, QTabWidget,
)

from core.scanner import Scanner
from core.hasher import Hasher
from core.action_manager import ActionManager, BackupError
from core.report_store import ReportStore, ReportStoreError
from utils.config_parser import (
    CONFIG_PATH,
    PROJECT_ROOT,
    ConfigError,
    load_config,
    validate_config,
)

from core.smart_mark import (
    SelectionError,
    plan_selection,
    REASONS as REASONS_SELECTION,
)


REASONS = {
    'FILE_CHANGED': 'Arquivo alterado durante a análise',
    'PERMISSION_DENIED': 'Acesso negado',
    'SHARING_VIOLATION': 'Arquivo em uso ou compartilhamento bloqueado',
    'NOT_FOUND': 'Arquivo ou pasta não encontrado',
    'NOT_A_DIRECTORY': 'O caminho não é uma pasta',
    'IO_ERROR': 'Falha de leitura ou do armazenamento',
    'UNSUPPORTED_FILE': 'Arquivo substituído por link ou tipo não suportado',
    'ATTEMPT_LIMIT_REACHED': 'Limite de duas tentativas atingido',
}
SKIP_REASONS = {
    'EXCLUDED_PATH': 'Caminho excluído da análise',
    'LINK_OR_REPARSE_POINT': 'Link ou ponto de redirecionamento',
    'DIRECTORY_FILTER': 'Nome de pasta filtrado',
    'FILE_FILTER': 'Nome ou extensão filtrada',
    'LINK_OR_SPECIAL_FILE': 'Link ou arquivo especial',
    'HIDDEN_OR_SYSTEM': 'Arquivo ou pasta oculto/de sistema',
    'PATH_PATTERN': 'Regra de exclusão por padrão',
    
}
STAGES = {
    'root': 'Raiz', 'directory': 'Diretório', 'walk': 'Enumeração',
    'file': 'Metadados', 'exclude': 'Exclusão do escopo',
    'partial_hash': 'SHA-256 dos primeiros 64 KiB',
    'hash': 'SHA-256 completo',
    'compare': 'Comparação de bytes',
    'recheck': 'Revalidação',
    'budget': 'Limite de tentativas',
}
SCAN_OUTCOMES = {
    'PENDING': 'Pendente após nova tentativa',
    'PENDING_RETRY': 'Pendente de nova tentativa',
    'INVENTORIED': 'Arquivo inventariado na nova tentativa',
    'ENUMERATED': 'Diretório enumerado na nova tentativa',
    'EXCLUSION_RESOLVED': 'Escopo de exclusão resolvido',
    'SAME_DIRECTORY': 'Diretório já coberto pelo inventário',
    'SKIPPED': 'Ignorado após nova verificação',
    'RESOLVED': 'Falha resolvida no inventário',
}
ACTION_NOTICE = (
    'Remoção e mesclagem indisponíveis: aguardam validação do fluxo de backup, '
    'referência preservada, atalho e recuperação.'
)
HISTORY_PAGE_SIZE = 50
BACKUP_NOTICE = (
    'Backup somente do conteúdo principal: permissões, proprietário e fluxos adicionais '
    'não estão incluídos. Os originais serão preservados; exclusão continua indisponível.'
)


class ScanWorker(QThread):
    """Entrega resultados observados e preserva falhas de persistência."""

    progress = pyqtSignal(str)
    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, config, parent=None, *, report_store=None):
        super().__init__(parent)

        self.report_store = (
            ReportStore()
            if report_store is None else report_store
        )

        config = validate_config(config)
        database = str(self.report_store.database_path)

        self.config = validate_config({
            **config,
            'excluded_paths': (
                config['excluded_paths']
                + [
                    database + suffix
                    for suffix in (
                        '',
                        '-journal',
                        '-wal',
                        '-shm',
                    )
                ]
                + [
                    str(CONFIG_PATH),
                    str(PROJECT_ROOT / 'logs'),
                ]
            ),
        })

    def run(self):
        analysis_id = str(uuid4())
        audit_errors = []

        try:
            audit_event(
                'SCAN_STARTED',
                analysis_id=analysis_id,
            )

            started_at = datetime.now(timezone.utc).isoformat()

            self.progress.emit(
                'Fase 1/3: inventariando arquivos e registrando falhas...'
            )

            config = self.config

            scanner = Scanner(
                config['monitored_paths'],
                ignored_dirs=config['ignored_dirs'],
                ignored_exts=config['ignored_exts'],
                excluded_paths=config['excluded_paths'],
                min_file_size_bytes=config['min_file_size_bytes'],
                ignored_path_patterns=config['ignored_path_patterns'],
            )

            size_groups = scanner.scan_directory()

            self.progress.emit(
                'Fase 2/3: prefixo de 64 KiB, SHA-256 completo e bytes; '
                'falhas serão tratadas na recuperação final...'
            )

            candidates_by_size = {}
            inventory_failures = {}

            def prior_failures_for(groups):
                return {
                    record['path']: inventory_failures[record['path']]
                    for files in groups.values()
                    for record in files
                    if record['path'] in inventory_failures
                }

            def recover_candidates():
                pending_count = len(scanner.pending_errors)

                self.progress.emit(
                    f'Fase 3/3: recuperação final; '
                    f'{pending_count} locais pendentes no inventário; '
                    'somente candidatos com tentativa restante '
                    'poderão ser repetidos...'
                )

                groups = (
                    scanner.retry_errors()
                    if pending_count else size_groups
                )

                inventory_failures.update({
                    item['path']: item['attempts'] - 1
                    for item in scanner.recovered_errors
                    if (
                        item['stage'] == 'file'
                        and item['resolution'] == 'INVENTORIED'
                    )
                })

                for record in scanner.inventory:
                    if (
                        record.get('same_file_as') is None
                        and record['size_bytes']
                        >= config['min_file_size_bytes']
                    ):
                        candidates_by_size.setdefault(
                            record['size_bytes'],
                            [],
                        ).append(record)

                return groups, prior_failures_for(groups)

            def candidates_for_size(size):
                files = candidates_by_size.get(size, [])
                groups = {size: files} if files else {}

                return groups, prior_failures_for(groups)

            hasher = Hasher(
                chunk_size=config['chunk_size_bytes']
            )

            duplicates = hasher.find_duplicates(
                size_groups,
                recover_candidates=recover_candidates,
                candidates_for_size=candidates_for_size,
            )

            report = {
                'duplicates': duplicates,
                'inventory': scanner.inventory,
                'scan_errors': scanner.errors,
                'scan_pending_errors': scanner.pending_errors,
                'scan_recovered_errors': scanner.recovered_errors,
                'scan_summary': scanner.summary,
                'skipped': scanner.skipped,
                'records': hasher.records,
                'comparison_errors': hasher.errors,
                'pending_files': hasher.pending_files,
                'recovered_files': hasher.recovered_files,
                'summary': hasher.summary,
            }

            finished_at = datetime.now(timezone.utc).isoformat()

            self.progress.emit(
                'Salvando relatório da análise...'
            )

            attempt_id = analysis_id

            # Registra o término da análise separadamente
            # da tentativa de gravar o relatório.
            try:
                audit_event(
                    'SCAN_COMPLETED',
                    analysis_id=analysis_id,
                    inventory_files=len(scanner.inventory),
                    duplicate_groups=len(duplicates),
                    pending_files=len(hasher.pending_files),
                    pending_locations=len(scanner.pending_errors),
                )

            except AuditError as audit_error:
                audit_errors.append(str(audit_error))

            try:
                report_id = self.report_store.save_report(
                    report,
                    config,
                    started_at=started_at,
                    finished_at=finished_at,
                    report_id=attempt_id,
                )

                persistence = {
                    'saved': True,
                    'report_id': report_id,
                    'error': None,
                }

            except OperationAuditError as error:
                audit_errors.append(str(error))

                persistence = {
                    'saved': error.completed,
                    'report_id': (
                        error.result
                        if error.completed else None
                    ),
                    'error': (
                        None
                        if error.completed else str(error)
                    ),
                }

            except Exception as error:
                if isinstance(error, AuditError):
                    audit_errors.append(str(error))

                persistence = {
                    'saved': False,
                    'report_id': None,
                    'error': f'{type(error).__name__}: {error}',
                }

            report['persistence'] = {
                **persistence,
                'started_at': started_at,
                'finished_at': finished_at,
                'attempt_id': attempt_id,
                'config': config,
                'save_attempts': 1,
                'audit_error': ' | '.join(audit_errors) or None,
            }

            self.result_ready.emit(report)

        except Exception as error:
            message = f'{type(error).__name__}: {error}'

            try:
                audit_event(
                    'SCAN_FAILED',
                    analysis_id=analysis_id,
                    error_type=type(error).__name__,
                    error=str(error),
                )

            except AuditError as audit_error:
                message += f' | Auditoria: {audit_error}'

            self.error.emit(message)


class ReportSaveWorker(QThread):
    """Repete a gravação do snapshot sem reler os arquivos de origem."""

    result_ready = pyqtSignal(dict)

    def __init__(self, report_store, report, parent=None):
        super().__init__(parent)

        self.report_store = report_store
        self.report = report

    @staticmethod
    def _json_path(value):
        if isinstance(value, Path):
            return str(value)

        raise TypeError(
            f'Tipo não suportado no relatório: '
            f'{type(value).__name__}.'
        )

    def run(self):
        persistence = dict(self.report['persistence'])

        persistence['save_attempts'] = (
            persistence.get('save_attempts', 1) + 1
        )
        persistence['audit_error'] = None

        try:
            report = {
                key: value
                for key, value in self.report.items()
                if key != 'persistence'
            }

            config = validate_config(
                persistence['config']
            )
            identifier = persistence['attempt_id']

            try:
                self.report_store.save_report(
                    report,
                    config,
                    started_at=persistence['started_at'],
                    finished_at=persistence['finished_at'],
                    report_id=identifier,
                )

            except Exception as save_error:
                if isinstance(save_error, AuditError):
                    persistence['audit_error'] = str(save_error)

                # A falha pode ter ocorrido depois do commit.
                # Só reconhece o registro existente se o
                # snapshot completo corresponder ao esperado.
                try:
                    existing = self.report_store.get_report(
                        identifier
                    )

                except Exception as read_error:
                    raise ReportStoreError(
                        f'Falha ao salvar: {save_error}. '
                        'Não foi possível confirmar o '
                        f'identificador no banco: {read_error}'
                    ) from save_error

                expected = json.loads(json.dumps(
                    report,
                    default=self._json_path,
                    ensure_ascii=False,
                    allow_nan=False,
                ))

                if (
                    existing['report'] != expected
                    or existing['config'] != config
                    or existing['started_at']
                    != persistence['started_at']
                    or existing['finished_at']
                    != persistence['finished_at']
                ):
                    raise ReportStoreError(
                        'O identificador já pertence a um '
                        'snapshot diferente; nenhum registro '
                        'foi substituído.'
                    ) from save_error

            persistence.update(
                saved=True,
                report_id=identifier,
                error=None,
            )

        except Exception as error:
            persistence.update(
                saved=False,
                report_id=None,
                error=f'{type(error).__name__}: {error}',
            )

            if isinstance(error, AuditError):
                persistence['audit_error'] = str(error)

        self.result_ready.emit(persistence)


class BackupWorker(QThread):
    """Copia versões selecionadas sem remover os arquivos de origem."""

    progress = pyqtSignal(str)
    item_ready = pyqtSignal(dict)
    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(
        self,
        config,
        records,
        parent=None,
        *,
        analysis_id=None,
    ):
        super().__init__(parent)

        self.config = validate_config(config)

        if (
            not isinstance(records, (list, tuple))
            or not records
        ):
            raise ValueError(
                'Selecione arquivos de uma análise da sessão.'
            )

        prepared = []
        seen = set()

        for record in records:
            if not isinstance(record, dict):
                raise ValueError(
                    'Cada arquivo deve ter um registro da análise.'
                )

            path = Path(record['path'])
            digest = record.get('hash')
            signature = record.get('read_signature')

            if (
                not path.is_absolute()
                or path in seen
                or record.get('analysis_status')
                != 'MATCH_OBSERVED'
                or record.get('same_file_as') is not None
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(
                    character not in '0123456789abcdef'
                    for character in digest
                )
                or not isinstance(signature, (list, tuple))
                or len(signature) != 5
                or any(
                    type(value) is not int
                    for value in signature[:4]
                )
                or (
                    signature[4] is not None
                    and type(signature[4]) is not int
                )
                or signature[1] == 0
                or signature[2] < 0
                or signature[2] != record.get('size_bytes')
                or signature[3]
                != record.get('modified_time_ns')
            ):
                raise ValueError(
                    'Arquivo sem evidência completa da versão '
                    'analisada ou repetido na seleção.'
                )

            seen.add(path)

            prepared.append({
                'path': path,
                'hash': digest,
                'read_signature': tuple(signature),
            })

        # O construtor apenas prepara os dados.
        # As operações começam em run(), após worker.start().
        self.records = tuple(prepared)
        self.analysis_id = analysis_id
        self.run_id = str(uuid4())

    def run(self):
        try:
            manager = ActionManager(
                self.config['backup_path'],
                chunk_size=self.config['chunk_size_bytes'],
                analysis_id=self.analysis_id,
            )

        except Exception as error:
            self.error.emit(
                f'{type(error).__name__}: {error}'
            )
            return

        saved = 0
        attempted = 0
        audit_failed = False

        for index, record in enumerate(self.records, 1):
            attempted += 1

            self.progress.emit(
                f"Backup de conteúdo {index}/{len(self.records)}: "
                f"{record['path']}"
            )

            result = {
                'run_id': self.run_id,
                'analysis_id': self.analysis_id,
                'source_path': record['path'],
                'expected_sha256': record['hash'],
                'source_signature': record['read_signature'],
                'backup_path': None,
                'operation_dir': None,
                'partial_path': None,
                'status': 'FAILED',
                'error': None,
                'audit_error': None,
                'metadata_scope': 'MAIN_DATA_STREAM_ONLY',
                'deletion_authorized': False,
            }

            try:
                try:
                    path = manager.backup_file(
                        record['path'],
                        expected_sha256=record['hash'],
                        expected_signature=record['read_signature'],
                    )

                except OperationAuditError as error:
                    if not error.completed:
                        raise

                    path = Path(error.result)
                    result['audit_error'] = str(error)
                    audit_failed = True

                result.update(
                    backup_path=path,
                    operation_dir=path.parent,
                )

                receipt = manager.verify_backup(path)

                if (
                    receipt['sha256'] != record['hash']
                    or receipt['size_bytes']
                    != record['read_signature'][2]
                    or Path(receipt['backup_path']) != path
                    or tuple(receipt['source_signature'])
                    != record['read_signature']
                    or Path(receipt['source_path'])
                    != record['path']
                    or receipt['metadata_scope']
                    != 'MAIN_DATA_STREAM_ONLY'
                    or receipt['deletion_authorized'] is not False
                ):
                    raise BackupError(
                        'O recibo do backup diverge da versão selecionada.'
                    )

                result['status'] = (
                    'CONTENT_VERIFIED_AUDIT_FAILED'
                    if result['audit_error']
                    else 'CONTENT_VERIFIED'
                )
                saved += 1

            except Exception as error:
                if isinstance(error, AuditError):
                    audit_failed = True
                    result['audit_error'] = str(error)

                result.update(
                    error=f'{type(error).__name__}: {error}',
                    operation_dir=(
                        getattr(error, 'operation_dir', None)
                        or result['operation_dir']
                    ),
                    partial_path=getattr(
                        error,
                        'partial_path',
                        None,
                    ),
                )

            result['occurred_at'] = datetime.now(
                timezone.utc
            ).isoformat()

            self.item_ready.emit(result)

            if audit_failed:
                break

        self.result_ready.emit({
            'run_id': self.run_id,
            'total': len(self.records),
            'saved': saved,
            'failed': attempted - saved,
            'not_started': len(self.records) - attempted,
            'audit_failed': audit_failed,
        })

class HistoryWorker(QThread):
    """Consulta o banco fora da thread gráfica, sem abrir arquivos de origem."""

    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, report_store, parent=None, *, offset=0, report_id=None):
        super().__init__(parent)
        self.report_store = report_store
        self.offset = offset
        self.report_id = report_id

    def run(self):
        try:
            if self.report_id is not None:
                result = {'snapshot': self.report_store.get_report(self.report_id)}
            else:
                rows = self.report_store.list_reports(limit=HISTORY_PAGE_SIZE + 1, offset=self.offset)
                result = {
                    'rows': rows[:HISTORY_PAGE_SIZE], 'offset': self.offset,
                    'has_more': len(rows) > HISTORY_PAGE_SIZE,
                }
            self.result_ready.emit(result)
        except Exception as error:
            self.error.emit(f'{type(error).__name__}: {error}')


class DedupApp(QMainWindow):
    def __init__(self, config=None, *, report_store=None):
        super().__init__()
        self.setWindowTitle('Dedup v1 - Análise de arquivos duplicados')
        self.resize(1250, 800)
        self.setStyleSheet('background-color: #f4f6f9;')
        self.worker = None
        self.history_worker = None
        self.save_worker = None
        self.backup_worker = None
        self._scan_running = False
        self._history_running = False
        self._save_running = False
        self._backup_running = False
        self.backup_results = []
        self._history_offset = 0
        self._history_has_more = False
        self._historical = False
        self.report_store = ReportStore() if report_store is None else report_store
        self.last_report = None
        self.last_snapshot = None
        self.last_report_id = None
        self._config_error = None
        try:
            self.config = validate_config(load_config() if config is None else config)
        except ConfigError as error:
            self.config = None
            self._config_error = str(error)
        self.setup_ui()
        if self.config is not None:
            self.list_folders.addItems(self.config['monitored_paths'])
        else:
            self.status_label.setText(f'Configuração inválida: {self._config_error}')
        self._update_controls()

    @staticmethod
    def _table(headers):
        table = QTreeWidget()
        table.setHeaderLabels(headers)
        table.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.setStyleSheet(
            'QTreeWidget { font-size: 13px; border: 1px solid #cbd5e1; '
            'background-color: white; } QTreeWidget::item { padding: 5px; }'
        )
        return table

    def setup_ui(self):
        central = QWidget(self)
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        header = QFrame()
        header.setStyleSheet('background-color: #002244; border-bottom: 4px solid #FDB913;')
        header_layout = QVBoxLayout(header)
        title = QLabel('Dedup - Auditoria de arquivos duplicados')
        title.setStyleSheet('color: white; font-size: 22px; font-weight: bold; border: none;')
        subtitle = QLabel('Análise de conteúdo e revisão dos resultados')
        subtitle.setStyleSheet('color: #cbd5e1; border: none;')
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        main_layout.addWidget(header)

        content = QVBoxLayout()
        content.setContentsMargins(20, 15, 20, 15)
        content.setSpacing(12)
        folders = QHBoxLayout()
        self.list_folders = QListWidget()
        self.list_folders.setFixedHeight(80)
        self.list_folders.setToolTip('Pastas desta sessão. Alterações aqui não gravam o JSON.')
        folders.addWidget(self.list_folders)
        folder_buttons = QVBoxLayout()
        self.btn_add_folder = QPushButton('Adicionar pasta')
        self.btn_add_folder.clicked.connect(self.adicionar_diretorio)
        self.btn_remove_folder = QPushButton('Remover pasta')
        self.btn_remove_folder.clicked.connect(self.remover_diretorio)
        folder_buttons.addWidget(self.btn_add_folder)
        folder_buttons.addWidget(self.btn_remove_folder)
        folders.addLayout(folder_buttons)
        self.btn_start_scan = QPushButton('1. Iniciar análise')
        self.btn_start_scan.setStyleSheet(
            'QPushButton { background-color: #0056b3; color: white; padding: 12px; '
            'font-weight: bold; } QPushButton:disabled { background-color: #94a3b8; }'
        )
        self.btn_start_scan.clicked.connect(self.iniciar_varredura)
        folders.addWidget(self.btn_start_scan)
        content.addLayout(folders)

        self.status_label = QLabel('Selecione as pastas e inicie a análise.')
        self.status_label.setWordWrap(True)
        content.addWidget(self.status_label)
        self.persistence_label = QLabel('Nenhum relatório desta sessão foi gravado.')
        self.persistence_label.setWordWrap(True)
        persistence_controls = QHBoxLayout()
        persistence_controls.addWidget(self.persistence_label, 1)
        self.btn_retry_save = QPushButton('Tentar salvar relatório novamente')
        self.btn_retry_save.clicked.connect(self.tentar_salvar_relatorio)
        persistence_controls.addWidget(self.btn_retry_save)
        content.addLayout(persistence_controls)
        self.tabs = QTabWidget()
        self.tree = self._table([
            'Arquivo / grupo', 'Tamanho (bytes)', 'Criação', 'Modificação', 'Situação',
        ])
        self.tree.itemChanged.connect(self.validar_selecao)
        self.inventory_tree = self._table([
            'Nome', 'Local no disco', 'Tamanho (bytes)', 'Criação', 'Modificação', 'Situação',
        ])
        self.issues_tree = self._table([
            'Arquivo / local', 'Etapa', 'Motivo', 'Tentativa geral / conteúdo', 'Resultado na etapa', 'Detalhes', 'Instante (UTC)',
        ])
        self.issues_tree.headerItem().setToolTip(
            3, 'Número geral da tentativa e, nos eventos do comparador, número da tentativa de conteúdo.',
        )
        self.skipped_tree = self._table(['Arquivo / local', 'Motivo do filtro'])
        self.tabs.addTab(self.tree, 'Duplicatas observadas')
        self.tabs.addTab(self.inventory_tree, 'Inventário')
        self.tabs.addTab(self.issues_tree, 'Pendências e ocorrências')
        self.tabs.addTab(self.skipped_tree, 'Ignorados')
        history = QWidget()
        history_layout = QVBoxLayout(history)
        history_buttons = QHBoxLayout()
        self.btn_history_refresh = QPushButton('Atualizar histórico')
        self.btn_history_previous = QPushButton('Página anterior')
        self.btn_history_next = QPushButton('Próxima página')
        self.btn_history_open = QPushButton('Abrir relatório selecionado')
        self.btn_history_refresh.clicked.connect(lambda: self.atualizar_historico(0))
        self.btn_history_previous.clicked.connect(
            lambda: self.atualizar_historico(max(0, self._history_offset - HISTORY_PAGE_SIZE))
        )
        self.btn_history_next.clicked.connect(
            lambda: self.atualizar_historico(self._history_offset + HISTORY_PAGE_SIZE)
        )
        self.btn_history_open.clicked.connect(self.abrir_relatorio_historico)
        for button in (self.btn_history_refresh, self.btn_history_previous,
                       self.btn_history_next, self.btn_history_open):
            history_buttons.addWidget(button)
        history_layout.addLayout(history_buttons)
        self.history_tree = self._table([
            'Término (UTC)', 'Resultado', 'Arquivos', 'Grupos',
            'Pendências: conteúdo / inventário', 'Identificador',
        ])
        self.history_tree.setSelectionMode(QTreeWidget.SelectionMode.SingleSelection)
        self.history_tree.itemSelectionChanged.connect(self._update_controls)
        history_layout.addWidget(self.history_tree)
        self.history_status = QLabel('Atualize para consultar os relatórios salvos.')
        self.history_status.setWordWrap(True)
        history_layout.addWidget(self.history_status)
        self.tabs.addTab(history, 'Histórico')
        self.backup_tree = self._table([
            'Arquivo de origem', 'Resultado', 'Backup / artefatos', 'Motivo da falha', 'Instante (UTC)',
        ])
        self.tabs.addTab(self.backup_tree, 'Backups desta sessão')
        content.addWidget(self.tabs)
        self.evidence_label = QLabel(
            'Datas em America/Sao_Paulo (UTC se o fuso estiver indisponível). '
            'Resultados representam as leituras da análise; exigem revalidação antes de qualquer ação.'
        )
        self.evidence_label.setWordWrap(True)
        content.addWidget(self.evidence_label)

        actions = QHBoxLayout()
        self.btn_smart_select = QPushButton('Seleção para revisão ▾')
        menu = QMenu(self)
        menu.addAction(
            'Preservar a cópia da pasta oficial...'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('official')
        )

        menu.addAction(
            'Preservar o mais novo por criação'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('creation_newest')
        )

        menu.addAction(
            'Preservar o mais antigo por criação'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('creation_oldest')
        )

        menu.addAction(
            'Preservar o mais novo por modificação'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('modified_newest')
        )

        menu.addAction(
            'Preservar o mais antigo por modificação'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('modified_oldest')
        )

        menu.addAction(
            'Limpar seleção'
        ).triggered.connect(
            lambda: self.aplicar_smart_mark('limpar')
        )
        self.btn_smart_select.setMenu(menu)
        actions.addWidget(self.btn_smart_select)
        actions.addStretch()
        self.btn_backup = QPushButton('Copiar conteúdo dos marcados para backup')
        self.btn_backup.clicked.connect(self.fazer_backup_marcados)
        self.btn_backup.setToolTip(BACKUP_NOTICE)
        actions.addWidget(self.btn_backup)
        self.btn_merge = QPushButton('2. Mesclar pastas')
        self.btn_merge.clicked.connect(self.executar_mesclagem)
        self.btn_delete = QPushButton('3. Backup e remoção')
        self.btn_delete.clicked.connect(self.executar_exclusao_padrao)
        actions.addWidget(self.btn_merge)
        actions.addWidget(self.btn_delete)
        content.addLayout(actions)
        self.selection_label = QLabel('0 arquivos marcados para revisão.')
        content.addWidget(self.selection_label)
        self.backup_label = QLabel(BACKUP_NOTICE)
        self.backup_label.setWordWrap(True)
        content.addWidget(self.backup_label)
        self.action_notice = QLabel(ACTION_NOTICE)
        self.action_notice.setWordWrap(True)
        content.addWidget(self.action_notice)
        main_layout.addLayout(content)

    def _busy(self):
        return self._scan_running or self._history_running or self._save_running or self._backup_running

    def _backup_records(self):
        if self._historical or self.last_report is None:
                return []

        selected = {
            Path(item['path'])
            for item in self.obter_arquivos_marcados()
        }

        for index in range(
            self.tree.topLevelItemCount()
        ):
            reference = self.tree.topLevelItem(index).data(
                0,
                Qt.ItemDataRole.UserRole + 2,
            )

            if (
                reference is not None
                and Path(reference) in selected
            ):
                raise ValueError(
                    'A referência automática '
                    'deve permanecer desmarcada.'
                )

        records = []

        for group in self.last_report['duplicates']:
            marked = [
                record
                for record in group
                if Path(record['path']) in selected
            ]

            if marked and len(marked) == len(group):
                raise ValueError(
                    'Mantenha um arquivo desmarcado por grupo.'
                )

            records.extend(marked)

        if len(records) != len(selected):
            raise ValueError(
                'Seleção não pertence aos grupos '
                'da análise atual.'
            )

        return records

    def _has_unsaved_report(self):
        if self._historical or self.last_report is None:
            return False

        persistence = self.last_report.get('persistence')

        return (
            not isinstance(persistence, dict)
            or persistence.get('saved') is not True
        )

    def _allow_report_change(self):
        if not self._has_unsaved_report():
            return True

        self.persistence_label.setText(
            'Relatório ainda não salvo. Use "Tentar salvar novamente" '
            'e confirme a gravação antes de iniciar outra análise, '
            'abrir outro relatório ou fechar a janela.'
        )

        return False

    def _can_retry_save(self):
        if self._historical or self.last_report is None:
            return False
        persistence = self.last_report.get('persistence', {})
        return (persistence.get('saved') is False
                and isinstance(persistence.get('config'), dict)
                and all(isinstance(persistence.get(key), str) and persistence[key]
                        for key in ('attempt_id', 'started_at', 'finished_at')))

    def _update_controls(self):
        idle = not self._busy()
        available = idle and self.config is not None
        self.list_folders.setEnabled(available)
        self.btn_add_folder.setEnabled(available)
        self.btn_remove_folder.setEnabled(available)
        self.btn_start_scan.setEnabled(available and not self._has_unsaved_report() and self.list_folders.count() > 0)
        self.btn_smart_select.setEnabled(available and not self._historical and self.tree.topLevelItemCount() > 0)
        self.tree.setEnabled(idle)
        self.history_tree.setEnabled(idle)
        self.btn_history_refresh.setEnabled(idle)
        self.btn_history_previous.setEnabled(idle and self._history_offset > 0)
        self.btn_history_next.setEnabled(idle and self._history_has_more)
        self.btn_history_open.setEnabled(idle and not self._has_unsaved_report() and bool(self.history_tree.selectedItems()))
        self.btn_retry_save.setEnabled(idle and self._can_retry_save())
        self.btn_backup.setEnabled(
            idle and not self._historical and self.last_report is not None
            and bool(self.obter_arquivos_marcados())
            and isinstance(self.last_report.get('persistence', {}).get('config'), dict)
        )
        # Backup é cópia; nenhum caminho da janela pode chamar remoção/mesclagem.
        self.btn_merge.setEnabled(False)
        self.btn_delete.setEnabled(False)
        self.btn_merge.setToolTip(ACTION_NOTICE)
        self.btn_delete.setToolTip(ACTION_NOTICE)

    def adicionar_diretorio(self):
        if self._busy() or self.config is None:
            return
        path = QFileDialog.getExistingDirectory(self, 'Selecione a pasta do setor')
        if path:
            paths = [self.list_folders.item(i).text() for i in range(self.list_folders.count())]
            try:
                config = validate_config({**self.config, 'monitored_paths': paths + [path]})
            except ConfigError as error:
                self.status_label.setText(f'Pasta não adicionada: {error}')
                return
            self.list_folders.clear()
            self.list_folders.addItems(config['monitored_paths'])
        self._update_controls()

    def remover_diretorio(self):
        if self._busy() or self.config is None:
            return
        for item in self.list_folders.selectedItems():
            self.list_folders.takeItem(self.list_folders.row(item))
        self._update_controls()

    def iniciar_varredura(self):
        if self._busy() or self.config is None:
            return

        if not self._allow_report_change():
            return
        
        paths = [self.list_folders.item(i).text() for i in range(self.list_folders.count())]
        if not paths:
            self.status_label.setText('Adicione pelo menos uma pasta para analisar.')
            return
        try:
            config = validate_config({**self.config, 'monitored_paths': paths})
            worker = ScanWorker(config, self, report_store=self.report_store)
        except (ConfigError, ReportStoreError) as error:
            self.status_label.setText(f'Configuração inválida: {error}')
            return
        self.config = config
        self._clear_report()
        self._scan_running = True
        self._update_controls()
        self.status_label.setText('Preparando análise...')
        if self.worker is not None:
            self.worker.deleteLater()
        self.worker = worker
        worker.progress.connect(self.status_label.setText)
        worker.result_ready.connect(self.apresentar_relatorio)
        worker.error.connect(self._scan_error)
        worker.finished.connect(self._scan_finished)
        worker.start()

    def _clear_report(self):
        if not self._allow_report_change():
            return
        self.last_report = None
        self.last_snapshot = None
        self.last_report_id = None
        self._historical = False
        self.persistence_label.setText('Nenhum relatório desta rodada foi gravado.')
        for tree in (self.tree, self.inventory_tree, self.issues_tree, self.skipped_tree):
            tree.clear()
        self.tabs.setTabText(0, 'Duplicatas observadas')
        self.tabs.setTabText(1, 'Inventário')
        self.tabs.setTabText(2, 'Pendências e ocorrências')
        self.tabs.setTabText(3, 'Ignorados')
        self.validar_selecao()

    def atualizar_historico(self, offset=0):
        if self._busy():
            return
        self._start_history_worker(HistoryWorker(self.report_store, self, offset=offset))

    def fazer_backup_marcados(self):
        if self._busy() or self._historical or self.last_report is None:
            return
        try:
            records = self._backup_records()
            if not records:
                return
            persistence = self.last_report.get('persistence', {})
            config = persistence.get('config')
            if not isinstance(config, dict):
                raise ValueError('Configuração original da análise indisponível; faça nova análise.')
            worker = BackupWorker(config, records, self, analysis_id=persistence.get('attempt_id'))
        except (ConfigError, ValueError, TypeError, KeyError) as error:
            self.backup_label.setText(f'Backup não iniciado: {error}. {BACKUP_NOTICE}')
            return
        if self.backup_worker is not None:
            self.backup_worker.deleteLater()
        self.backup_worker = worker
        self._backup_running = True
        self.backup_label.setText(f"Destino: {worker.config['backup_path']}. {BACKUP_NOTICE}")
        self._update_controls()
        worker.progress.connect(self._backup_progress)
        worker.item_ready.connect(self._backup_item_result)
        worker.result_ready.connect(self._backup_result)
        worker.error.connect(self._backup_error)
        worker.finished.connect(self._backup_finished)
        self.tabs.setCurrentWidget(self.backup_tree)
        worker.start()

    def _backup_progress(self, message):
        self.backup_label.setText(f'{message}. {BACKUP_NOTICE}')

    def _backup_item_result(self, result):
        self.backup_results.append(result)
        location = result['backup_path'] or result['partial_path'] or result['operation_dir']
        item = QTreeWidgetItem(self.backup_tree, [
            str(result['source_path']),
            (
            'Conteúdo validado; auditoria pendente' 
            if result['status'] == 'CONTENT_VERIFIED_AUDIT_FAILED' 
            else 'Conteúdo validado'
            if result['status'] == 'CONTENT_VERIFIED' 
            else 'Falhou; nenhuma remoção executada'
            ),
            str(location) if location is not None else 'Nenhum artefato informado',
            result['error'] or result.get('audit_error') or '',
            result['occurred_at'],
        ])
        item.setData(0, Qt.ItemDataRole.UserRole, dict(result))
        for column in (0, 2, 3):
            item.setToolTip(column, item.text(column))

    def _backup_result(self, result):
        self.backup_label.setText(
            f"Backup de conteúdo concluído: "
            f"{result['saved']}/{result['total']} validados; "
            f"{result['failed']} falhas; "
            f"{result.get('not_started', 0)} não iniciados; "
            f"falha de auditoria: "
            f"{'sim' if result.get('audit_failed') else 'não'}. "
            f"Consulte os motivos e artefatos na aba de backups. "
            f"{BACKUP_NOTICE}"
        )

    def _backup_error(self, message):
        self.backup_label.setText(f'Backup não iniciado: {message}. {BACKUP_NOTICE}')

    def _backup_finished(self):
        self.backup_worker.records = ()
        self._backup_running = False
        self._update_controls()

    def abrir_relatorio_historico(self):
        if self._busy():
            return

        if not self._allow_report_change():
            return
        
        selected = self.history_tree.selectedItems()
        if selected:
            identifier = selected[0].data(0, Qt.ItemDataRole.UserRole)
            self._start_history_worker(HistoryWorker(self.report_store, self, report_id=identifier))

    def tentar_salvar_relatorio(self):
        if self._busy() or not self._can_retry_save():
            return
        if self.save_worker is not None:
            self.save_worker.deleteLater()
        worker = ReportSaveWorker(self.report_store, self.last_report, self)
        self.save_worker = worker
        self._save_running = True
        self.persistence_label.setText('Tentando salvar o relatório desta sessão novamente...')
        self._update_controls()
        worker.result_ready.connect(self._retry_save_result)
        worker.finished.connect(self._retry_save_finished)
        worker.start()

    def _retry_save_result(self, persistence):
        if (self.last_report is not None and not self._historical
                and persistence['attempt_id'] == self.last_report.get('persistence', {}).get('attempt_id')):
            self.last_report['persistence'] = persistence
            # Atualiza somente a gravação, preservando linhas, resumo e as
            # marcações de revisão que o usuário fez depois da análise.
            self._show_persistence(self.last_report)

    def _retry_save_finished(self):
        # Não retém um relatório inteiro no worker após ele terminar; a janela
        # continua dona do resultado da sessão, salvo ou ainda pendente.
        self.save_worker.report = None
        self._save_running = False
        self._update_controls()

    def _start_history_worker(self, worker):
        self._history_running = True
        self.history_status.setText('Consultando histórico...')
        self._update_controls()
        if self.history_worker is not None:
            self.history_worker.deleteLater()
        self.history_worker = worker
        worker.result_ready.connect(self._history_result)
        worker.error.connect(self._history_error)
        worker.finished.connect(self._history_finished)
        worker.start()

    def _history_result(self, result):
        if 'snapshot' in result:
            if not self._allow_report_change():
                return
            
            snapshot = result['snapshot']
            try:
                self.apresentar_relatorio(snapshot['report'], snapshot=snapshot)
            except Exception as error:
                self._clear_report()
                self.status_label.setText('O relatório histórico não pôde ser apresentado.')
                self._history_error(f'{type(error).__name__}: {error}')
                return
            self.tabs.setCurrentIndex(0)
            self.history_status.setText(f"Relatório histórico aberto: {snapshot['report_id']}.")
        else:
            items = []
            try:
                for row in result['rows']:
                    outcome = {
                        'CONCLUDED': 'Concluída',
                        'CONCLUDED_WITH_PENDING': 'Concluída com pendências',
                    }.get(row['outcome'], 'Resultado desconhecido')
                    item = QTreeWidgetItem([
                        str(row['finished_at']), outcome, str(row['inventory_files']),
                        str(row['duplicate_groups']), f"{row['pending_files']} / {row['pending_locations']}",
                        str(row['report_id']),
                    ])
                    item.setData(0, Qt.ItemDataRole.UserRole, row['report_id'])
                    items.append(item)
            except Exception as error:
                self._history_error(f'{type(error).__name__}: {error}')
                return
            self.history_tree.clear()
            self.history_tree.addTopLevelItems(items)
            self._history_offset = result['offset']
            self._history_has_more = result['has_more']
            self.history_status.setText(
                f"Página {self._history_offset // HISTORY_PAGE_SIZE + 1}: {len(result['rows'])} relatórios. "
                'A integridade é conferida ao abrir; origens não são revalidadas.'
            )

    def _history_error(self, message):
        self.history_status.setText(f'Falha ao consultar o histórico: {message}')

    def _history_finished(self):
        self._history_running = False
        self._update_controls()

    def _scan_error(self, message):
        self.status_label.setText(f'Análise interrompida por erro: {message}. Inicie uma nova rodada.')

    def _scan_finished(self):
        self._scan_running = False
        self._update_controls()

    @staticmethod
    def _date(nanoseconds):
        if nanoseconds is None:
            return 'Não disponível'
        zone = QTimeZone(b'America/Sao_Paulo')
        if not zone.isValid():
            zone = QTimeZone(b'UTC')
        instant = QDateTime.fromMSecsSinceEpoch(nanoseconds // 1_000_000, zone)
        if not instant.isValid():
            return 'Data inválida'
        return instant.toString('dd/MM/yyyy HH:mm:ss.zzz t')

    @staticmethod
    def _bytes(size):
        return f'{size:,}'.replace(',', '.')

    def popular_tabela(self, duplicates_list):
        # Somente os dados observados: não consulta novamente os caminhos no disco.
        with QSignalBlocker(self.tree):
            self.tree.clear()
            for group in duplicates_list:
                parent = QTreeWidgetItem(self.tree, [
                    f"SHA-256: {group[0]['hash'][:16]}…", self._bytes(group[0]['size_bytes']),
                    '', '', f'{len(group)} arquivos; igualdade observada',
                ])
                parent.setToolTip(0, group[0]['hash'])
                parent.setExpanded(True)
                for record in group:
                    child = QTreeWidgetItem(parent, [
                        str(record['path']), self._bytes(record['size_bytes']),
                        self._date(record.get('creation_time_ns')),
                        self._date(record.get('modified_time_ns')), 'Exige revalidação para agir',
                    ])
                    child.setData(0, Qt.ItemDataRole.UserRole, record['path'])
                    child.setData(0, Qt.ItemDataRole.UserRole + 1, dict(record))
                    child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    if self._historical:
                        child.setFlags(child.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                    child.setCheckState(0, Qt.CheckState.Unchecked)
        self.validar_selecao()

    def _show_persistence(self, report, snapshot=None):
        persistence = report.get('persistence', {})
        self.last_report_id = snapshot['report_id'] if snapshot else persistence.get('report_id')
        if snapshot:
            self.persistence_label.setText(
                f"RELATÓRIO HISTÓRICO — {snapshot['report_id']}. Período (UTC): "
                f"{snapshot['started_at']} a {snapshot['finished_at']}. "
                'Arquivos atuais não revalidados; seleção indisponível.'
            )
        elif persistence.get('saved'):
            self.persistence_label.setText(
                f"Relatório salvo no histórico: {self.last_report_id}. Atualize a aba Histórico para consultar."
            )
        elif persistence:
            self.persistence_label.setText(
                f"O relatório NÃO foi salvo: {persistence['error']}. "
                f"Tentativa de gravação {persistence.get('save_attempts', 1)}. "
                'Resultado disponível apenas nesta sessão.'
            )
        else:
            self.persistence_label.setText('Relatório desta sessão; gravação não informada.')

        if persistence.get('audit_error'):
            self.persistence_label.setText(
                self.persistence_label.text()
                + ' AUDITORIA PENDENTE: '
                + persistence['audit_error']
            )

    def apresentar_relatorio(self, report, *, snapshot=None):
        if(
            report is not self.last_report
            and not self._allow_report_change()
        ):
            return
        
        self._historical = snapshot is not None
        self.last_snapshot = snapshot
        self.last_report = report
        self._show_persistence(report, snapshot)
        self.popular_tabela(report['duplicates'])
        records = {str(item['path']): item for item in report['records']}
        states = {
            'NO_PARTIAL_MATCH': (
                'Sem par de mesmo tamanho e prefixo nesta análise'
            ),
            'MATCH_OBSERVED': 'Igualdade observada',
            'NO_CONFIRMED_MATCH': 'Sem duplicata confirmada',
            'SAME_FILE': 'Mesmo arquivo físico',
            'FAILED': 'Pendente: análise não concluída',
        }
        self.inventory_tree.clear()
        for original in report['inventory']:
            record = {**original, **records.get(str(original['path']), {})}
            default = ('Mesmo arquivo físico' if record.get('same_file_as') is not None
                       else 'Fora dos candidatos por tamanho/mínimo')
            QTreeWidgetItem(self.inventory_tree, [
                record['name'], str(record['directory']), self._bytes(record['size_bytes']),
                self._date(record.get('creation_time_ns')),
                self._date(record.get('modified_time_ns')),
                states.get(record.get('analysis_status'), default),
            ])
        self.issues_tree.clear()
        for error in report['scan_errors']:
            outcome = SCAN_OUTCOMES.get(error['outcome'], error['outcome'])
            self._add_issue(error, str(error['attempt']), outcome)
        for error in report['comparison_errors']:
            record = records.get(str(error['path']), {})
            if error['reason'] == 'ATTEMPT_LIMIT_REACHED':
                outcome = 'Pendente: tentativas já consumidas; conteúdo não iniciado'
            elif record.get('analysis_status') == 'FAILED':
                outcome = 'Pendente após nova tentativa'
            else:
                outcome = 'Recuperado na nova tentativa'
            content_attempt = error['content_attempt'] or 'não iniciada'
            attempt = f"{error['attempt']} / {content_attempt}"
            self._add_issue(error, attempt, outcome)
        self.skipped_tree.clear()
        for skipped in report['skipped']:
            reason = SKIP_REASONS.get(
                skipped['reason'],
                skipped['reason'],
            )

            if skipped.get('pattern'):
                reason += f": {skipped['pattern']}"

            item = QTreeWidgetItem(
                self.skipped_tree,
                [
                    str(skipped['path']),
                    reason,
                ],
            )

            item.setData(
                0,
                Qt.ItemDataRole.UserRole,
                dict(skipped),
            )
        pending = len(report['pending_files'])
        scan_failures = len(report['scan_pending_errors'])
        scan_summary = report['scan_summary']
        conclusion = 'Análise concluída com pendências' if pending or scan_failures else 'Análise concluída'
        self.status_label.setText(
            ('Relatório histórico; sem revalidação atual. ' if self._historical else '')
            + f"{conclusion}: {len(report['inventory'])} arquivos inventariados; "
            f"{len(report['duplicates'])} grupos de igualdade observada; "
            f"{report['summary'].get('partial_only_files', 0)} candidatos sem leitura integral após o filtro de prefixo; "
            f"{report['summary']['size_candidate_files']} candidatos incorporados após mudança de tamanho; "
            f"{report['summary']['inherited_failure_files']} candidatos com falha anterior no inventário; "
            f"{len(report['recovered_files'])} arquivos recuperados na comparação; "
            f"{scan_summary['recovered_locations']} locais recuperados no inventário; "
            f"{scan_summary['skipped_failed_locations']} locais ignorados após falha no inventário; "
            f'{pending} arquivos pendentes na comparação e {scan_failures} '
            'locais pendentes no inventário.'
        )
        self.tabs.setTabText(0, f"Duplicatas observadas ({len(report['duplicates'])})")
        self.tabs.setTabText(1, f"Inventário ({len(report['inventory'])})")
        self.tabs.setTabText(2, f'Pendências e ocorrências ({self.issues_tree.topLevelItemCount()})')
        self.tabs.setTabText(3, f"Ignorados ({len(report['skipped'])})")

    def _add_issue(self, error, attempt, outcome):
        item = QTreeWidgetItem(self.issues_tree, [
            str(error['path']), STAGES.get(error['stage'], error['stage']),
            REASONS.get(error['reason'], error['reason']), attempt, outcome,
            error['message'], error.get('occurred_at', 'Não registrado'),
        ])
        item.setData(0, Qt.ItemDataRole.UserRole, dict(error))
        item.setToolTip(5, error['message'])
        if 'content_attempt' in error:
            item.setToolTip(
                3, f"Tentativa geral: {error['attempt']}; tentativa de conteúdo: {error['content_attempt']}; "
                f"falhas anteriores herdadas do inventário: {error['prior_failures']}.",
            )

    def aplicar_smart_mark(self, criterio):
        if self._busy() or self._historical:
            return

        aliases = {
            'antigos': 'creation_newest',
            'novos': 'creation_oldest',
        }

        strategy = aliases.get(
            criterio,
            criterio,
        )

        if strategy == 'limpar':
            with QSignalBlocker(self.tree):
                for index in range(
                    self.tree.topLevelItemCount()
                ):
                    parent = self.tree.topLevelItem(index)

                    parent.setData(
                        0,
                        Qt.ItemDataRole.UserRole + 2,
                        None,
                    )
                    parent.setText(
                        4,
                        f'{parent.childCount()} arquivos; '
                        'igualdade observada',
                    )
                    parent.setToolTip(4, '')

                    for child_index in range(
                        parent.childCount()
                    ):
                        child = parent.child(child_index)

                        child.setCheckState(
                            0,
                            Qt.CheckState.Unchecked,
                        )
                        child.setText(
                            4,
                            'Exige revalidação para agir',
                        )

            self.validar_selecao()
            return

        if self.last_report is None:
            return

        official = None

        if strategy == 'official':
            official = QFileDialog.getExistingDirectory(
                self,
                'Escolha a pasta cuja cópia deve ser preservada',
            )

            if not official:
                return

        try:
            report = self.last_report
            groups = report['duplicates']
            persistence = report['persistence']
            inventory = report['inventory']

            # Usa as raízes registradas pelo Scanner,
            # que já normalizou os caminhos do inventário.
            scope = tuple(dict.fromkeys(
                item['root']
                for item in inventory
            ))

            inventoried = {
                Path(item['path'])
                for item in inventory
            }

            if any(
                Path(record['path']) not in inventoried
                for group in groups
                for record in group
            ):
                raise SelectionError(
                    'Um candidato não pertence '
                    'ao inventário da análise.'
                )

            if official is not None:
                official = Path(official).resolve(
                    strict=True
                )

            decisions = plan_selection(
                groups,
                strategy=strategy,
                scope=scope,
                official_directory=official,
            )

            if (
                self.tree.topLevelItemCount()
                != len(groups)
            ):
                raise SelectionError(
                    'A tabela diverge dos grupos do relatório.'
                )

            rows = []

            for index, group in enumerate(groups):
                parent = self.tree.topLevelItem(index)

                children = [
                    parent.child(i)
                    for i in range(parent.childCount())
                ]

                if (
                    len(children) != len(group)
                    or [
                        child.data(
                            0,
                            Qt.ItemDataRole.UserRole,
                        )
                        for child in children
                    ]
                    != [
                        record['path']
                        for record in group
                    ]
                ):
                    raise SelectionError(
                        'Os caminhos da tabela '
                        'divergem do relatório.'
                    )

                rows.append((parent, children))

            selection_id = str(uuid4())

            blocked = sum(
                item.reference is None
                for item in decisions
            )

            audit_event(
                'SMART_MARK_PLANNED',
                selection_id=selection_id,
                analysis_id=persistence['attempt_id'],
                strategy=strategy,
                official_directory=(
                    str(official)
                    if official else None
                ),
                groups=len(decisions),
                blocked_groups=blocked,
                references=[
                    str(item.reference)
                    if item.reference else None
                    for item in decisions
                ],
                reasons=[
                    item.reason
                    for item in decisions
                ],
            )

        except (
            SelectionError,
            OSError,
            KeyError,
            TypeError,
        ) as error:
            self.selection_label.setText(
                'Seleção não aplicada; '
                f'marcação anterior mantida: {error}'
            )
            return

        with QSignalBlocker(self.tree):
            for decision, (parent, children) in zip(
                decisions,
                rows,
            ):
                parent.setData(
                    0,
                    Qt.ItemDataRole.UserRole + 2,
                    decision.reference,
                )
                parent.setText(
                    4,
                    REASONS_SELECTION[decision.reason],
                )
                parent.setToolTip(
                    4,
                    str(
                        decision.reference
                        or REASONS_SELECTION[decision.reason]
                    ),
                )

                for child in children:
                    path = Path(child.data(
                        0,
                        Qt.ItemDataRole.UserRole,
                    ))

                    child.setCheckState(
                        0,
                        (
                            Qt.CheckState.Checked
                            if path in decision.marked
                            else Qt.CheckState.Unchecked
                        ),
                    )

                    child.setText(
                        4,
                        (
                            'Referência preservada para revisão'
                            if path == decision.reference
                            else 'Exige revalidação para agir'
                        ),
                    )

        self.validar_selecao()

        self.selection_label.setText(
            self.selection_label.text()
            + f' {blocked} grupos sem seleção automática; '
            'consulte os motivos nos grupos.'
        )

        try:
            audit_event(
                'SMART_MARK_APPLIED',
                selection_id=selection_id,
                analysis_id=persistence['attempt_id'],
                strategy=strategy,
                selected_files=sum(
                    len(item.marked)
                    for item in decisions
                ),
                blocked_groups=blocked,
            )

        except AuditError as error:
            self.selection_label.setText(
                self.selection_label.text()
                + f' AUDITORIA PENDENTE: {error}'
            )

    def validar_selecao(self, changed_item=None, column=0):
        protected = False

        with QSignalBlocker(self.tree):
            for index in range(
                self.tree.topLevelItemCount()
            ):
                parent = self.tree.topLevelItem(index)

                children = [
                    parent.child(i)
                    for i in range(parent.childCount())
                ]

                if self._historical:
                    for child in children:
                        child.setCheckState(
                            0,
                            Qt.CheckState.Unchecked,
                        )
                    continue

                reference = parent.data(
                    0,
                    Qt.ItemDataRole.UserRole + 2,
                )

                if reference is not None:
                    matches = [
                        child
                        for child in children
                        if child.data(
                            0,
                            Qt.ItemDataRole.UserRole,
                        ) == reference
                    ]

                    if len(matches) != 1:
                        for child in children:
                            child.setCheckState(
                                0,
                                Qt.CheckState.Unchecked,
                            )

                        protected = True
                        continue

                    if (
                        matches[0].checkState(0)
                        == Qt.CheckState.Checked
                    ):
                        matches[0].setCheckState(
                            0,
                            Qt.CheckState.Unchecked,
                        )
                        protected = True

                if children and all(
                    child.checkState(0)
                    == Qt.CheckState.Checked
                    for child in children
                ):
                    preserve = (
                        changed_item
                        if changed_item in children
                        else children[-1]
                    )

                    preserve.setCheckState(
                        0,
                        Qt.CheckState.Unchecked,
                    )
                    protected = True

        self.selection_label.setText(
            f'{len(self.obter_arquivos_marcados())} '
            'arquivos marcados para revisão.'
            + (
                ' Referência preservada; '
                'grupos inconsistentes ficam desmarcados.'
                if protected else ''
            )
        )

        self._update_controls()

    def obter_arquivos_marcados(self):
        if self._historical:
            return []
        marked = []
        for index in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(index)
            for child_index in range(parent.childCount()):
                child = parent.child(child_index)
                if child.checkState(0) == Qt.CheckState.Checked:
                    marked.append({
                        'path': child.data(0, Qt.ItemDataRole.UserRole),
                        'item_ui': child, 'pai_ui': parent,
                    })
        return marked

    def processar_alvos(self, alvos, mensagem_sucesso):
        # Guarda também chamadas diretas: backup não habilita o executor destrutivo.
        self.action_notice.setText(ACTION_NOTICE)
        return False

    def executar_exclusao_padrao(self):
        return self.processar_alvos([], '')

    def executar_mesclagem(self):
        return self.processar_alvos([], '')

    def closeEvent(self, event):
        if (self._busy()
                or (self.worker is not None and self.worker.isRunning())
                or (self.history_worker is not None and self.history_worker.isRunning())
                or (self.save_worker is not None and self.save_worker.isRunning())
                or (self.backup_worker is not None and self.backup_worker.isRunning())):
            if self._backup_running:
                self.backup_label.setText(f'Aguarde o backup terminar para fechar a janela. {BACKUP_NOTICE}')
            elif self._save_running:
                self.persistence_label.setText('Aguarde a gravação terminar para fechar a janela.')
            elif self._history_running:
                self.history_status.setText('Aguarde a consulta terminar para fechar a janela.')
            else:
                self.status_label.setText('Aguarde a análise terminar para fechar a janela.')
            event.ignore()
            return

        if not self._allow_report_change():
            event.ignore()
            return
        
        super().closeEvent(event)
