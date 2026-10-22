"""Interface de análise. Ações destrutivas aguardam o executor seguro."""

from PyQt6.QtCore import Qt, QThread, QSignalBlocker, QDateTime, QTimeZone, pyqtSignal
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QFileDialog,
    QListWidget, QFrame, QMenu, QTabWidget,
)

from core.scanner import Scanner
from core.hasher import Hasher
from utils.config_parser import ConfigError, load_config, validate_config


REASONS = {
    'FILE_CHANGED': 'Arquivo alterado durante a análise',
    'PERMISSION_DENIED': 'Acesso negado',
    'SHARING_VIOLATION': 'Arquivo em uso ou compartilhamento bloqueado',
    'NOT_FOUND': 'Arquivo ou pasta não encontrado',
    'NOT_A_DIRECTORY': 'O caminho não é uma pasta',
    'IO_ERROR': 'Falha de leitura ou do armazenamento',
    'UNSUPPORTED_FILE': 'Arquivo substituído por link ou tipo não suportado',
}
SKIP_REASONS = {
    'EXCLUDED_PATH': 'Caminho excluído da análise',
    'LINK_OR_REPARSE_POINT': 'Link ou ponto de redirecionamento',
    'DIRECTORY_FILTER': 'Nome de pasta filtrado',
    'FILE_FILTER': 'Nome ou extensão filtrada',
    'LINK_OR_SPECIAL_FILE': 'Link ou arquivo especial',
    'HIDDEN_OR_SYSTEM': 'Arquivo ou pasta oculto/de sistema',
}
STAGES = {
    'root': 'Raiz', 'directory': 'Diretório', 'walk': 'Enumeração',
    'file': 'Metadados', 'exclude': 'Exclusão do escopo',
    'hash': 'SHA-256', 'compare': 'Comparação de bytes', 'recheck': 'Revalidação',
}
ACTION_NOTICE = (
    'Remoção e mesclagem indisponíveis: aguardam validação do fluxo de backup, '
    'referência preservada, atalho e recuperação.'
)


class ScanWorker(QThread):
    """Entrega dados observados sem substituir o sinal finished do QThread."""

    progress = pyqtSignal(str)
    result_ready = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = validate_config(config)

    def run(self):
        try:
            self.progress.emit('Fase 1/2: inventariando arquivos e registrando falhas...')
            config = self.config
            scanner = Scanner(
                config['monitored_paths'],
                ignored_dirs=config['ignored_dirs'],
                ignored_exts=config['ignored_exts'],
                excluded_paths=config['excluded_paths'],
                min_file_size_bytes=config['min_file_size_bytes'],
            )
            size_groups = scanner.scan_directory()
            self.progress.emit(
                'Fase 2/2: SHA-256 e comparação de bytes; '
                'falhas dos candidatos terão uma nova tentativa ao final...'
            )
            hasher = Hasher(chunk_size=config['chunk_size_bytes'])
            duplicates = hasher.find_duplicates(size_groups)
            self.result_ready.emit({
                'duplicates': duplicates,
                'inventory': scanner.inventory,
                'scan_errors': scanner.errors,
                'skipped': scanner.skipped,
                'records': hasher.records,
                'comparison_errors': hasher.errors,
                'pending_files': hasher.pending_files,
                'recovered_files': hasher.recovered_files,
                'summary': hasher.summary,
            })
        except Exception as error:
            self.error.emit(f'{type(error).__name__}: {error}')


class DedupApp(QMainWindow):
    def __init__(self, config=None):
        super().__init__()
        self.setWindowTitle('Dedup v1 - Análise de arquivos duplicados')
        self.resize(1250, 800)
        self.setStyleSheet('background-color: #f4f6f9;')
        self.worker = None
        self._scan_running = False
        self.last_report = None
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
        self.tabs = QTabWidget()
        self.tree = self._table([
            'Arquivo / grupo', 'Tamanho (bytes)', 'Criação', 'Modificação', 'Situação',
        ])
        self.tree.itemChanged.connect(self.validar_selecao)
        self.inventory_tree = self._table([
            'Nome', 'Local no disco', 'Tamanho (bytes)', 'Criação', 'Modificação', 'Situação',
        ])
        self.issues_tree = self._table([
            'Arquivo / local', 'Etapa', 'Motivo', 'Tentativa', 'Resultado final', 'Detalhes', 'Instante (UTC)',
        ])
        self.skipped_tree = self._table(['Arquivo / local', 'Motivo do filtro'])
        self.tabs.addTab(self.tree, 'Duplicatas observadas')
        self.tabs.addTab(self.inventory_tree, 'Inventário')
        self.tabs.addTab(self.issues_tree, 'Pendências e ocorrências')
        self.tabs.addTab(self.skipped_tree, 'Ignorados')
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
        menu.addAction('Marcar demais; preservar o mais novo por criação').triggered.connect(
            lambda: self.aplicar_smart_mark('antigos')
        )
        menu.addAction('Marcar demais; preservar o mais antigo por criação').triggered.connect(
            lambda: self.aplicar_smart_mark('novos')
        )
        menu.addAction('Limpar seleção').triggered.connect(lambda: self.aplicar_smart_mark('limpar'))
        self.btn_smart_select.setMenu(menu)
        actions.addWidget(self.btn_smart_select)
        actions.addStretch()
        self.btn_merge = QPushButton('2. Mesclar pastas')
        self.btn_merge.clicked.connect(self.executar_mesclagem)
        self.btn_delete = QPushButton('3. Backup e remoção')
        self.btn_delete.clicked.connect(self.executar_exclusao_padrao)
        actions.addWidget(self.btn_merge)
        actions.addWidget(self.btn_delete)
        content.addLayout(actions)
        self.selection_label = QLabel('0 arquivos marcados para revisão.')
        content.addWidget(self.selection_label)
        self.action_notice = QLabel(ACTION_NOTICE)
        self.action_notice.setWordWrap(True)
        content.addWidget(self.action_notice)
        main_layout.addLayout(content)

    def _update_controls(self):
        available = not self._scan_running and self.config is not None
        self.list_folders.setEnabled(available)
        self.btn_add_folder.setEnabled(available)
        self.btn_remove_folder.setEnabled(available)
        self.btn_start_scan.setEnabled(available and self.list_folders.count() > 0)
        self.btn_smart_select.setEnabled(available and self.tree.topLevelItemCount() > 0)
        self.tree.setEnabled(not self._scan_running)
        # A seleção é revisão; nenhum caminho da janela pode chamar o executor legado.
        self.btn_merge.setEnabled(False)
        self.btn_delete.setEnabled(False)
        self.btn_merge.setToolTip(ACTION_NOTICE)
        self.btn_delete.setToolTip(ACTION_NOTICE)

    def adicionar_diretorio(self):
        if self._scan_running or self.config is None:
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
        if self._scan_running or self.config is None:
            return
        for item in self.list_folders.selectedItems():
            self.list_folders.takeItem(self.list_folders.row(item))
        self._update_controls()

    def iniciar_varredura(self):
        if self._scan_running or self.config is None:
            return
        paths = [self.list_folders.item(i).text() for i in range(self.list_folders.count())]
        if not paths:
            self.status_label.setText('Adicione pelo menos uma pasta para analisar.')
            return
        try:
            config = validate_config({**self.config, 'monitored_paths': paths})
            worker = ScanWorker(config, self)
        except ConfigError as error:
            self.status_label.setText(f'Configuração inválida: {error}')
            return
        self.config = config
        self.last_report = None
        for tree in (self.tree, self.inventory_tree, self.issues_tree, self.skipped_tree):
            tree.clear()
        self.tabs.setTabText(0, 'Duplicatas observadas')
        self.tabs.setTabText(1, 'Inventário')
        self.tabs.setTabText(2, 'Pendências e ocorrências')
        self.tabs.setTabText(3, 'Ignorados')
        self.validar_selecao()
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
                    child.setCheckState(0, Qt.CheckState.Unchecked)
        self.validar_selecao()

    def apresentar_relatorio(self, report):
        self.last_report = report
        self.popular_tabela(report['duplicates'])
        records = {str(item['path']): item for item in report['records']}
        states = {
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
            self._add_issue(error, '1 (inventário)', 'Pendente; nova tentativa ainda não integrada')
        for error in report['comparison_errors']:
            record = records.get(str(error['path']), {})
            outcome = ('Pendente após nova tentativa' if record.get('analysis_status') == 'FAILED'
                       else 'Recuperado na nova tentativa')
            self._add_issue(error, str(error['attempt']), outcome)
        self.skipped_tree.clear()
        for skipped in report['skipped']:
            item = QTreeWidgetItem(self.skipped_tree, [
                str(skipped['path']), SKIP_REASONS.get(skipped['reason'], skipped['reason']),
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, dict(skipped))
        pending = len(report['pending_files'])
        scan_failures = len(report['scan_errors'])
        conclusion = 'Análise concluída com pendências' if pending or scan_failures else 'Análise concluída'
        self.status_label.setText(
            f"{conclusion}: {len(report['inventory'])} arquivos inventariados; "
            f"{len(report['duplicates'])} grupos de igualdade observada; "
            f"{len(report['recovered_files'])} arquivos recuperados na nova tentativa; "
            f'{pending} arquivos pendentes na comparação e {scan_failures} '
            'ocorrências pendentes no inventário.'
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

    def aplicar_smart_mark(self, criterio):
        if self._scan_running or criterio not in ('antigos', 'novos', 'limpar'):
            return
        unavailable = 0
        with QSignalBlocker(self.tree):
            for index in range(self.tree.topLevelItemCount()):
                parent = self.tree.topLevelItem(index)
                children = [parent.child(i) for i in range(parent.childCount())]
                dated = [child for child in children
                         if child.data(0, Qt.ItemDataRole.UserRole + 1).get('creation_time_ns') is not None]
                preserve = None
                if criterio != 'limpar':
                    if len(dated) != len(children):
                        unavailable += 1
                    elif children:
                        ordered = sorted(children, key=lambda child: (
                            child.data(0, Qt.ItemDataRole.UserRole + 1)['creation_time_ns'],
                            str(child.data(0, Qt.ItemDataRole.UserRole)),
                        ))
                        preserve = ordered[-1] if criterio == 'antigos' else ordered[0]
                for child in children:
                    marked = preserve is not None and child is not preserve
                    child.setCheckState(0, Qt.CheckState.Checked if marked else Qt.CheckState.Unchecked)
        self.validar_selecao()
        if unavailable:
            self.selection_label.setText(
                self.selection_label.text() + f' {unavailable} grupos sem todas as datas de criação: desmarcados.'
            )

    def validar_selecao(self, changed_item=None, column=0):
        protected = False
        with QSignalBlocker(self.tree):
            for index in range(self.tree.topLevelItemCount()):
                parent = self.tree.topLevelItem(index)
                children = [parent.child(i) for i in range(parent.childCount())]
                if children and all(child.checkState(0) == Qt.CheckState.Checked for child in children):
                    preserve = changed_item if changed_item in children else children[-1]
                    preserve.setCheckState(0, Qt.CheckState.Unchecked)
                    protected = True
        self.selection_label.setText(
            f'{len(self.obter_arquivos_marcados())} arquivos marcados para revisão.'
            + (' Mantido um arquivo desmarcado por grupo.' if protected else '')
        )
        self._update_controls()

    def obter_arquivos_marcados(self):
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
        # Guarda também chamadas diretas: não importa nem instancia ActionManager.
        self.action_notice.setText(ACTION_NOTICE)
        return False

    def executar_exclusao_padrao(self):
        return self.processar_alvos([], '')

    def executar_mesclagem(self):
        return self.processar_alvos([], '')

    def closeEvent(self, event):
        if self._scan_running or (self.worker is not None and self.worker.isRunning()):
            self.status_label.setText('Aguarde a análise terminar para fechar a janela.')
            event.ignore()
            return
        super().closeEvent(event)
