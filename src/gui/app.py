import sys
from datetime import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QFileDialog, 
    QMessageBox, QListWidget, QAbstractItemView, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# Importando o Core
from core.scanner import Scanner
from core.hasher import Hasher
from core.action_manager import ActionManager

# -------------------------------------------------------------------
# WORKER PARA RODAR EM SEGUNDO PLANO
# -------------------------------------------------------------------
class ScanWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, target_dirs):
        super().__init__()
        self.target_dirs = target_dirs

    def run(self):
        try:
            self.progress.emit("Fase 1/2: Mapeando arquivos por tamanho (Aguarde)...")
            scanner = Scanner(self.target_dirs)
            size_groups = scanner.scan_directory()

            self.progress.emit("Fase 2/2: Cruzando Hashes SHA-256 e validando Byte a Byte...")
            hasher = Hasher()
            duplicates = hasher.find_duplicates(size_groups)

            self.finished.emit(duplicates)
        except Exception as e:
            self.error.emit(str(e))

# -------------------------------------------------------------------
# JANELA ÚNICA DA APLICAÇÃO
# -------------------------------------------------------------------
class DedupApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dedup CGM v1 - Monitor e Deduplicação")
        self.resize(1100, 750)
        self.setStyleSheet("background-color: #f4f6f9;")
        
        self.action_manager = ActionManager(backup_dir="Backup_Quarentena")
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. CABEÇALHO INSTITUCIONAL (Azul PMS e Dourado)
        header = QFrame()
        header.setStyleSheet("background-color: #002244; border-bottom: 4px solid #FDB913;")
        header.setFixedHeight(80)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        title_box = QVBoxLayout()
        title = QLabel("Dedup CGM - Auditoria de Ficheiros Duplicados")
        title.setStyleSheet("color: #ffffff; font-size: 22px; font-weight: bold;")
        subtitle = QLabel("Mapeamento Seguro e Limpeza de Espaço em Servidores de Rede")
        subtitle.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        
        self.status_label = QLabel("Sistema Pronto.")
        self.status_label.setStyleSheet("color: #FDB913; font-size: 14px; font-weight: bold;")
        header_layout.addStretch()
        header_layout.addWidget(self.status_label)
        
        main_layout.addWidget(header)

        # CONTEÚDO PRINCIPAL (Margens internas)
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)

        # 2. SELEÇÃO MÚLTIPLA DE PASTAS
        folder_layout = QHBoxLayout()
        
        self.list_folders = QListWidget()
        self.list_folders.setFixedHeight(80)
        self.list_folders.setStyleSheet("background-color: white; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 13px;")
        
        btn_folder_layout = QVBoxLayout()
        self.btn_add_folder = QPushButton("➕ Adicionar Pasta (Setor)")
        self.btn_add_folder.setStyleSheet("QPushButton { background-color: #ffffff; border: 1px solid #cbd5e1; padding: 8px; border-radius: 4px;} QPushButton:hover {background-color: #e2e8f0;}")
        self.btn_add_folder.clicked.connect(self.adicionar_diretorio)
        
        self.btn_remove_folder = QPushButton("❌ Remover Selecionada")
        self.btn_remove_folder.setStyleSheet("QPushButton { background-color: #ffffff; border: 1px solid #cbd5e1; padding: 8px; border-radius: 4px;} QPushButton:hover {background-color: #fee2e2;}")
        self.btn_remove_folder.clicked.connect(self.remover_diretorio)

        self.btn_start_scan = QPushButton("🔍 1. Iniciar Análise de Rede")
        self.btn_start_scan.setStyleSheet("QPushButton { background-color: #0056b3; color: white; padding: 12px; font-weight: bold; border-radius: 4px;} QPushButton:hover {background-color: #004494;} QPushButton:disabled {background-color: #94a3b8;}")
        self.btn_start_scan.setEnabled(False)
        self.btn_start_scan.clicked.connect(self.iniciar_varredura)

        btn_folder_layout.addWidget(self.btn_add_folder)
        btn_folder_layout.addWidget(self.btn_remove_folder)
        
        folder_layout.addWidget(self.list_folders)
        folder_layout.addLayout(btn_folder_layout)
        folder_layout.addWidget(self.btn_start_scan)
        
        content_layout.addLayout(folder_layout)

        # 3. TABELA DE RESULTADOS
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Ficheiro / Grupo Identificado", "Tamanho", "Data de Criação", "Status (Idade)"])
        # Coluna 0 (Ficheiro) permite redimensionar manualmente com bom tamanho inicial
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(0, 450)
        
        # Colunas 1 e 2 (Tamanho e Data) ajustam automaticamente ao conteúdo
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        # Coluna 3 (Status) preenche o resto do espaço vazio da tela
        self.tree.header().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.tree.setStyleSheet("QTreeWidget { font-size: 14px; border: 1px solid #cbd5e1; background-color: white;}")
        self.tree.itemChanged.connect(self.validar_selecao)
        content_layout.addWidget(self.tree)

        # 4. RODAPÉ DE AÇÕES (Lógica de Apagar Antigos)
        action_layout = QHBoxLayout()
        
        self.btn_auto_select = QPushButton("⚡ Marcar Automático: Mais Antigos")
        self.btn_auto_select.setStyleSheet("QPushButton { background-color: #ffffff; border: 2px solid #FDB913; color: #002244; font-weight: bold; padding: 12px; border-radius: 4px;} QPushButton:hover {background-color: #fff9e6;}")
        self.btn_auto_select.setEnabled(False)
        self.btn_auto_select.clicked.connect(self.selecionar_mais_antigos)
        
        self.btn_action = QPushButton("🗑️ 2. Executar Backup e Eliminar")
        self.btn_action.setStyleSheet("QPushButton { background-color: #d32f2f; color: white; padding: 12px; font-weight: bold; border-radius: 4px;} QPushButton:disabled {background-color: #fca5a5;} QPushButton:hover:!disabled {background-color: #b71c1c;}")
        self.btn_action.setEnabled(False)
        self.btn_action.clicked.connect(self.executar_exclusao)
        
        action_layout.addWidget(self.btn_auto_select)
        action_layout.addStretch()
        action_layout.addWidget(self.btn_action)
        
        content_layout.addLayout(action_layout)
        main_layout.addLayout(content_layout)

    # --- MÉTODOS DE CONTROLE DA LISTA DE PASTAS ---
    def adicionar_diretorio(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Selecione a pasta do Setor")
        if dir_path:
            # Verifica se já não foi adicionada
            items = [self.list_folders.item(x).text() for x in range(self.list_folders.count())]
            if dir_path not in items:
                self.list_folders.addItem(dir_path)
            self.btn_start_scan.setEnabled(self.list_folders.count() > 0)

    def remover_diretorio(self):
        selected_items = self.list_folders.selectedItems()
        if not selected_items: return
        for item in selected_items:
            self.list_folders.takeItem(self.list_folders.row(item))
        self.btn_start_scan.setEnabled(self.list_folders.count() > 0)

    # --- MÉTODOS DE VARREDURA E RENDERIZAÇÃO ---
    def iniciar_varredura(self):
        target_dirs = [self.list_folders.item(i).text() for i in range(self.list_folders.count())]
        
        self.btn_start_scan.setEnabled(False)
        self.btn_add_folder.setEnabled(False)
        self.btn_remove_folder.setEnabled(False)
        self.btn_auto_select.setEnabled(False)
        self.tree.clear()

        self.worker = ScanWorker(target_dirs)
        self.worker.progress.connect(lambda msg: self.status_label.setText(msg))
        self.worker.error.connect(lambda msg: self.status_label.setText(f"Erro: {msg}"))
        self.worker.finished.connect(self.popular_tabela)
        self.worker.start()

    def popular_tabela(self, duplicates_list):
        self.status_label.setText(f"Análise concluída: {len(duplicates_list)} grupos detetados.")
        self.btn_start_scan.setEnabled(True)
        self.btn_add_folder.setEnabled(True)
        self.btn_remove_folder.setEnabled(True)
        
        if duplicates_list:
            self.btn_auto_select.setEnabled(True)

        for grupo in duplicates_list:
            hash_str = grupo[0]['hash'][:16] + "..."
            from pathlib import Path
            tamanho = Path(grupo[0]['path']).stat().st_size
            tamanho_fmt = f"{tamanho / 1024.0:.2f} KB" if tamanho < 1048576 else f"{tamanho / 1048576.0:.2f} MB"
            
            item_pai = QTreeWidgetItem(self.tree, [f"Duplicata (Hash: {hash_str})", tamanho_fmt, "-", f"{len(grupo)} Ficheiros"])
            item_pai.setBackground(0, Qt.GlobalColor.lightGray)
            item_pai.setExpanded(True)

            # O backend (Hasher) já nos entrega a lista ordenada por criação (0 = Mais Antigo, -1 = Mais Novo)
            for idx, arquivo in enumerate(grupo):
                path_obj = arquivo['path']
                data_criacao = datetime.fromtimestamp(arquivo['creation_time_ns'] / 1e9).strftime("%d/%m/%Y %H:%M:%S")
                
                # Destaca visualmente o mais antigo e o mais novo
                if idx == 0:
                    status = "Mais Antigo"
                elif idx == len(grupo) - 1:
                    status = "Mais Novo (Preservar)"
                else:
                    status = "Intermediário"
                
                item_filho = QTreeWidgetItem(item_pai, [str(path_obj), tamanho_fmt, data_criacao, status])
                item_filho.setData(0, Qt.ItemDataRole.UserRole, path_obj)
                item_filho.setToolTip(0, str(path_obj))
                item_filho.setFlags(item_filho.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item_filho.setCheckState(0, Qt.CheckState.Unchecked)

    # --- LÓGICA DE NEGÓCIO: SELEÇÃO E EXCLUSÃO ---
    def selecionar_mais_antigos(self):
        """Marca todos os ficheiros de um grupo, deixando SEMPRE o Mais Novo desmarcado."""
        # Desconecta temporariamente o evento de checagem para não travar a UI atualizando o botão 100x
        self.tree.itemChanged.disconnect(self.validar_selecao)
        
        for index_pai in range(self.tree.topLevelItemCount()):
            item_pai = self.tree.topLevelItem(index_pai)
            arquivos_no_grupo = item_pai.childCount()
            
            for index_filho in range(arquivos_no_grupo):
                item_filho = item_pai.child(index_filho)
                # O último filho (arquivos_no_grupo - 1) é o Mais Novo, deixamos Unchecked.
                if index_filho < arquivos_no_grupo - 1:
                    item_filho.setCheckState(0, Qt.CheckState.Checked)
                else:
                    item_filho.setCheckState(0, Qt.CheckState.Unchecked)
                    
        # Reconecta e valida uma vez só no final
        self.tree.itemChanged.connect(self.validar_selecao)
        self.validar_selecao()

    def validar_selecao(self):
        alvos = self.obter_arquivos_marcados()
        if alvos:
            self.btn_action.setEnabled(True)
            self.btn_action.setText(f"🗑️ 2. Executar Backup e Eliminar ({len(alvos)} ficheiros)")
        else:
            self.btn_action.setEnabled(False)
            self.btn_action.setText("🗑️ 2. Executar Backup e Eliminar")

    def obter_arquivos_marcados(self):
        marcados = []
        for index_pai in range(self.tree.topLevelItemCount()):
            item_pai = self.tree.topLevelItem(index_pai)
            arquivos_no_grupo = item_pai.childCount()
            marcados_neste_grupo = 0
            
            for index_filho in range(arquivos_no_grupo):
                item_filho = item_pai.child(index_filho)
                if item_filho.checkState(0) == Qt.CheckState.Checked:
                    marcados.append({
                        "path": item_filho.data(0, Qt.ItemDataRole.UserRole), 
                        "item_ui": item_filho, 
                        "pai_ui": item_pai
                    })
                    marcados_neste_grupo += 1
                    
            # Segurança máxima: Bloqueia se tentar apagar TUDO do grupo
            if arquivos_no_grupo > 0 and marcados_neste_grupo == arquivos_no_grupo:
                QMessageBox.warning(self, "Ação Protegida", "Não pode apagar todos os ficheiros. O ficheiro mais novo foi desmarcado automaticamente para preservação.")
                # Desmarca o último (Mais Novo) bloqueando sinais para evitar recursão infinita
                self.tree.blockSignals(True)
                item_pai.child(arquivos_no_grupo - 1).setCheckState(0, Qt.CheckState.Unchecked)
                self.tree.blockSignals(False)
                # Recalcula a lista já que desmarcamos um
                return self.obter_arquivos_marcados()

        return marcados

    def executar_exclusao(self):
        alvos = self.obter_arquivos_marcados()
        if not alvos: return

        resposta = QMessageBox.question(
            self, "Confirmação de Ação", 
            f"Vai mover {len(alvos)} ficheiro(s) antigo(s) para a Quarentena e eliminá-los da origem.\nTem a certeza?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if resposta == QMessageBox.StandardButton.Yes:
            sucessos = 0
            for alvo in alvos:
                if self.action_manager.delete_duplicate(alvo["path"]):
                    sucessos += 1
                    alvo["pai_ui"].removeChild(alvo["item_ui"])
                    
                    if alvo["pai_ui"].childCount() < 2:
                        self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(alvo["pai_ui"]))
            
            QMessageBox.information(self, "Concluído", f"{sucessos} ficheiros antigos mesclados/apagados com segurança.\nForam movidos para a Quarentena.")
            self.validar_selecao()