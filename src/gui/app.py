import sys
from pathlib import Path
from datetime import datetime
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QTreeWidget, QTreeWidgetItem, QHeaderView, QFileDialog, 
    QMessageBox, QListWidget, QFrame, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

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
        self.setWindowTitle("Dedup v1 - Monitor e Deduplicação")
        self.resize(1150, 750)
        self.setStyleSheet("background-color: #f4f6f9;")
        
        self.action_manager = ActionManager(backup_dir="Backup_Quarentena")
        self.setup_ui()

    def setup_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. CABEÇALHO INSTITUCIONAL
        header = QFrame()
        header.setStyleSheet("background-color: #002244; border-bottom: 4px solid #FDB913;")
        header.setFixedHeight(80)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 0, 20, 0)
        
        title_box = QVBoxLayout()
        title = QLabel("Dedup - Auditoria de Ficheiros Duplicados")
        title.setStyleSheet("color: #ffffff; font-size: 22px; font-weight: bold; border: none;")
        subtitle = QLabel("Mapeamento Seguro e Limpeza de Espaço em Servidores de Rede")
        subtitle.setStyleSheet("color: #cbd5e1; font-size: 12px; border: none;")
        
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header_layout.addLayout(title_box)
        
        main_layout.addWidget(header)

        # CONTEÚDO PRINCIPAL
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(15)

        # 2. SELEÇÃO MÚLTIPLA DE PASTAS
        folder_layout = QHBoxLayout()
        
        self.list_folders = QListWidget()
        self.list_folders.setFixedHeight(80)
        self.list_folders.setStyleSheet("background-color: white; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 13px;")
        
        btn_folder_layout = QVBoxLayout()
        self.btn_add_folder = QPushButton("➕ Adicionar Pasta")
        self.btn_add_folder.setStyleSheet("QPushButton { background-color: #ffffff; border: 1px solid #cbd5e1; padding: 8px; border-radius: 4px;} QPushButton:hover {background-color: #e2e8f0;}")
        self.btn_add_folder.clicked.connect(self.adicionar_diretorio)
        
        self.btn_remove_folder = QPushButton("❌ Remover Pasta")
        self.btn_remove_folder.setStyleSheet("QPushButton { background-color: #ffffff; border: 1px solid #cbd5e1; padding: 8px; border-radius: 4px;} QPushButton:hover {background-color: #fee2e2;}")
        self.btn_remove_folder.clicked.connect(self.remover_diretorio)

        self.btn_start_scan = QPushButton("🔍 1. Iniciar Análise")
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
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.setStyleSheet("QTreeWidget { font-size: 14px; border: 1px solid #cbd5e1; background-color: white;} QTreeWidget::item { padding: 5px; }")
        self.tree.itemChanged.connect(self.validar_selecao)
        content_layout.addWidget(self.tree)

        # 4. RODAPÉ DE AÇÕES (Menu Suspenso e Mesclagem)
        action_layout = QHBoxLayout()
        
        # O Botão de Seleção Inteligente (Com Menu Suspenso)
        self.btn_smart_select = QPushButton("⚡ Seleção Inteligente ▾")
        self.btn_smart_select.setStyleSheet("QPushButton { background-color: #ffffff; border: 2px solid #FDB913; color: #002244; font-weight: bold; padding: 12px; border-radius: 4px;} QPushButton:hover {background-color: #fff9e6;} QPushButton::menu-indicator { image: none; }")
        self.btn_smart_select.setEnabled(False)
        
        # Configurando as opções do Menu Suspenso (Smart Mark)
        menu_selecao = QMenu(self)
        menu_selecao.setStyleSheet("QMenu { background-color: white; border: 1px solid #cbd5e1; font-size: 14px; } QMenu::item { padding: 8px 24px; } QMenu::item:selected { background-color: #f1f5f9; color: #002244; font-weight: bold; }")
        
        acao_antigos = menu_selecao.addAction("🟢 Marcar Mais Antigos (Preservar o Mais Novo)")
        acao_novos = menu_selecao.addAction("🔵 Marcar Mais Novos (Preservar o Mais Antigo)")
        menu_selecao.addSeparator()
        acao_limpar = menu_selecao.addAction("⚪ Limpar Seleção (Desmarcar Tudo)")

        # Conectando as ações à nossa nova função central
        acao_antigos.triggered.connect(lambda: self.aplicar_smart_mark("antigos"))
        acao_novos.triggered.connect(lambda: self.aplicar_smart_mark("novos"))
        acao_limpar.triggered.connect(lambda: self.aplicar_smart_mark("limpar"))
        
        # Atrela o menu ao botão
        self.btn_smart_select.setMenu(menu_selecao)

        # Botão de Mesclar
        self.btn_merge = QPushButton("📁 2. Mesclar em uma 3ª Pasta")
        self.btn_merge.setStyleSheet("QPushButton { background-color: #eab308; color: #ffffff; padding: 12px; font-weight: bold; border-radius: 4px;} QPushButton:disabled {background-color: #fef08a;} QPushButton:hover:!disabled {background-color: #ca8a04;}")
        self.btn_merge.setEnabled(False)
        self.btn_merge.clicked.connect(self.executar_mesclagem)
        
        # Botão de Excluir Padrão
        self.btn_delete = QPushButton("🗑️ 3. Quarentena e Eliminar")
        self.btn_delete.setStyleSheet("QPushButton { background-color: #d32f2f; color: white; padding: 12px; font-weight: bold; border-radius: 4px;} QPushButton:disabled {background-color: #fca5a5;} QPushButton:hover:!disabled {background-color: #b71c1c;}")
        self.btn_delete.setEnabled(False)
        self.btn_delete.clicked.connect(self.executar_exclusao_padrao)
        
        action_layout.addWidget(self.btn_smart_select)
        action_layout.addStretch()
        action_layout.addWidget(self.btn_merge)
        action_layout.addWidget(self.btn_delete)
        
        content_layout.addLayout(action_layout)
        main_layout.addLayout(content_layout)

    # --- MÉTODOS DE CONTROLE DA LISTA ---
    def adicionar_diretorio(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Selecione a pasta do Setor")
        if dir_path:
            items = [self.list_folders.item(x).text() for x in range(self.list_folders.count())]
            if dir_path not in items:
                self.list_folders.addItem(dir_path)
            self.btn_start_scan.setEnabled(self.list_folders.count() > 0)

    def remover_diretorio(self):
        selected = self.list_folders.selectedItems()
        for item in selected:
            self.list_folders.takeItem(self.list_folders.row(item))
        self.btn_start_scan.setEnabled(self.list_folders.count() > 0)

    # --- VARREDURA E RENDERIZAÇÃO ---
    def iniciar_varredura(self):
        target_dirs = [self.list_folders.item(i).text() for i in range(self.list_folders.count())]
        self.btn_start_scan.setEnabled(False)
        self.btn_smart_select.setEnabled(False)
        self.tree.clear()

        self.worker = ScanWorker(target_dirs)
        self.worker.progress.connect(lambda msg: self.status_label.setText(msg))
        self.worker.error.connect(lambda msg: self.status_label.setText(f"Erro: {msg}"))
        self.worker.finished.connect(self.popular_tabela)
        self.worker.start()

    def popular_tabela(self, duplicates_list):
        self.status_label.setText(f"Análise concluída: {len(duplicates_list)} grupos detetados.")
        self.btn_start_scan.setEnabled(True)
        if duplicates_list: self.btn_smart_select.setEnabled(True)

        for grupo in duplicates_list:
            hash_str = grupo[0]['hash'][:16] + "..."
            tamanho = grupo[0]['path'].stat().st_size
            tamanho_fmt = f"{tamanho / 1024.0:.2f} KB" if tamanho < 1048576 else f"{tamanho / 1048576.0:.2f} MB"
            
            item_pai = QTreeWidgetItem(self.tree, [f"Grupo Hash: {hash_str}", tamanho_fmt, "-", f"{len(grupo)} Ficheiros"])
            item_pai.setBackground(0, Qt.GlobalColor.lightGray)
            item_pai.setExpanded(True)

            for idx, arquivo in enumerate(grupo):
                path_obj = arquivo['path']
                data_criacao = datetime.fromtimestamp(arquivo['creation_time_ns'] / 1e9).strftime("%d/%m/%Y %H:%M:%S")
                
                if idx == 0: status = "Mais Antigo"
                elif idx == len(grupo) - 1: status = "Mais Novo"
                else: status = "Intermediário"
                
                item_filho = QTreeWidgetItem(item_pai, [str(path_obj), tamanho_fmt, data_criacao, status])
                item_filho.setData(0, Qt.ItemDataRole.UserRole, path_obj)
                item_filho.setFlags(item_filho.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item_filho.setCheckState(0, Qt.CheckState.Unchecked)

    # --- LÓGICA DE NEGÓCIO: SMART MARK ---
    def aplicar_smart_mark(self, criterio: str):
        """Aplica a regra selecionada no menu suspenso sem travar a interface."""
        self.tree.itemChanged.disconnect(self.validar_selecao)
        
        for index_pai in range(self.tree.topLevelItemCount()):
            item_pai = self.tree.topLevelItem(index_pai)
            arquivos_no_grupo = item_pai.childCount()
            
            for index_filho in range(arquivos_no_grupo):
                item_filho = item_pai.child(index_filho)
                
                if criterio == "limpar":
                    estado = Qt.CheckState.Unchecked
                elif criterio == "antigos":
                    # Marca todos, MENOS o último (que é o Mais Novo)
                    estado = Qt.CheckState.Checked if index_filho < arquivos_no_grupo - 1 else Qt.CheckState.Unchecked
                elif criterio == "novos":
                    # Marca todos, MENOS o primeiro (que é o Mais Antigo / Original)
                    estado = Qt.CheckState.Checked if index_filho > 0 else Qt.CheckState.Unchecked
                
                item_filho.setCheckState(0, estado)
                    
        self.tree.itemChanged.connect(self.validar_selecao)
        self.validar_selecao()

    def validar_selecao(self):
        alvos = self.obter_arquivos_marcados()
        if alvos:
            self.btn_merge.setEnabled(True)
            self.btn_delete.setEnabled(True)
            self.btn_merge.setText(f"📁 2. Mesclar em 3ª Pasta ({len(alvos)})")
            self.btn_delete.setText(f"🗑️ 3. Quarentena e Eliminar ({len(alvos)})")
        else:
            self.btn_merge.setEnabled(False)
            self.btn_delete.setEnabled(False)
            self.btn_merge.setText("📁 2. Mesclar em 3ª Pasta")
            self.btn_delete.setText("🗑️ 3. Quarentena e Eliminar")

    def obter_arquivos_marcados(self):
        marcados = []
        for index_pai in range(self.tree.topLevelItemCount()):
            item_pai = self.tree.topLevelItem(index_pai)
            arquivos_no_grupo = item_pai.childCount()
            marcados_neste_grupo = 0
            
            for index_filho in range(arquivos_no_grupo):
                item_filho = item_pai.child(index_filho)
                if item_filho.checkState(0) == Qt.CheckState.Checked:
                    marcados.append({"path": item_filho.data(0, Qt.ItemDataRole.UserRole), "item_ui": item_filho, "pai_ui": item_pai})
                    marcados_neste_grupo += 1
                    
            if marcados_neste_grupo == arquivos_no_grupo:
                QMessageBox.warning(self, "Ação Protegida", "Não pode apagar/mesclar TODOS os ficheiros do grupo. Deixamos 1 desmarcado para preservar a informação original.")
                item_pai.child(arquivos_no_grupo - 1).setCheckState(0, Qt.CheckState.Unchecked)
                return self.obter_arquivos_marcados()

        return marcados

    # --- AÇÕES FINAIS (MESCLAR & EXCLUIR) ---
    def processar_alvos(self, alvos, mensagem_sucesso):
        """Função genérica que executa a exclusão de fato usando o ActionManager."""
        sucessos = 0
        for alvo in alvos:
            # Aqui a regra de ouro se aplica: O backend SÓ APAGA se a cópia (backup/mesclagem) for 100% igual
            if self.action_manager.delete_duplicate(alvo["path"]):
                sucessos += 1
                alvo["pai_ui"].removeChild(alvo["item_ui"])
                if alvo["pai_ui"].childCount() < 2:
                    self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(alvo["pai_ui"]))
        
        QMessageBox.information(self, "Operação Concluída", f"{sucessos} ficheiros processados com sucesso.\n{mensagem_sucesso}")
        self.validar_selecao()

    def executar_exclusao_padrao(self):
        alvos = self.obter_arquivos_marcados()
        if not alvos: return
        resposta = QMessageBox.question(self, "Confirmação", f"Mover {len(alvos)} ficheiro(s) para Quarentena Padrão e eliminar originais?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if resposta == QMessageBox.StandardButton.Yes:
            self.action_manager.backup_dir = Path("Backup_Quarentena") # Garante que vai para quarentena
            self.processar_alvos(alvos, "Foram movidos para a Quarentena Padrão.")

    def executar_mesclagem(self):
        alvos = self.obter_arquivos_marcados()
        if not alvos: return
        
        # 1. Pergunta para onde o utilizador quer Mesclar
        pasta_destino = QFileDialog.getExistingDirectory(self, "Selecione a 3ª Pasta (Destino da Mesclagem)")
        if not pasta_destino: return # Se cancelar, aborta

        resposta = QMessageBox.question(self, "Confirmar Mesclagem", f"Vai consolidar {len(alvos)} ficheiro(s) na pasta:\n{pasta_destino}\n\nEles serão apagados dos setores de origem após a cópia segura. Confirma?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if resposta == QMessageBox.StandardButton.Yes:
            # A MÁGICA DA ARQUITETURA: Trocamos o diretório de backup temporariamente.
            # O ActionManager vai aplicar a mesma regra rigorosa (copiar > verificar tamanho > apagar).
            self.action_manager.backup_dir = Path(pasta_destino)
            self.processar_alvos(alvos, f"Foram mesclados com segurança na pasta:\n{pasta_destino}")