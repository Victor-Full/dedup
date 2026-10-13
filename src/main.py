"""
Ponto de entrada da aplicação Dedup v1 (PyQt6).
Inicializa o logger, carrega configurações e executa a aplicação gráfica.
"""
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication

# Adiciona src ao sys.path
sys.path.insert(0, str(Path(__file__).parent))

from gui.app import DedupApp
from utils.logger import setup_logger
from utils.config_parser import load_config

def main():
    logger = setup_logger()
    logger.info("Iniciando aplicação Dedup v1 (PyQt6)...")

    config = load_config()
    logger.info(f"Configurações carregadas: {len(config.get('monitored_paths', []))} caminhos monitorados.")

    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Dedup v1")

    window = DedupApp()
    window.show()

    sys.exit(qt_app.exec())

if __name__ == "__main__":
    main()
