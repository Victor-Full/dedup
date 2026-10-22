"""
Ponto de entrada da aplicação Dedup v1 (PyQt6).
Inicializa o logger, carrega configurações e executa a aplicação gráfica.
"""
import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QMessageBox

# Adiciona src ao sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gui.app import DedupApp
from utils.logger import setup_logger
from utils.config_parser import CONFIG_PATH, PROJECT_ROOT, ConfigError, load_config

def main() -> int:
    """Inicializa a janela ou informa a falha, retornando o código de saída."""
    # O QApplication precisa existir para apresentar erros de inicialização.
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Dedup v1")

    log_path = PROJECT_ROOT / "logs" / "auditoria_dedup.log"
    try:
        logger = setup_logger(log_file=str(log_path))
    except OSError as error:
        QMessageBox.critical(
            None,
            "Falha ao iniciar o registro de auditoria",
            f"Não foi possível abrir o registro de auditoria:\n{log_path}\n\n"
            f"Verifique o acesso à pasta e tente novamente.\n\nDetalhes: {error}",
        )
        return 1

    logger.info("Iniciando aplicação Dedup v1 (PyQt6)...")
    try:
        config = load_config()
    except ConfigError as error:
        logger.error("Falha ao carregar a configuração %s: %s", CONFIG_PATH, error)
        QMessageBox.critical(
            None,
            "Configuração inválida ou inacessível",
            f"Não foi possível carregar a configuração:\n{CONFIG_PATH}\n\n"
            f"Corrija o arquivo ou suas permissões e abra o programa novamente.\n\nDetalhes: {error}",
        )
        return 1

    logger.info("Configurações carregadas: %s caminhos monitorados.", len(config['monitored_paths']))
    try:
        window = DedupApp(config=config)
        window.show()
    except Exception as error:
        logger.exception("Falha ao abrir a janela principal.")
        QMessageBox.critical(
            None,
            "Falha ao abrir o Dedup",
            f"Não foi possível abrir a janela principal.\n\n"
            f"Consulte o registro de auditoria:\n{log_path}\n\nDetalhes: {error}",
        )
        return 1

    return qt_app.exec()

if __name__ == "__main__":
    sys.exit(main())
