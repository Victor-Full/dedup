import shutil
from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

try:
    import win32com.client
except ImportError:
    win32com = None

class ActionManager:
    def __init__(self, backup_dir: str, logger: Optional[logging.Logger] = None):
        self.backup_dir = Path(backup_dir)
        self.logger = logger or logging.getLogger("dedup_audit")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def _generate_safe_backup_path(self, original_path: Path) -> Path:
        """
        Recria a árvore de diretórios original dentro do backup para evitar colisões.
        """
        relative_parts = original_path.parts[1:]
        dest_dir = self.backup_dir.joinpath(*relative_parts[:-1])
        dest_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"{original_path.stem}_{timestamp}{original_path.suffix}"
        return dest_dir / safe_name
    
    def backup_file(self, file_path: Path) -> Path:
        """Copia arquivo para o diretório de backup preservando metadados."""
        dest_path = self._generate_safe_backup_path(file_path)
        shutil.copy2(file_path, dest_path)
        return dest_path

    def _create_windowas_shortcut(self, location_path: Path, target_path: Path) -> bool:
        """Cria um atalho (.lnk) na localização especificada apontando para o alvo."""
        if not win32com:
            self.logger.error("Biblioteca pywin32 não instalada. Atalho cancelado.")
            return False

        try:
            shell = win32com.client.Dispatch("wscript.Shell")
            lnk_path = location_path.with_suffix('.lnk')
            shortcut = shell.CreateShortCut(str(lnk_path))
            shortcut.Targetpath = str(target_path)
            shortcut.WorkingDirectory = str(target_path.parent)
            shortcut.save()
            return True
        except Exception as e:
            self.logger.error(f"FALHA ao criar atalho em {location_path}: {e}")
            return False

    def replace_with_shortcut(self, duplicate_path: Path, original_path: Path) -> bool:
        """
        O Fluxo Completo:
        1. Confirma se o duplicado existe.
        2. Faz backup para a quarentena.
        3. Valida a integridade do backup (Tamanho exato).
        4. Exclui a duplicata da origem.
        5. Cria o atalho apontando para o original que foi preservado noutro setor.
        """
        try:
            if not duplicate_path.exists():
                self.logger.error(f"FALHA ficheiro origianl desapareceu -> {duplicate_path}")
                return False
            dest = self.backup_file(duplicate_path)

            if not dest.exists() or dest.stat().st_size != duplicate_path.stat().st_size:
                self.logger.error(f"FALHA DE INTEGRIDADE Backup falhou. Eliminação abortada -> {duplicate_path}")
                return False

            self.logger.info(f"BACKUP VALIDADO {duplicate_path} -> {dest}")

            duplicate_path.unlink()
            self.logger.info(f"ELIMINADO DA ORIGEM {duplicate_path}")

            sucesso_atalho = self._create_windowas_shortcut(duplicate_path, target_path=original_path)

            if sucesso_atalho:
                self.logger.info(f"ATALHO CRIADO em {duplicate_path.parent} a apontar para {original_path}")
                
            return True

        except Exception as e:
            self.logger.error(f"ERRO CRÍTICO no replace_with_shortcut {duplicate_path}: {e}")
            return False