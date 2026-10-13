"""
Executa as ações de deduplicação:
- Criação de backup
- Remoção segura de arquivos duplicados
- Validação pós-ação e registro de auditoria
"""
import shutil
from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

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
        dest_path = self._generate_safe_backup_path(file_path) / file_path.name
        shutil.copy2(file_path, dest_path)
        return dest_path

    def delete_duplicate(self, file_path: Path, make_backup: bool = True) -> bool:
        """
        Executa a eliminação segura. 
        """
        try:
            if not file_path.exists():
                self.logger.error(f"FALHA: O ficheiro original desapareceu antes do processamento -> {file_path}")
                return False
            
            if make_backup:
                dest = self.backup_file(file_path)
                if not dest.exists() or dest.stat().st_size != file_path.stat().st_size:
                    self.logger.error(f"FALHA DE INTEGRIDADE: Backup corrompido, a eliminação foi abortada -> {file_path}")
                    return False
                
                self.logger.info(f"BACKUP VALIDADO: {file_path} -> {dest}")

            file_path.unlink()
            self.logger.info(f"ELIMINADO DA ORIGEM: {file_path}")
            return True
        
        except Exception as e:
            self.logger.error(f"ERRO CRÍTICO ao processar {file_path}: {e}")
            return False