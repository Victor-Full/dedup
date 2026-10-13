import os
import stat
from pathlib import Path
from typing import Dict, List, Set

class Scanner:
    def __init__(
        self, 
        target_dirs: List[str],
        ignored_dirs: Set[str] = None,
        ignored_exts: Set[str] = None
    ):
        self.target_dirs = target_dirs

        self.target_dirs = target_dirs
        self.ignored_dirs = ignored_dirs or {
            '$recycle.bin', 'windoes', 'system32', '.git',
            'node_modules', 'appdata', '__pycache__'
        }
        self.ignored_exts = ignored_exts or {
            '.tmp', '.sys', '.ini', '.dll', '.log', '.bak', '.cab'
        }

    def scan_directory(self) -> Dict[int, List[Dict]]:
        """
        Mapeia diretórios aplicando filtros agressivos de exclusão ANTES 
        de realizar operações de I/O na rede, otimizando a performance.
        """
        size_map: Dict[int, List[Dict]] = {}
        
        for directory in self.target_dirs:
            dir_path = Path(directory)
            if not dir_path.exists() or not dir_path.is_dir():
                continue

            # Converte para String puro
            dir_str = str(dir_path)

            for root, dirs, files in os.walk(dir_str):
                # Removemos as pastas proibidas da lista 'dirs' ANTES do os.walk tentar abri-las.
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in self.ignored_dirs and not d.startswith('.')
                ]

                for file_name in files:
                    if file_name.startswith('.'):
                        continue

                    _, ext = os.path.splitext(file_name)
                    if ext.lower() in self.ignored_exts:
                        continue

                    file_path = os.path.join(root, file_name)

                    # Extrai metadados do arquivo
                    try:
                        file_stats = os.stat(file_path)

                        if hasattr(file_stats, 'st_file_attributes'):
                            is_hidden = stat.FILE_ATTRIBUTE_HIDDEN
                            is_system = stat.FILE_ATTRIBUTE_SYSTEM
                            if file_stats.st_file_attributes & (is_hidden | is_system):
                                continue
                            
                        size = file_stats.st_size

                        if size > 0:
                            # Monta o dicionário com os dados necessários
                            file_info = {
                                'path': file_path,
                                'creation_time_ns': file_stats.st_ctime_ns,
                                'modified_time_ns': file_stats.st_mtime_ns
                            }
                            size_map.setdefault(size, []).append(file_info)

                    except (PermissionError, FileNotFoundError):
                        continue
        # Retorna apenas grupos com 2 ou mais arquivos com mesmo tamanho
        return {size: files for size, files in size_map.items() if len(files) > 1}