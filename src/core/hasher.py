"""
Lógica do funil de verificação:
1. Hash parcial inicial (primeiros KB)
2. Hash SHA-256 completo
3. Comparação byte a byte (filecmp) para confirmação de duplicidade
"""
import hashlib
import filecmp
from typing import List, Dict

class Hasher:
    def __init__(self, chunk_size: int = 65536):
        self.chunk_size = chunk_size

    def compute_sha256(self, file_path: str) -> str:
        """Calcula o hash SHA-256 completo do arquivo."""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None
        
    def compare_byte_to_byte(self, file1: str, file2: str) -> bool:
        """Confirmação byte a byte se dois arquivos são exatamente idênticos."""
        return filecmp.cmp(file1, file2, shallow=False)
    
    def find_duplicates(self, size_grups: Dict[int, List[Dict]]) -> List[List[Dict]]:
        """Recebe os grupos do Scanner, aplica o Hash SHA-256"""
        confirmed_duplicates = []

        for size, files in size_grups.items():
            # Agrupamento Criptográfico Hash
            hash_map: Dict[str, list[Dict]] = {}
            for file_info in files:
                file_hash = self.compute_sha256(file_info['path'])

                if file_hash:
                    file_info['hash'] = file_hash
                    hash_map.setdefault(file_hash, []).append(file_info)

                    for file_hash, hashed_files in hash_map.items():
                        if len(hashed_files) < 2:
                            continue 

                        # lista de subgrupos já verificados byte a byte
                        byte_verified_groups = []

                        for current_file in hashed_files:
                            found_match = False

                            #Compara o arquivo com o arquivo verificado de cada grupo
                            for group in byte_verified_groups:
                                reference_file = group[0]

                                if self.compare_byte_to_byte(current_file['path'], reference_file['path']):
                                    group.append(current_file)
                                    found_match = True
                                    break

                            if not found_match:
                                byte_verified_groups.append([current_file])

                        for group in byte_verified_groups:
                            if len(group) > 1:
                                group.sort(key=lambda x: x['creation_time_ns'])
                                confirmed_duplicates.append(group)

        return confirmed_duplicates        