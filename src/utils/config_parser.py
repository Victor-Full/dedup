"""
Leitura e persistência de variáveis de configuração.
Gerencia caminhos das pastas monitoradas, diretórios de backup e preferências.
"""
import json
from pathlib import Path
from typing import Any, Dict

CONFIG_PATH = Path("config/settings.json")

def load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {
            "monitored_paths": [],
            "backup_path": "",
            "min_file_size_bytes": 1,
            "chunk_size_bytes": 65536
        }
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_config(config_data: Dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4, ensure_ascii=False)
