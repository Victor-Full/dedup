"""Configuração validada, com caminhos relativos à raiz do projeto.

Carregar não cria diretórios nem testa acesso aos setores. Salvar valida antes
da escrita e substitui o JSON somente depois de concluir o arquivo temporário.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / 'config' / 'settings.json'


class ConfigError(ValueError):
    """Configuração inválida ou falha explícita de leitura/gravação."""


def _config_path(value=None) -> Path:
    value = CONFIG_PATH if value is None else value
    return Path(_path(os.fspath(value), 'config_path'))


def _path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f'{field}: informe um caminho de pasta não vazio.')
    value = value.strip()
    if any(ord(character) < 32 for character in value):
        raise ConfigError(f'{field}: o caminho contém caracteres de controle.')
    path = Path(value)
    if os.name == 'nt' and bool(path.drive) != bool(path.root):
        raise ConfigError(f'{field}: use um caminho absoluto completo ou relativo ao projeto.')
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    # Normalização lexical: não acessa rede/disco para consultar essas pastas.
    return os.path.normpath(str(path))


def _paths(value: Any, field: str) -> list:
    if not isinstance(value, list):
        raise ConfigError(f'{field}: informe uma lista de caminhos.')
    return list(dict.fromkeys(_path(item, field) for item in value))


def _filters(value: Any, field: str) -> Optional[list]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ConfigError(f'{field}: use null para os padrões ou uma lista de filtros.')
    normalized = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f'{field}: os filtros devem ser textos não vazios.')
        item = item.strip().lower()
        if any(character in item for character in '/\\:') or any(
            ord(character) < 32 for character in item
        ):
            raise ConfigError(f'{field}: informe nomes ou extensões, sem caminhos.')
        if field == 'ignored_exts':
            if (
                not item.startswith('.') or len(item) < 2
                or '.' in item[1:] or any(character.isspace() for character in item)
            ):
                raise ConfigError(f'{field}: informe extensões simples com ponto, como .tmp.')
        elif item in ('.', '..'):
            raise ConfigError(f'{field}: use nomes de diretórios, sem . ou ...')
        if item not in normalized:
            normalized.append(item)
    return normalized


def validate_config(config_data: Dict[str, Any]) -> Dict[str, Any]:
    """Retorna uma nova configuração normalizada, sem efeitos no disco.

    null nos filtros usa os padrões do Scanner; [] desativa o filtro de nomes
    ou extensões correspondente. O backup entra sempre nos caminhos excluídos.
    Não substitui a validação operacional de backup/permissões do executor.
    """
    if not isinstance(config_data, dict):
        raise ConfigError('A configuração deve ser um objeto JSON.')
    defaults = {
        'monitored_paths': [],
        'backup_path': str(PROJECT_ROOT / 'Backup_Quarentena'),
        'min_file_size_bytes': 1,
        'chunk_size_bytes': 65536,
        'excluded_paths': [],
        'ignored_dirs': None,
        'ignored_exts': None,
    }
    unknown = set(config_data) - set(defaults)
    if unknown:
        names = ', '.join(sorted(map(str, unknown)))
        raise ConfigError(f'Campos de configuração desconhecidos: {names}.')
    config = {**defaults, **config_data}
    for field, minimum in (('min_file_size_bytes', 0), ('chunk_size_bytes', 1)):
        value = config[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ConfigError(f'{field}: informe um inteiro maior ou igual a {minimum}.')
    config['monitored_paths'] = _paths(config['monitored_paths'], 'monitored_paths')
    config['backup_path'] = _path(config['backup_path'], 'backup_path')
    config['excluded_paths'] = _paths(config['excluded_paths'], 'excluded_paths')
    for field in ('ignored_dirs', 'ignored_exts'):
        config[field] = _filters(config[field], field)

    backup = os.path.normcase(config['backup_path'])
    for monitored in config['monitored_paths']:
        key = os.path.normcase(monitored)
        if key == backup or key.startswith(backup.rstrip(os.sep) + os.sep):
            raise ConfigError('Uma pasta monitorada não pode ser o backup nem estar dentro dele.')
    if backup not in {os.path.normcase(item) for item in config['excluded_paths']}:
        config['excluded_paths'].append(config['backup_path'])
    try:
        # Detecta textos não representáveis antes de qualquer escrita.
        json.dumps(config, ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError) as error:
        raise ConfigError(f'A configuração não pode ser gravada como JSON UTF-8: {error}') from error
    return config


def _unique_object(pairs) -> Dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError(f'Campo JSON repetido: {key}.')
        result[key] = value
    return result


def _reject_constant(value):
    raise ConfigError(f'Valor não permitido em JSON: {value}.')


def load_config(config_path=None) -> Dict[str, Any]:
    """Lê o JSON; somente a ausência do arquivo usa os padrões sem gravar.

    Erros de acesso, JSON malformado e valores inválidos levantam ConfigError.
    Caminhos relativos, inclusive de um config_path alternativo, usam a raiz
    do projeto como base, independentemente do diretório de execução.
    """
    path = _config_path(config_path)
    try:
        with path.open('r', encoding='utf-8-sig') as stream:
            data = json.load(
                stream, object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
    except FileNotFoundError:
        return validate_config({})
    except (OSError, UnicodeError, ValueError) as error:
        raise ConfigError(f'Não foi possível ler a configuração {path}: {error}') from error
    try:
        return validate_config(data)
    except ConfigError as error:
        raise ConfigError(f'Configuração inválida em {path}: {error}') from error


def save_config(config_data: Dict[str, Any], config_path=None) -> None:
    """Valida e grava em temporário no mesmo diretório, depois substitui o JSON.

    Falhas anteriores à substituição preservam o arquivo anterior. Não fornece
    controle de concorrência entre vários editores/processos nem garantia
    absoluta de durabilidade em caso de falha do armazenamento.
    """
    config = validate_config(config_data)
    payload = json.dumps(config, indent=4, ensure_ascii=False, allow_nan=False) + '\n'
    path = _config_path(config_path)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', newline='\n',
            dir=path.parent, prefix=f'.{path.name}.', suffix='.tmp', delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except (OSError, UnicodeError) as error:
        message = f'Não foi possível salvar a configuração {path}: {error}'
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                message += f'. Temporário não removido: {temporary}: {cleanup_error}'
        raise ConfigError(message) from error
