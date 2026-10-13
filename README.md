# Dedup v1

Sistema de auditoria, monitoramento e remoção segura de arquivos duplicados em diretórios e servidores de arquivos com interface gráfica em **PyQt6**.

## 📁 Estrutura do Projeto

```
dedup_v1/
├── src/
│   ├── main.py                 # Ponto de entrada: inicializa a UI PyQt6 e conecta os módulos
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner.py          # Mapeia diretórios e extrai metadados (tamanho, data)
│   │   ├── hasher.py           # Lógica do funil: SHA-256 e comparação byte a byte (filecmp)
│   │   └── action_manager.py   # Executa as ações: copia para backup, deleta e valida
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── app.py              # Janela principal da interface (QMainWindow, navegação)
│   │   ├── views.py            # Telas: Dashboard, Tabela de Revisão, Configurações
│   │   └── components.py       # Botões customizados, cards de métricas, diálogos
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logger.py           # Configuração do módulo logging (auditoria)
│   │   └── config_parser.py    # Leitura de variáveis (caminho das pastas, backup)
├── data/
│   └── relatorios.sqlite       # Banco SQLite local para histórico das varreduras
├── config/
│   └── settings.json           # Arquivo para definir pastas mapeadas (Ex: V:/RH, Z:/TI)
├── logs/
│   └── auditoria_dedup.log     # Logs de segurança: quem apagou, quando, de onde, pra onde foi
├── requirements.txt            # Dependências do projeto (PyQt6)
└── README.md                   # Instruções de execução do projeto
```

## 🚀 Como Executar

1. **Criar e ativar o ambiente virtual:**
   ```bash
   python -m venv venv
   # No Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   ```

2. **Instalar dependências:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Iniciar a aplicação:**
   ```bash
   python src/main.py
   ```
