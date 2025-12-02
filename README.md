# BTC_Finder (Go skeleton)

Este repositório contém um esqueleto inicial para migrar o projeto `BTC_Finder` de Python para Go.

Instruções rápidas:

1. Instale Go 1.20+
2. No diretório do repo, rode:

```bash
go build ./...
```

Aviso: este projeto mexe com chaves privadas de Bitcoin — não utilize em endereços que não são de sua propriedade. Use apenas para fins educativos e com endereços sob seu controle.

Nota: o código legado em Python foi removido neste branch. A implementação atual é em Go; os scripts Python e dependências foram excluídos.
# Brute Force Bitcoin Private Key Finder

## Requisitos

- Python 3
- Bibliotecas Python: `ecdsa`, `base58`, `logging`

Para instalar os módulos execute:
```powershell
python -m venv .venv
.\.venv\Scripts\activate.ps1
pip install -r requirements.txt
```

## Configuração
Adicione as informações abaixo no script `brute_force.py`:

```python
BITCOIN_ADDRESS = "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb" # Endereço de busca
MIN_PK_INTERVAL = 0x02 # Intervalo mínimo de chaves privadas em hexadecimal
MAX_PK_INTERVAL = 0x03 # Intervalo máximo de chaves privadas em hexadecimal
THREADS = 1 # Número de threads da CPU utilizados
```

## Logs
Os logs são salvos no arquivo `brute_force.log`.

## Checkpoint
O script trabalha com marcações de checkpoints no arquivo `checkpoint.txt`, sendo que ao executar o script novamente, o mesmo continua a partir do último checkpoint registrado no arquivo .txt.
