# BTC_Finder - Node-Seed Distributed Architecture

## Overview

A implementação transforma o BTC_Finder em um sistema distribuído onde:
- **Node**: Gerencia ranges de chaves privadas, divide em jobs e distribui para seeds
- **Seed**: Workers remotos que executam bruteforce em paralelo, solicitando jobs ao Node
- **Modo Local**: Execução standalone original (compatível com versão anterior)

## Architecture Components

### 1. Data Models (`internal/models/`)
- `Job`: Representa uma unidade de trabalho (range de chaves)
- `SeedMetrics`: Métricas de velocidade por seed (chaves/segundo)
- `JobProgress`: Estado atual de um job
- `JobStatus`: Enum de estados (pending, assigned, in_progress, completed, failed)

### 2. Persistence Layer (`internal/storage/`)
- Interface `Storage`: Contrato para persistência
- `SQLiteStorage`: Implementação com SQLite
- Tabelas:
  - `jobs`: Jobs com status, range, seed_id, timestamps
  - `seed_registry`: Seeds conectados com métricas
  - `job_history`: Histórico de execução para auditoria

### 3. Authentication (`internal/auth/`)
- `BearerTokenValidator`: Middleware HTTP para validar tokens
- Estratégia: Token bearer simples (configurável via `NODE_TOKEN`)
- Header: `Authorization: Bearer <token>`

### 4. Node Server (`internal/node/`)

#### Endpoints
- `POST /health` - Status do servidor
- `POST /jobs/request` - Seed requisita novo job
- `PATCH /jobs/:id/status` - Seed envia progresso periódico
- `POST /jobs/:id/claim-match` - Seed notifica encontro de chave
- `POST /jobs/:id/complete` - Job completado sem encontro
- `POST /jobs/:id/fail` - Job falhou
- `GET /metrics` - Métricas do node

#### Job Manager (`manager.go`)
- `CreateJobsFromRange(minHex, maxHex, numSeeds)`: Divide range em N jobs iguais
- `RequestJob(seedID)`: Aloca job para seed
- `UpdateJobStatus(jobID, status)`: Persiste progresso
- `OnMatchFound(jobID, privateKey)`: Cancela outros jobs, notifica Telegram

#### Seed Registry (`registry.go`)
- Registra seeds conectados com métricas de velocidade
- Detecta seeds lentos (velocidade < mediana)
- Marca seeds inativos após timeout (5 min sem heartbeat)

### 5. Seed Client (`internal/seed/`)
- `NewClient(seedID, nodeURL, token)`: Cria cliente
- `Start(ctx, workers, targetAddress, ...)`: Loop principal
  1. Requisita job ao Node (com retry exponencial)
  2. Executa bruteforce no range
  3. Envia status periódico (10s)
  4. Ao encontrar: notifica Node e termina
  5. Ao completar: requisita novo job
- `RequestJobWithRetry(maxRetries)`: Implementa backoff exponencial
- `ReportMatch/Progress/Completion/Failure()`: Notificações ao Node

### 6. Bruteforce Runner (`internal/bruteforce/runner.go`)
- Método `StartWithCallback(ctx, onMatch)`: Novo modo que executa callback ao encontrar match
- Mantém compatibilidade com `Start()` para modo local
- Usa workers em paralelo com canais Go
- Checkpoint periódico (5s)

### 7. Notifications (`internal/notifications/`)
- `TelegramNotifier`: Envia alertas via Telegram Bot API
- Disparado quando Node recebe notificação de match
- Payload: `{address, privateKey, seedID, jobID, timestamp}`

## Execution Modes

### 1. Local Mode (Default)
```bash
go run ./cmd/btcfinder/main.go \
  --mode local \
  --min 0x8000 \
  --max 0xffff \
  --workers 8 \
  --address "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY"
```
- Comportamento original
- Sem comunicação de rede
- Checkpoint local

### 2. Node Mode
```bash
go run ./cmd/btcfinder/main.go \
  --mode node \
  --port :8080 \
  --min 0x8000 \
  --max 0xffff \
  --num-seeds 4 \
  --address "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY" \
  --db btcfinder.db \
  --node-token secret-token \
  --telegram-bot-token "YOUR_BOT_TOKEN" \
  --telegram-chat-id "YOUR_CHAT_ID"
```
- Servidor HTTP na porta 8080
- Aceita requisições de até 4 seeds
- Divide range em 4 jobs iguais
- Persiste estado em SQLite
- Envia alertas ao Telegram

### 3. Seed Mode
```bash
go run ./cmd/btcfinder/main.go \
  --mode seed \
  --seed-id "seed-worker-1" \
  --node-url "http://node.example.com:8080" \
  --seed-token secret-token \
  --workers 8 \
  --address "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY"
```
- Cliente HTTP que se conecta ao Node
- Requisita jobs continuamente
- Executa bruteforce em paralelo
- Reporta progresso a cada 10s
- Termina ao encontrar chave ou sem jobs disponíveis

## Communication Flow

```
┌─────────────────────────────────────────────────────────────┐
│ NODE                                                          │
├─────────────────────────────────────────────────────────────┤
│ - Divide [0x8000-0xffff] em 4 jobs iguais                    │
│ - Mantém fila: [job1, job2, job3, job4]                     │
│ - Registra seeds: {seed-1, seed-2, seed-3, seed-4}          │
│ - Persiste em SQLite                                         │
└─────────────────────────────────────────────────────────────┘
         │
         │ HTTP POST /jobs/request
         ├──────────────────────────────────────────────┐
         │                                              │
    ┌────▼────────────┐  ┌────────────────┐  ┌─────────▼─────┐
    │ SEED-1          │  │ SEED-2         │  │ SEED-3        │
    ├─────────────────┤  ├────────────────┤  ├───────────────┤
    │ job-1           │  │ job-2          │  │ job-3         │
    │ 0x8000-0x3fff   │  │ 0x4000-0x7fff  │  │ 0x8000-0xbfff │
    │ 8 workers       │  │ 8 workers      │  │ 8 workers     │
    │ Testing keys... │  │ Testing keys...│  │ Testing keys..│
    │ [PATCH /status] │  │ [PATCH /status]│  │ [PATCH /status]
    └────────────────┘  └────────────────┘  └───────────────┘

            SEED-4 (inativo) requisita job:
            - NODE não tem job disponível
            - STATUS 204 No Content
            - SEED aguarda 10s e tenta novamente
```

## Rebalancing Logic (Fase 2)

Quando todos os jobs terminam mas 1 seed permanece ativo com job muito lento:

```
1. Node detecta: seed-4 tem job-4 com velocidade < mediana histórica
2. Node subdivide job-4 em M jobs menores (M = num_seeds_aguardando)
3. Node devolve job-4 para fila
4. Seeds rápidos requisitam novos jobs menores
5. Resultado: distribuição mais equilibrada
```

## Database Schema

### Table: `jobs`
```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  min_hex TEXT NOT NULL,
  max_hex TEXT NOT NULL,
  status TEXT NOT NULL,
  seed_id TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  completed_at TIMESTAMP
);
```

### Table: `seed_registry`
```sql
CREATE TABLE seed_registry (
  seed_id TEXT PRIMARY KEY,
  last_heartbeat TIMESTAMP,
  keys_per_second REAL,
  jobs_completed INT,
  current_job_id TEXT,
  status TEXT
);
```

### Table: `job_history`
```sql
CREATE TABLE job_history (
  id TEXT PRIMARY KEY,
  job_id TEXT,
  seed_id TEXT,
  status TEXT,
  keys_checked INT64,
  event_at TIMESTAMP,
  FOREIGN KEY(job_id) REFERENCES jobs(id)
);
```

## Security Considerations

1. **Token Bearer**: Simples mas efetivo para redes internas
2. **HTTPS Recomendado**: Use reverse proxy (nginx) em produção
3. **Validação de Range**: Node valida min/max antes de criar jobs
4. **Rate Limiting**: Fase 2 - implementar rate limit por seed

## Performance Notes

- **Divisão de Jobs**: 1 job/seed esperado (configurável)
- **Status Updates**: 10s por seed
- **Checkpoint**: 5s no Node + SQLite
- **Retry Backoff**: Exponencial (5s, 10s, 20s, ...)

## Migration Path

1. **Phase 1 (Implementado)**: Node, Seed, autenticação, persistência
2. **Phase 2 (TODO)**: Rebalancing de jobs lentos, WebSocket fallback
3. **Phase 3 (Future)**: gRPC, TLS, clustering múltiplos nodes

## Testing & Deployment

### Local Testing
```bash
# Terminal 1 - Node
go run ./cmd/btcfinder/main.go --mode node --port :8080 --num-seeds 2

# Terminal 2 - Seed 1
go run ./cmd/btcfinder/main.go --mode seed --seed-id seed-1 --node-url http://localhost:8080

# Terminal 3 - Seed 2
go run ./cmd/btcfinder/main.go --mode seed --seed-id seed-2 --node-url http://localhost:8080
```

### Validation
- Node expõe `/health` para verificar status
- Logs indicam: job allocation, progress updates, match found
- SQLite persiste state para verificação post-execution

---

**Última atualização**: 3 de dezembro de 2025
