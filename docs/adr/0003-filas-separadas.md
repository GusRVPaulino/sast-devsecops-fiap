# ADR 0003 — Duas filas: análise determinística e IA

**Status:** aceito

## Contexto
A análise determinística de um PR leva milissegundos; a avaliação por LLM
leva segundos por achado. Numa fila única, um PR com 50 achados atrasaria a
análise de todos os outros.

## Decisão
Celery com Redis e duas filas: `analysis` (parsing, regras, taint, Bandit,
gate) e `ai` (uma tarefa por achado). Um *chord* garante que o `finalize`
(cálculo do gate) só rode depois de todas as avaliações. Os workers são
containers separados e escalam de forma independente.

## Consequências
- `docker compose up --scale worker-ai=3` acelera só a IA.
- `acks_late` + `reject_on_worker_lost`: um worker que morre devolve a tarefa.
- PostgreSQL é o estado compartilhado; a API não guarda nada em memória.
