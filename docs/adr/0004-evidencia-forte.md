# ADR 0004 — O gate só bloqueia com evidência forte

**Status:** aceito

## Contexto
Um Security Gate que bloqueia por qualquer padrão suspeito gera falsos
positivos e o time passa a ignorá-lo (ou desligá-lo).

## Decisão
Um achado com severidade ≥ `fail_on` bloqueia somente com **evidência forte**:
fluxo de dados comprovado (taint), dois motores independentes concordando
(ex.: regra + Bandit) ou credencial em formato de provedor. Com evidência
única, o achado vira **aviso** (o job passa, mas o PR mostra). A política é
configurável por repositório em `.sentinela.yml`.

## Consequências
Menos bloqueios injustos; quando o gate bloqueia, o motivo é demonstrável
(o caminho do dado aparece no comentário). Times mais rígidos podem usar
`require_strong_evidence: false`.
