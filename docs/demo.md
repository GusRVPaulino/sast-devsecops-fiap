# Roteiro de demonstração (defesa)

Tempo total: cerca de 10 minutos. Faça o passo 0 antes da apresentação.

## 0. Antes de entrar na sala

```bash
docker compose --profile ai up --build -d   # primeira vez: baixa o Llama 3 (~4,7 GB)
docker compose exec api python scripts/seed_demo.py
```

Abra http://localhost:8000 e confira se o projeto **loja-demo** aparece com
o histórico de scans.

## 1. O problema (1 min)

SAST encontra vulnerabilidades no código sem executá-lo, ainda no Pull
Request (shift-left). Ferramentas puramente de padrão têm dois problemas:
muito falso positivo e pouca explicação. O Sentinela ataca os dois com taint
analysis (prova o caminho do dado) e triagem por IA local.

## 2. Arquitetura (2 min)

Abra [`architecture/c4.md`](architecture/c4.md) e mostre:

- **O motor multi-linguagem:** Tree-sitter mais um adaptador por linguagem.
  Regras e taint são escritas uma vez e valem para Python, JS e Java
  ([ADR 0001](adr/0001-ir-multilinguagem.md)).
- **As duas filas:** análise e IA, cada uma com seus workers
  ([ADR 0003](adr/0003-filas-separadas.md)).

## 3. Scan ao vivo pela CLI (2 min)

```bash
pip install -e .
sentinela scan benchmark/corpus/java --no-fail
```

Aponte no terminal o **caminho do dado**: `@RequestParam cliente`, depois
`String sql = ... + cliente`, depois `stmt.executeQuery(sql)`. Explique por
que é crítico e por que o gate bloqueia: há evidência forte
([ADR 0004](adr/0004-evidencia-forte.md)).

## 4. IA reduzindo falso positivo (2 min)

```bash
sentinela scan benchmark/corpus/java/FalsosPositivosSemanticos.java --ai --no-fail
```

O motor sinaliza o SQL e o `exec`, mas o código valida contra uma allowlist.
O Llama 3 responde `false_positive` citando a linha da validação. Ressalte
que **a IA não libera nada sozinha**: o achado fica aberto até um revisor
confirmar ([ADR 0002](adr/0002-ia-consultiva.md)).

## 5. Dashboard (2 min)

No http://localhost:8000:

1. **Visão geral:** severidade, tendência (as falhas caindo ao longo dos
   scans), top arquivos críticos e OWASP Top 10.
2. **Scans → um scan bloqueado:** abra um achado e mostre o caminho do dado,
   a análise da IA, a correção sugerida e o botão "Falso positivo".
3. Marque um achado como **Risco aceito** com uma justificativa. Explique que
   a decisão fica guardada pelo fingerprint e vale nos próximos scans, mesmo
   se a linha mudar.
4. Baixe o **SARIF**.

## 6. Security Gate no GitHub (1 min)

Mostre um PR do repositório onde o workflow **Security Gate** comentou e
falhou o check. Se não houver um, crie uma branch com um arquivo vulnerável
copiado do corpus e abra o PR.

## 7. Resultados e limitações (1 min)

Mostre [`benchmark/RESULTS.md`](../benchmark/RESULTS.md):

- **Recall de 100%** nas 3 linguagens.
- **Bandit sozinho** encontra 59% no Python.
- **Precisão de 76% sem IA:** os FPs restantes são exatamente os casos
  semânticos. A linha `--ai` mostra quanto a IA recupera.

Seja honesto sobre as limitações: o taint não atravessa arquivos, e o corpus
foi escrito pelo grupo.
