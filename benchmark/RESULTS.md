# Benchmark do Sentinela

Verdade: **37 vulnerabilidades rotuladas** java: 8, javascript: 12, python: 17 em `benchmark/corpus/`.

| Configuração | VP | FP | FN | Precisão | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Regras de padrão (AST) | 26 | 10 | 11 | 72% | 70% | 0.71 |
| Regras + taint analysis | 37 | 12 | 0 | 76% | 100% | 0.86 |
| Sentinela (regras + taint + Bandit) | 37 | 12 | 0 | 76% | 100% | 0.86 |
| Bandit sozinho (só Python) | 10 | 7 | 7 | 59% | 59% | 0.59 |
| Sentinela (só Python, para comparar) | 17 | 5 | 0 | 77% | 100% | 0.87 |

## Detalhe da configuração principal
- FP `java/FalsosPositivosSemanticos.java:18` java.taint.sql-injection (CWE-89)
- FP `java/FalsosPositivosSemanticos.java:27` java.taint.command-injection (CWE-78)
- FP `javascript/falsos_positivos_semanticos.js:11` javascript.taint.command-injection (CWE-78)
- FP `python/falsos_positivos_semanticos.py:23` python.taint.sql-injection (CWE-89)
- FP `python/falsos_positivos_semanticos.py:30` python.taint.command-injection (CWE-78)
- FP `javascript/falsos_positivos_semanticos.js:22` javascript.taint.xss (CWE-79)
- FP `python/falsos_positivos_semanticos.py:36` python.deserialization.pickle (CWE-502)
- FP `python/falsos_positivos_semanticos.py:41` python.command.subprocess-shell (CWE-78)
- FP `python/falsos_positivos_semanticos.py:45` secrets.hardcoded-credential (CWE-798)
- FP `java/PedidoSeguro.java:26` java.sql.string-built-query (CWE-89)
- FP `javascript/api_segura.js:23` javascript.sql.string-built-query (CWE-89)
- FP `javascript/falsos_positivos_semanticos.js:16` javascript.taint.open-redirect (CWE-601)
