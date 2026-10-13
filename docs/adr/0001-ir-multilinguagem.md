# ADR 0001 — Um motor, três linguagens, via adaptadores sobre o Tree-sitter

**Status:** aceito

## Contexto
O projeto pede parsing multi-linguagem. A alternativa óbvia — um analisador
por linguagem (módulo `ast` para Python, outro para JS, outro para Java) —
triplica regras e taint analysis, e cada correção precisa ser feita três vezes.

## Decisão
Usar o Tree-sitter para gerar a AST das três linguagens e um `LanguageAdapter`
por linguagem que responde a perguntas comuns (nome qualificado de chamada,
argumentos, atribuições, parâmetros, literais, constância). Regras (YAML),
detector de segredos e taint analysis são escritos uma vez sobre esse contrato.

## Consequências
- Adicionar uma linguagem = um adaptador + um YAML de regras.
- O adaptador Java registra o tipo declarado das variáveis, então as regras
  podem dizer `Statement.executeQuery` em vez de adivinhar pelo nome.
- A análise é sintática + fluxo de dados intraprocedural com um nível de
  resumo entre funções do mesmo arquivo; não há resolução de tipos completa
  nem análise entre arquivos.
