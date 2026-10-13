# ADR 0002 — A IA recomenda; o gate decide com evidência determinística

**Status:** aceito

## Contexto
O projeto pede uso de LLM local para classificar severidade, reduzir falsos
positivos e sugerir correções. LLMs erram e podem ser induzidos por texto no
próprio código analisado (comentários do tipo "isto é seguro").

## Decisão
- O Llama 3 (via Ollama) avalia cada achado e devolve veredito, confiança,
  severidade sugerida e correção, tudo em JSON validado.
- O veredito **não** altera status, severidade efetiva nem o gate. Ele muda a
  apresentação: prováveis falsos positivos ficam recolhidos no comentário do PR
  e filtráveis no dashboard. Quem fecha um achado é um revisor humano.
- Credenciais detectadas são mascaradas antes de qualquer envio ao modelo.
- Sem Ollama, tudo funciona igual; uma falha de conexão desliga a IA pelo
  resto do scan (circuit breaker).

## Consequências
A IA reduz o ruído que o desenvolvedor vê sem poder liberar uma vulnerabilidade
real nem travar um PR por alucinação. O ganho é medido no benchmark (`--ai`).
