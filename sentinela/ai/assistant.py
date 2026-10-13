"""Análise semântica com LLM local (Ollama + Llama 3).

Para cada achado, o modelo recebe a regra, o caminho do dado contaminado e
uma janela de código ao redor (com segredos já mascarados pelo motor) e
devolve, em uma única resposta JSON:

* **veredito** — ``true_positive``, ``false_positive`` ou ``uncertain``,
  com confiança e justificativa citando a linha decisiva;
* **severidade sugerida** — reavaliação no contexto (ex.: SQL Injection em
  script de migração interno vs. em endpoint público);
* **correção** — explicação curta e o bloco de código corrigido.

Princípios:

* a IA **recomenda**; quem aplica é uma pessoa. Status, severidade efetiva
  e decisão do Security Gate nunca dependem só do modelo;
* sem Ollama a plataforma funciona igual — a remediação vem das regras e o
  campo de IA fica vazio. Uma falha de conexão desliga a IA pelo resto do
  scan (circuit breaker), então um modelo fora do ar custa um timeout, não N.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from sentinela.engine.models import Finding, Severity

logger = logging.getLogger(__name__)

VERDICTS = ("true_positive", "false_positive", "uncertain")
CONFIDENCES = ("high", "medium", "low")


@dataclass(frozen=True)
class AIAssessment:
    verdict: str
    confidence: str
    rationale: str
    suggested_severity: str | None
    fix_explanation: str
    fix_code: str
    model: str

    @property
    def dismisses(self) -> bool:
        """Provável falso positivo com confiança suficiente para recolher no PR."""

        return self.verdict == "false_positive" and self.confidence in {"high", "medium"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OllamaAssistant:
    def __init__(self, *, base_url: str, model: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._broken = False

    @property
    def available(self) -> bool:
        return bool(self.base_url and self.model) and not self._broken

    def assess(self, finding: Finding) -> AIAssessment | None:
        if not self.available:
            return None
        try:
            raw = self._generate(build_prompt(finding))
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError):
            self._broken = True
            logger.info("Ollama indisponível; IA desligada para o restante do scan.")
            return None
        except (httpx.HTTPError, ValueError):
            return None
        return parse_assessment(raw, model=self.model, current=finding.severity)

    def health(self) -> bool:
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def _generate(self, prompt: str) -> Mapping[str, Any]:
        response = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "num_ctx": 4096},
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, Mapping):
            raise ValueError("resposta do Ollama não é um objeto JSON")
        return payload


SYSTEM_PROMPT = (
    "Você é um revisor sênior de segurança de aplicações fazendo a triagem de "
    "achados de análise estática (SAST). Responda somente com JSON válido."
)


def build_prompt(finding: Finding) -> str:
    path = (
        "\n".join(f"  linha {s.line} [{s.kind}]: {s.code}" for s in finding.taint_path)
        or "  (achado por padrão, sem fluxo de dados)"
    )
    meta = {
        "regra": finding.rule_id,
        "titulo": finding.title,
        "cwe": finding.cwe,
        "linguagem": finding.language,
        "arquivo": finding.file_path,
        "linha": finding.line,
        "severidade_atual": finding.severity.value,
        "motores_que_detectaram": sorted(engine.value for engine in finding.engines),
        "mensagem": finding.message,
    }
    return (
        "Decida se ESTA ocorrência é explorável, usando apenas o código mostrado.\n\n"
        "Responda false_positive somente quando o próprio código mostrar por que é seguro, por exemplo:\n"
        "- o valor é validado contra uma allowlist fixa, regex com fullmatch, ou convertido com int()/UUID antes do sink;\n"
        "- o valor é constante ou vem de configuração do servidor, não de usuário/requisição/arquivo enviado;\n"
        "- o código é de teste, fixture ou exemplo, não alcançável em produção;\n"
        "- a 'credencial' é claramente um placeholder ou identificador público.\n"
        "Responda true_positive quando dado controlado pelo atacante alcança o sink, ou há credencial real no código.\n"
        "Responda uncertain quando o código decisivo não está visível. Na dúvida, não diga false_positive.\n\n"
        "Formato da resposta (JSON):\n"
        '{"verdict": "true_positive|false_positive|uncertain", "confidence": "high|medium|low", '
        '"rationale": "uma frase citando a linha que justifica", '
        '"suggested_severity": "critical|high|medium|low|info", '
        '"fix_explanation": "o que mudar, em uma ou duas frases", '
        '"fix_code": "trecho corrigido, mesma linguagem, sem markdown"}\n\n'
        f"Achado: {json.dumps(meta, ensure_ascii=False)}\n\n"
        f"Caminho do dado:\n{path}\n\n"
        f"Código (linhas com >> são o achado):\n{finding.context}\n"
    )


def parse_assessment(payload: Mapping[str, Any], *, model: str, current: Severity) -> AIAssessment | None:
    body: Any = payload.get("response", payload)
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            return None
    if not isinstance(body, Mapping):
        return None

    verdict = str(body.get("verdict", "")).strip().lower().replace("likely_", "")
    confidence = str(body.get("confidence", "")).strip().lower()
    rationale = body.get("rationale")
    if verdict not in VERDICTS or confidence not in CONFIDENCES:
        return None
    if not isinstance(rationale, str) or not rationale.strip():
        return None

    suggested = str(body.get("suggested_severity", "")).strip().lower()
    suggested_severity = suggested if suggested in {s.value for s in Severity} and suggested != current.value else None

    fix_code = body.get("fix_code")
    fix_code = _strip_fences(fix_code) if isinstance(fix_code, str) else ""
    explanation = body.get("fix_explanation")
    return AIAssessment(
        verdict=verdict,
        confidence=confidence,
        rationale=rationale.strip()[:600],
        suggested_severity=suggested_severity,
        fix_explanation=explanation.strip()[:800] if isinstance(explanation, str) else "",
        fix_code=fix_code[:3000],
        model=model,
    )


def _strip_fences(code: str) -> str:
    text = code.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    return text.strip()


def assistant_from_env() -> OllamaAssistant | None:
    from sentinela.config import get_settings

    settings = get_settings()
    if not settings.ai_enabled:
        return None
    return OllamaAssistant(
        base_url=settings.ollama_url,
        model=settings.ollama_model,
        timeout=settings.ollama_timeout,
    )


__all__ = ["AIAssessment", "OllamaAssistant", "assistant_from_env", "build_prompt", "parse_assessment"]
