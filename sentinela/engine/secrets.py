"""Detecção de credenciais escritas no código (CWE-798), em qualquer linguagem.

Duas estratégias complementares:

1. **Formato conhecido** — tokens com prefixo/estrutura de provedor (AWS,
   GitHub, Slack, Stripe, Google, JWT, chave privada PEM, URL com senha).
   São reconhecidos em qualquer string, independente do nome da variável.
2. **Nome + valor** — um literal atribuído a algo chamado ``password``,
   ``apiKey``, ``client_secret``... com valor que não parece placeholder e tem
   entropia mínima.

O valor encontrado **nunca** é copiado para o achado: a evidência guarda só
os dois primeiros caracteres e o tamanho.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from tree_sitter import Node

from sentinela.engine.languages.base import LanguageAdapter
from sentinela.engine.models import Engine, Finding, Severity

RULE_ID = "secrets.hardcoded-credential"
CWE = "CWE-798"
OWASP = "A07:2021 - Identification and Authentication Failures"

_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("chave de acesso AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("token do GitHub", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("token do GitHub", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("token do Slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("chave de API do Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("chave secreta do Stripe", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("chave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("URL com senha", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+", re.I)),
)

_SECRET_NAME = re.compile(
    r"(passw(or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?(token|key)|credential|"
    r"signing[_-]?key|encryption[_-]?key|jwt[_-]?key)",
    re.I,
)
# Nomes que falam *sobre* a credencial, mas não guardam a credencial.
_METADATA_SUFFIX = re.compile(
    r"(field|label|header|name|url|uri|endpoint|path|file|len|length|min|max|"
    r"prompt|message|msg|regex|pattern|type|hint|placeholder|policy|ttl|"
    r"timeout|expiry|expires|expiration|reset|param|key_name|env|var|column)$",
    re.I,
)
_PLACEHOLDER = re.compile(
    r"^(\s*|x+|\*+|\.+|-+|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%\(?\w*\)?s|\$\w+|"
    r"(change[_-]?me|changeit|your[_-].*|my[_-].*|example.*|sample.*|dummy.*|"
    r"placeholder|redacted|none|null|undefined|todo|fixme|test|secret|password|"
    r"token|senha|xxx.*))$",
    re.I,
)
_MIN_LENGTH = 6
_MIN_ENTROPY = 2.3
_TEST_PATH = re.compile(
    r"(^|/)(tests?|spec|__tests__|fixtures?)(/|$)|(^|/)test_[^/]+$|_test\.[a-z]+$|\.spec\.[a-z]+$|Test\.java$", re.I
)


@dataclass(frozen=True)
class _Hit:
    node: Node
    label: str
    value: str
    name: str | None
    severity: Severity


def detect_secrets(
    adapter: LanguageAdapter,
    root: Node,
    *,
    path: str,
    source_lines: list[str],
) -> list[Finding]:
    hits: dict[int, _Hit] = {}
    in_tests = bool(_TEST_PATH.search(path))

    for literal in adapter.named_literals(root):
        provider = provider_token(literal.value)
        if provider is not None:
            severity = Severity.CRITICAL
            label = provider
        elif looks_like_secret(literal.name, literal.value):
            severity = Severity.HIGH
            label = "credencial"
        else:
            continue
        line = adapter.line(literal.node)
        hits.setdefault(line, _Hit(literal.node, label, literal.value, literal.name, severity))

    for value, node in adapter.string_literals(root):
        provider = provider_token(value)
        line = adapter.line(node)
        if provider is not None and line not in hits:
            hits[line] = _Hit(node, provider, value, None, Severity.CRITICAL)

    findings = []
    for line, hit in sorted(hits.items()):
        severity = Severity.LOW if in_tests else hit.severity
        masked = mask(hit.value)
        subject = f"`{hit.name}` recebe" if hit.name else "Literal contém"
        finding = Finding(
            rule_id=RULE_ID,
            title=f"Credencial no código-fonte ({hit.label})",
            language=adapter.name,
            file_path=path,
            line=line,
            end_line=adapter.end_line(hit.node),
            column=hit.node.start_point[1] + 1,
            severity=severity,
            cwe=CWE,
            owasp=OWASP,
            message=(
                f"{subject} um valor que parece {hit.label} ({masked}). Segredos "
                "no código vazam para todos com acesso ao repositório e "
                "continuam no histórico do git mesmo depois de removidos."
                + (" Arquivo de teste: severidade reduzida." if in_tests else "")
            ),
            snippet=mask_line(source_lines[line - 1], hit.value),
            engines={Engine.SECRET},
            remediation=(
                "Leia o valor de variável de ambiente ou de um cofre de segredos "
                "e revogue/rotacione a credencial exposta."
            ),
            safe_example=_example(adapter.name, hit.name),
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        )
        findings.append(finding)
    return findings


def secret_lines(findings: list[Finding]) -> dict[str, set[int]]:
    """Linhas com segredo por arquivo — usadas para mascarar o contexto da IA."""

    result: dict[str, set[int]] = {}
    for finding in findings:
        if finding.cwe == CWE:
            result.setdefault(finding.file_path, set()).update(
                range(finding.line, finding.end_line + 1),
            )
    return result


def provider_token(value: str) -> str | None:
    for label, pattern in _PROVIDER_PATTERNS:
        if pattern.search(value):
            return label
    return None


def looks_like_secret(name: str, value: str) -> bool:
    if not name or not _SECRET_NAME.search(name):
        return False
    if _METADATA_SUFFIX.search(name.replace("-", "_")):
        return False
    stripped = value.strip()
    if len(stripped) < _MIN_LENGTH or _PLACEHOLDER.match(stripped):
        return False
    if len(stripped.split()) > 2:  # frase, não credencial
        return False
    return shannon_entropy(stripped) >= _MIN_ENTROPY


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def mask(value: str) -> str:
    return f"{value[:2]}•••• ({len(value)} caracteres)"


def mask_line(line: str, secret: str) -> str:
    if secret and secret in line:
        return line.replace(secret, f"{secret[:2]}••••").strip()
    return line.strip()


def _example(language: str, name: str | None) -> str:
    var = name or "SEGREDO"
    env = re.sub(r"[^A-Za-z0-9]", "_", var).upper()
    if language == "python":
        return f'import os\n{var} = os.environ["{env}"]'
    if language == "javascript":
        return f"const {var} = process.env.{env};"
    return f'String {var} = System.getenv("{env}");'


__all__ = ["CWE", "RULE_ID", "detect_secrets", "looks_like_secret", "mask", "provider_token", "secret_lines"]
