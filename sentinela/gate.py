"""Security Gate: decide se um conjunto de achados bloqueia o merge.

Política (``.sentinela.yml`` no repositório analisado)::

    gate:
      fail_on: high            # severidade mínima que pode bloquear
      require_strong_evidence: true
      ignore_rules: []
      ignore_paths: ["tests/**", "**/fixtures/**"]

**Evidência forte** é o que separa "bloqueia" de "avisa":

* fluxo de dados comprovado (taint: fonte → sink), ou
* dois ou mais motores independentes no mesmo ponto (ex. regra + Bandit), ou
* credencial em formato de provedor (AWS, GitHub, Stripe...).

O veredito da IA **nunca** conta como evidência — nem para bloquear, nem
para liberar. Só a decisão registrada por um revisor (falso positivo,
risco aceito, corrigido) remove um achado do gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from sentinela.engine.models import Engine, Severity

CLOSED_STATUSES = {"false_positive", "accepted_risk", "fixed"}


@dataclass(frozen=True)
class GatePolicy:
    fail_on: Severity = Severity.HIGH
    require_strong_evidence: bool = True
    ignore_rules: tuple[str, ...] = ()
    ignore_paths: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> GatePolicy:
        gate = (data or {}).get("gate", data or {})
        return cls(
            fail_on=Severity.parse(gate.get("fail_on", "high")),
            require_strong_evidence=bool(gate.get("require_strong_evidence", True)),
            ignore_rules=tuple(gate.get("ignore_rules", ())),
            ignore_paths=tuple(gate.get("ignore_paths", ())),
        )

    @classmethod
    def load(cls, path: str | Path | None) -> GatePolicy:
        if path is None or not Path(path).exists():
            return cls()
        return cls.from_dict(yaml.safe_load(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on.value,
            "require_strong_evidence": self.require_strong_evidence,
            "ignore_rules": list(self.ignore_rules),
            "ignore_paths": list(self.ignore_paths),
        }


@dataclass
class GateDecision:
    status: str  # passed | warned | failed
    blocking: list[str] = field(default_factory=list)  # fingerprints
    warnings: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status != "failed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "passed": self.passed,
            "blocking": self.blocking,
            "warnings": self.warnings,
            "reasons": self.reasons,
        }


def has_strong_evidence(engines: set[Engine] | set[str], severity: Severity, rule_id: str) -> bool:
    names = {getattr(engine, "value", engine) for engine in engines}
    if Engine.TAINT.value in names:
        return True
    if len(names) >= 2:
        return True
    return Engine.SECRET.value in names and severity == Severity.CRITICAL


def evaluate(findings: list[Any], policy: GatePolicy) -> GateDecision:
    """``findings`` pode ser ``Finding`` do motor ou linha do banco/dicionário."""

    decision = GateDecision(status="passed")
    for finding in findings:
        status = _get(finding, "status") or "open"
        if status in CLOSED_STATUSES:
            continue
        rule_id = _get(finding, "rule_id")
        path = _get(finding, "file_path")
        if any(fnmatch(rule_id, pattern) for pattern in policy.ignore_rules):
            continue
        if any(fnmatch(path, pattern) for pattern in policy.ignore_paths):
            continue
        severity = Severity.parse(_get(finding, "severity"))
        if severity.rank < policy.fail_on.rank:
            continue
        engines = set(_get(finding, "engines") or ())
        fingerprint = _get(finding, "fingerprint")
        where = f"{path}:{_get(finding, 'line')} {rule_id}"
        if not policy.require_strong_evidence or has_strong_evidence(engines, severity, rule_id):
            decision.blocking.append(fingerprint)
            decision.reasons.append(f"BLOQUEIA {severity.value}: {where}")
        else:
            decision.warnings.append(fingerprint)
            decision.reasons.append(f"aviso {severity.value} (evidência única): {where}")

    if decision.blocking:
        decision.status = "failed"
    elif decision.warnings:
        decision.status = "warned"
    if not decision.reasons:
        decision.reasons.append(f"Nenhum achado aberto com severidade >= {policy.fail_on.value}.")
    return decision


def _get(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    value = getattr(item, name, None)
    return getattr(value, "value", value) if name == "severity" else value


__all__ = ["CLOSED_STATUSES", "GateDecision", "GatePolicy", "evaluate", "has_strong_evidence"]
