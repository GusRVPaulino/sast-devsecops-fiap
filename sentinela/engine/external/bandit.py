"""Bandit como segundo motor, independente, para arquivos Python.

O Bandit é mantido pela PyCQA, com regras próprias. Quando ele aponta a
mesma linha e uma CWE compatível com um achado do Sentinela, o achado ganha
o motor ``bandit`` — duas implementações diferentes concordando é evidência
mais forte, e é isso que o Security Gate exige para bloquear.

Se o Bandit não estiver instalado ou falhar, a análise segue sem ele.
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)
logging.getLogger("stevedore.extension").setLevel(logging.CRITICAL)

# Mesma fraqueza descrita por CWEs diferentes em cada ferramenta.
_CWE_FAMILIES = (
    {78, 94, 95},
    {259, 798, 321},
    {502, 20},
    {89},
    {22},
    {918},
    {327, 328},
    {295},
    {489, 94},
    {377},
    {79},
)


@dataclass(frozen=True)
class BanditIssue:
    test_id: str
    line: int
    end_line: int
    cwe: int | None
    severity: str


def run_bandit(source: str) -> list[BanditIssue]:
    try:
        from bandit.core import config as bandit_config
        from bandit.core import manager as bandit_manager
    except ImportError:
        return []

    with tempfile.TemporaryDirectory(prefix="sentinela-bandit-") as tmp:
        path = os.path.join(tmp, "alvo.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        try:
            manager = bandit_manager.BanditManager(bandit_config.BanditConfig(), "file", quiet=True)
            manager.discover_files([path])
            manager.run_tests()
            raw = [issue.as_dict(with_code=False) for issue in manager.get_issue_list()]
        except Exception:  # o Bandit nunca pode derrubar a análise
            logger.warning("Bandit falhou; seguindo sem ele.", exc_info=True)
            return []

    issues = []
    for item in raw:
        lines = item.get("line_range") or [item.get("line_number", 1)]
        cwe = (item.get("issue_cwe") or {}).get("id")
        issues.append(
            BanditIssue(
                test_id=str(item.get("test_id", "")),
                line=int(lines[0]),
                end_line=int(lines[-1]),
                cwe=int(cwe) if cwe else None,
                severity=str(item.get("issue_severity", "")).lower(),
            ),
        )
    return issues


def cwe_compatible(own: str, other: int | None) -> bool:
    if other is None:
        return False
    try:
        number = int(own.upper().removeprefix("CWE-"))
    except ValueError:
        return False
    return number == other or any(number in family and other in family for family in _CWE_FAMILIES)


__all__ = ["BanditIssue", "cwe_compatible", "run_bandit"]
