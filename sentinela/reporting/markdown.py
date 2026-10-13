"""Relatório em Markdown — usado como comentário de Pull Request e no terminal."""

from __future__ import annotations

from collections import Counter
from typing import Any

_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}
_GATE = {
    "passed": "✅ **Security Gate: aprovado**",
    "warned": "⚠️ **Security Gate: aprovado com avisos**",
    "failed": "⛔ **Security Gate: bloqueado**",
}
MARKER = "<!-- sentinela-report -->"


def pr_comment(findings: list[dict[str, Any]], gate: dict[str, Any], *, max_items: int = 25) -> str:
    """Achados com IA dizendo 'falso positivo' vão para uma seção recolhida."""

    active = [f for f in findings if f.get("status", "open") in {"open", "confirmed"}]
    dismissed_by_ai = [f for f in active if _ai_dismisses(f)]
    main = [f for f in active if not _ai_dismisses(f)]
    counts = Counter(f["severity"] for f in active)

    lines = [MARKER, "## 🛡️ Sentinela — análise de segurança", "", _GATE.get(gate.get("status"), "")]
    lines.append("")
    lines.append(
        " · ".join(f"{_ICON[s]} {s}: **{counts.get(s, 0)}**" for s in ("critical", "high", "medium", "low")),
    )
    if dismissed_by_ai:
        lines += [
            "",
            f"🤖 A IA local marcou **{len(dismissed_by_ai)}** achado(s) como provável falso positivo "
            "(recolhidos no fim). Eles continuam abertos até um revisor confirmar — a IA não altera o gate.",
        ]
    blocking = set(gate.get("blocking", []))
    if blocking:
        lines += ["", "**O que bloqueia o merge:**"]
        lines += [
            f"- `{f['file_path']}:{f['line']}` {f['title']}"
            for f in main + dismissed_by_ai
            if f["fingerprint"] in blocking
        ]

    if not active:
        lines += ["", "Nenhuma vulnerabilidade aberta encontrada nos arquivos alterados. 🎉"]
        return "\n".join(lines)

    lines += ["", "### Achados", ""]
    for finding in main[:max_items]:
        lines += _finding_block(finding)
    if len(main) > max_items:
        lines.append(f"_…e mais {len(main) - max_items} achado(s). Veja o relatório SARIF ou o dashboard._")

    if dismissed_by_ai:
        lines += [
            "",
            "<details>",
            f"<summary>🤖 Prováveis falsos positivos segundo a IA ({len(dismissed_by_ai)})</summary>",
            "",
        ]
        for finding in dismissed_by_ai:
            lines += _finding_block(finding)
        lines += ["</details>"]
    return "\n".join(lines)


def _finding_block(f: dict[str, Any]) -> list[str]:
    engines = ", ".join(f.get("engines", []))
    out = [
        f"<details><summary>{_ICON[f['severity']]} <b>{f['title']}</b> — <code>{f['file_path']}:{f['line']}</code> "
        f"({f['cwe']}, confiança {f.get('confidence', '?')})</summary>",
        "",
        f"{f['message']}",
        "",
        f"```{f['language']}\n{f['snippet']}\n```",
    ]
    if f.get("taint_path"):
        out += ["", "**Caminho do dado:**"]
        out += [f"{i}. linha {s['line']} ({s['kind']}): `{s['code']}`" for i, s in enumerate(f["taint_path"], 1)]
    ai = f.get("ai")
    if ai:
        out += [
            "",
            f"**IA ({ai.get('model')}):** {_verdict_pt(ai['verdict'])}, confiança {ai['confidence']}. {ai['rationale']}",
        ]
        if ai.get("suggested_severity"):
            out.append(f"Severidade sugerida: `{ai['suggested_severity']}` (não aplicada automaticamente).")
    out += ["", f"**Como corrigir:** {f.get('remediation', '')}"]
    fix = (ai or {}).get("fix_code") or f.get("safe_example")
    if fix:
        out += ["", f"```{f['language']}\n{fix}\n```"]
    out += [
        "",
        f"<sub>regra `{f['rule_id']}` · motores: {engines} · fingerprint `{f['fingerprint'][:12]}`</sub>",
        "</details>",
        "",
    ]
    return out


def _ai_dismisses(f: dict[str, Any]) -> bool:
    ai = f.get("ai") or {}
    return ai.get("verdict") == "false_positive" and ai.get("confidence") in {"high", "medium"}


def _verdict_pt(verdict: str) -> str:
    return {
        "true_positive": "vulnerabilidade real",
        "false_positive": "provável falso positivo",
        "uncertain": "inconclusivo",
    }.get(verdict, verdict)
