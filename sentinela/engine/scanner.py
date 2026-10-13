"""Orquestra a análise de um conjunto de arquivos.

Para cada arquivo: detecta a linguagem → parseia (Tree-sitter) → regras
declarativas → detector de segredos → taint analysis → Bandit (Python) →
une achados que descrevem a mesma vulnerabilidade → monta o contexto de
código que a IA vai ler (com segredos mascarados) → fingerprint.
"""

from __future__ import annotations

import time
from collections.abc import Iterable
from dataclasses import dataclass

from sentinela.engine.external.bandit import cwe_compatible, run_bandit
from sentinela.engine.languages import detect_language, get_adapter
from sentinela.engine.models import Engine, Finding, ScanResult, SourceFile
from sentinela.engine.rules import RuleMatcher, load_rules
from sentinela.engine.secrets import detect_secrets
from sentinela.engine.taint import TaintAnalyzer, load_taint_spec

CONTEXT_RADIUS = 8
MAX_FILE_BYTES = 1_000_000


@dataclass(frozen=True)
class ScanOptions:
    use_bandit: bool = True
    scope: str = ""  # entra no fingerprint (ex. nome do projeto)
    rules_dir: str | None = None


def scan_files(files: Iterable[SourceFile], options: ScanOptions | None = None) -> ScanResult:
    options = options or ScanOptions()
    started = time.perf_counter()
    findings: list[Finding] = []
    skipped: list[tuple[str, str]] = []
    languages: dict[str, int] = {}
    scanned = 0

    for source in files:
        language = source.language or detect_language(source.path)
        if language is None:
            skipped.append((source.path, "linguagem não suportada"))
            continue
        if len(source.content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
            skipped.append((source.path, "arquivo maior que 1 MB"))
            continue
        try:
            file_findings = scan_source(source.path, source.content, language, options)
        except Exception as exc:  # um arquivo ruim não derruba o scan inteiro
            skipped.append((source.path, f"erro de análise: {type(exc).__name__}"))
            continue
        scanned += 1
        languages[language] = languages.get(language, 0) + 1
        findings.extend(file_findings)

    findings.sort(key=lambda f: (-f.severity.rank, f.file_path, f.line))
    return ScanResult(
        findings=findings,
        files_scanned=scanned,
        files_skipped=skipped,
        languages=languages,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )


def scan_source(path: str, content: str, language: str, options: ScanOptions | None = None) -> list[Finding]:
    options = options or ScanOptions()
    adapter = get_adapter(language)
    tree = adapter.parse(content)
    root = tree.root_node
    ctx = adapter.build_context(root)
    lines = content.splitlines()

    rule_findings = RuleMatcher(adapter, load_rules(language, options.rules_dir)).run(
        root,
        ctx,
        path=path,
        source_lines=lines,
    )
    secret_findings = detect_secrets(adapter, root, path=path, source_lines=lines)
    spec = load_taint_spec(language, options.rules_dir)
    taint_findings = TaintAnalyzer(adapter, spec, ctx, path=path, source_lines=lines).run(root) if spec else []

    findings = merge_findings([*secret_findings, *rule_findings], taint_findings)

    if options.use_bandit and language == "python":
        corroborate_with_bandit(findings, content)

    masked_lines = {
        line for finding in findings if finding.cwe == "CWE-798" for line in range(finding.line, finding.end_line + 1)
    }
    for finding in findings:
        finding.context = code_window(lines, finding.line, finding.end_line, masked_lines)
        finding.compute_fingerprint(options.scope)
    return findings


def merge_findings(pattern_findings: list[Finding], taint_findings: list[Finding]) -> list[Finding]:
    """Regra e taint na mesma chamada = uma vulnerabilidade só, com dois motores.

    O achado de taint é mais informativo (tem o caminho do dado e severidade
    maior), então ele é mantido e absorve o motor da regra.
    """

    result = list(taint_findings)
    for finding in pattern_findings:
        twin = next(
            (
                taint
                for taint in taint_findings
                if taint.cwe == finding.cwe
                and taint.file_path == finding.file_path
                and taint.line <= finding.end_line
                and finding.line <= taint.end_line
            ),
            None,
        )
        if twin is None:
            result.append(finding)
            continue
        twin.engines |= finding.engines
        if finding.severity.rank > twin.severity.rank:
            twin.severity = finding.severity
    return result


def corroborate_with_bandit(findings: list[Finding], content: str) -> None:
    issues = run_bandit(content)
    for finding in findings:
        for issue in issues:
            if (
                issue.line <= finding.end_line
                and finding.line <= issue.end_line
                and cwe_compatible(
                    finding.cwe,
                    issue.cwe,
                )
            ):
                finding.engines.add(Engine.BANDIT)
                break


def code_window(lines: list[str], start: int, end: int, masked: set[int], radius: int = CONTEXT_RADIUS) -> str:
    """Linhas numeradas ao redor do achado; ``>>`` marca as linhas do achado."""

    first = max(1, start - radius)
    last = min(len(lines), end + radius)
    out = []
    for number in range(first, last + 1):
        text = "<linha com credencial mascarada>" if number in masked else lines[number - 1]
        marker = ">>" if start <= number <= end else "  "
        out.append(f"{marker} {number:4d} | {text}")
    return "\n".join(out)


__all__ = ["ScanOptions", "code_window", "merge_findings", "scan_files", "scan_source"]
