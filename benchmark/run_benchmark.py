"""Benchmark de precisão e recall do Sentinela.

A verdade está no próprio corpus: uma linha que termina com
``# expect: CWE-N`` (ou ``// expect: CWE-N``) é uma vulnerabilidade real.
Qualquer outro achado é falso positivo.

    python -m benchmark.run_benchmark
    python -m benchmark.run_benchmark --markdown benchmark/RESULTS.md
    python -m benchmark.run_benchmark --ai --ollama-url http://localhost:11434

Compara configurações do motor para mostrar a contribuição de cada camada
(regras → taint → Bandit → IA) e compara com o Bandit sozinho.
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from sentinela.engine.external.bandit import cwe_compatible, run_bandit
from sentinela.engine.languages import detect_language
from sentinela.engine.models import Engine, Finding, SourceFile
from sentinela.engine.scanner import ScanOptions, scan_files

CORPUS = Path(__file__).resolve().parent / "corpus"
_EXPECT = re.compile(r"(?:#|//)\s*expect:\s*(CWE-\d+)")
# Mesmo critério do motor: famílias de CWE equivalentes.
_EQUIVALENT = {"CWE-94": "CWE-95"}


@dataclass(frozen=True)
class Expected:
    path: str
    line: int
    cwe: str


@dataclass(frozen=True)
class Reported:
    path: str
    line: int
    end_line: int
    cwe: str
    rule: str


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    false_positives: list[Reported] = field(default_factory=list)
    missed: list[Expected] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


def load_corpus(root: Path = CORPUS) -> tuple[list[SourceFile], list[Expected]]:
    files, expected = [], []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if not path.is_file() or detect_language(rel) is None:
            continue
        content = path.read_text(encoding="utf-8")
        files.append(SourceFile(path=rel, content=content))
        for number, line in enumerate(content.splitlines(), start=1):
            match = _EXPECT.search(line)
            if match:
                expected.append(Expected(rel, number, match.group(1)))
    return files, expected


def _same_weakness(reported: str, expected: str) -> bool:
    reported = _EQUIVALENT.get(reported, reported)
    if reported == expected:
        return True
    try:
        return cwe_compatible(expected, int(reported.split("-")[1]))
    except (IndexError, ValueError):
        return False


def score(reported: list[Reported], expected: list[Expected]) -> Score:
    result = Score()
    matched: set[Expected] = set()
    for item in reported:
        hit = next(
            (
                exp
                for exp in expected
                if exp.path == item.path
                and item.line <= exp.line <= item.end_line
                and _same_weakness(item.cwe, exp.cwe)
            ),
            None,
        )
        if hit is None:
            result.false_positives.append(item)
        else:
            matched.add(hit)
    result.tp = len(matched)
    result.fp = len(result.false_positives)
    result.missed = [exp for exp in expected if exp not in matched]
    result.fn = len(result.missed)
    return result


def _as_reported(findings: list[Finding]) -> list[Reported]:
    return [Reported(f.file_path, f.line, f.end_line, f.cwe, f.rule_id) for f in findings]


def _engine_filter(engines: set[Engine]) -> Callable[[list[Finding]], list[Finding]]:
    def keep(findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.engines & engines]

    return keep


def run(ai_assistant=None) -> tuple[list[Expected], dict[str, Score]]:
    files, expected = load_corpus()
    full = scan_files(files, ScanOptions(use_bandit=True)).findings

    configurations: dict[str, list[Finding]] = {
        "Regras de padrão (AST)": _engine_filter({Engine.RULE, Engine.SECRET})(
            scan_files(files, ScanOptions(use_bandit=False)).findings,
        ),
        "Regras + taint analysis": scan_files(files, ScanOptions(use_bandit=False)).findings,
        "Sentinela (regras + taint + Bandit)": full,
    }
    results = {name: score(_as_reported(findings), expected) for name, findings in configurations.items()}

    # Bandit sozinho, só nos arquivos Python, severidade média ou maior.
    bandit_reported = []
    for source in files:
        if source.path.endswith(".py"):
            for issue in run_bandit(source.content):
                if issue.severity in {"medium", "high"}:
                    bandit_reported.append(
                        Reported(source.path, issue.line, issue.end_line, f"CWE-{issue.cwe}", issue.test_id)
                    )
    python_expected = [e for e in expected if e.path.endswith(".py")]
    results["Bandit sozinho (só Python)"] = score(bandit_reported, python_expected)
    sentinela_python = [f for f in full if f.file_path.endswith(".py")]
    results["Sentinela (só Python, para comparar)"] = score(_as_reported(sentinela_python), python_expected)

    if ai_assistant is not None:
        kept = []
        for finding in full:
            assessment = ai_assistant.assess(finding)
            if assessment is not None and assessment.dismisses:
                continue
            kept.append(finding)
        results["Sentinela + triagem por IA"] = score(_as_reported(kept), expected)
    return expected, results


def render(expected: list[Expected], results: dict[str, Score]) -> str:
    by_language = defaultdict(int)
    for item in expected:
        by_language[item.path.split("/")[0]] += 1
    lines = [
        "# Benchmark do Sentinela",
        "",
        f"Verdade: **{len(expected)} vulnerabilidades rotuladas** "
        + ", ".join(f"{lang}: {n}" for lang, n in sorted(by_language.items()))
        + " em `benchmark/corpus/`.",
        "",
        "| Configuração | VP | FP | FN | Precisão | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, result in results.items():
        lines.append(
            f"| {name} | {result.tp} | {result.fp} | {result.fn} | {result.precision:.0%} | {result.recall:.0%} | {result.f1:.2f} |",
        )
    main = results.get("Sentinela + triagem por IA") or results["Sentinela (regras + taint + Bandit)"]
    if main.false_positives or main.missed:
        lines += ["", "## Detalhe da configuração principal"]
        lines += [f"- FP `{r.path}:{r.line}` {r.rule} ({r.cwe})" for r in main.false_positives]
        lines += [f"- FN `{e.path}:{e.line}` esperado {e.cwe}" for e in main.missed]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark de precisão/recall do Sentinela")
    parser.add_argument("--markdown", type=Path, help="grava o relatório neste arquivo")
    parser.add_argument("--ai", action="store_true", help="inclui a triagem por IA (precisa do Ollama)")
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument("--model", default="llama3")
    args = parser.parse_args()

    assistant = None
    if args.ai:
        from sentinela.ai.assistant import OllamaAssistant

        assistant = OllamaAssistant(base_url=args.ollama_url, model=args.model, timeout=120)
        if not assistant.health():
            raise SystemExit(f"Ollama não respondeu em {args.ollama_url}.")

    expected, results = run(assistant)
    report = render(expected, results)
    print(report)
    if args.markdown:
        args.markdown.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
