"""CLI ``sentinela`` — análise local e Security Gate para pipelines CI/CD.

Exemplos::

    sentinela scan src/                       # analisa um diretório
    sentinela scan . --diff origin/main       # só arquivos alterados no PR
    sentinela scan . --sarif out.sarif --markdown pr.md --ai
    sentinela scan . --api http://sentinela:8000 --project loja   # envia ao servidor
    sentinela serve                           # sobe a API + dashboard

Código de saída: 0 = gate aprovado (ou com avisos), 1 = gate bloqueado,
2 = erro de uso. Use ``--no-fail`` para só reportar.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from sentinela import __version__
from sentinela.engine.languages import detect_language
from sentinela.engine.models import SourceFile
from sentinela.engine.scanner import ScanOptions, scan_files
from sentinela.gate import GatePolicy, evaluate
from sentinela.reporting.markdown import pr_comment
from sentinela.reporting.sarif import to_sarif

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".tox", ".mypy_cache"}
_COLORS = {"critical": "\033[41;97m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[90m"}
_RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinela", description="Sentinela — SAST & DevSecOps")
    parser.add_argument("--version", action="version", version=f"sentinela {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analisa arquivos e aplica o Security Gate")
    scan.add_argument("paths", nargs="*", default=["."], help="arquivos ou diretórios (padrão: .)")
    scan.add_argument("--diff", metavar="REF", help="analisa só os arquivos alterados desde REF (git)")
    scan.add_argument("--project", default=os.environ.get("GITHUB_REPOSITORY", Path.cwd().name))
    scan.add_argument("--policy", default=".sentinela.yml", help="arquivo de política do gate")
    scan.add_argument("--sarif", metavar="ARQ", help="grava relatório SARIF 2.1.0")
    scan.add_argument("--markdown", metavar="ARQ", help="grava relatório Markdown (comentário de PR)")
    scan.add_argument("--json", metavar="ARQ", help="grava resultado completo em JSON")
    scan.add_argument("--ai", action="store_true", help="triagem e correção por IA local (Ollama)")
    scan.add_argument("--ollama-url", default=os.environ.get("SENTINELA_OLLAMA_URL", "http://localhost:11434"))
    scan.add_argument("--model", default=os.environ.get("SENTINELA_OLLAMA_MODEL", "llama3"))
    scan.add_argument("--api", metavar="URL", help="envia ao servidor Sentinela em vez de analisar localmente")
    scan.add_argument("--api-token", default=os.environ.get("SENTINELA_API_TOKEN"))
    scan.add_argument("--no-bandit", action="store_true", help="não usar o Bandit como segundo motor")
    scan.add_argument("--no-fail", action="store_true", help="sempre sai com código 0")
    scan.add_argument("--quiet", action="store_true")

    serve = sub.add_parser("serve", help="sobe a API e o dashboard")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8000)

    args = parser.parse_args(argv)
    if args.command == "serve":
        return _serve(args)
    return _scan(args)


# --------------------------------------------------------------------- scan
def _scan(args: argparse.Namespace) -> int:
    files = _collect(args.paths, args.diff)
    if not files:
        print("Nenhum arquivo Python, JavaScript ou Java para analisar.")
        return 0

    policy = GatePolicy.load(args.policy)
    commit = os.environ.get("GITHUB_SHA")
    if args.api:
        findings, gate = _scan_remote(args, files, policy, commit)
    else:
        findings, gate = _scan_local(args, files, policy)

    if args.sarif:
        _write(
            args.sarif,
            json.dumps(to_sarif(findings, commit_sha=commit, repository=args.project), indent=2, ensure_ascii=False),
        )
    if args.markdown:
        _write(args.markdown, pr_comment(findings, gate))
    if args.json:
        _write(args.json, json.dumps({"gate": gate, "findings": findings}, indent=2, ensure_ascii=False))
    if not args.quiet:
        _print_report(findings, gate, len(files))

    if gate["status"] == "failed" and not args.no_fail:
        return 1
    return 0


def _scan_local(args: argparse.Namespace, files: list[SourceFile], policy: GatePolicy) -> tuple[list[dict], dict]:
    result = scan_files(files, ScanOptions(use_bandit=not args.no_bandit, scope=args.project))
    assistant = None
    if args.ai:
        from sentinela.ai.assistant import OllamaAssistant

        assistant = OllamaAssistant(base_url=args.ollama_url, model=args.model)
        if not assistant.health():
            print(f"⚠ Ollama indisponível em {args.ollama_url}; seguindo sem IA.", file=sys.stderr)
            assistant = None

    findings = []
    for finding in result.findings:
        data = _finding_dict(finding)
        if assistant is not None and assistant.available:
            assessment = assistant.assess(finding)
            data["ai"] = assessment.to_dict() if assessment else None
        findings.append(data)
    gate = evaluate(findings, policy).to_dict()
    return findings, gate


def _scan_remote(
    args: argparse.Namespace, files: list[SourceFile], policy: GatePolicy, commit: str | None
) -> tuple[list[dict], dict]:
    import httpx

    headers = {"X-API-Token": args.api_token} if args.api_token else {}
    pr = os.environ.get("SENTINELA_PR_NUMBER")
    body = {
        "project": args.project,
        "files": [{"path": f.path, "content": f.content} for f in files],
        "commit_sha": commit,
        "branch": os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME"),
        "pr_number": int(pr) if pr and pr.isdigit() else None,
        "trigger": "ci",
        "policy": policy.to_dict(),
    }
    base = args.api.rstrip("/")
    scan = httpx.post(f"{base}/api/scans", json=body, headers=headers, timeout=120).raise_for_status().json()
    deadline = time.time() + 900
    while scan["status"] not in {"completed", "failed"}:
        if time.time() > deadline:
            raise SystemExit("Tempo esgotado esperando o servidor concluir o scan.")
        time.sleep(3)
        scan = httpx.get(f"{base}/api/scans/{scan['id']}", timeout=30).raise_for_status().json()
    if scan["status"] == "failed":
        raise SystemExit(f"Scan falhou no servidor: {scan.get('error')}")
    findings = httpx.get(f"{base}/api/scans/{scan['id']}/findings", timeout=60).raise_for_status().json()
    gate = evaluate(findings, policy).to_dict()
    gate["dashboard"] = f"{base}/#/scan/{scan['id']}"
    return findings, gate


def _finding_dict(finding) -> dict:
    return {
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "language": finding.language,
        "file_path": finding.file_path,
        "line": finding.line,
        "end_line": finding.end_line,
        "column": finding.column,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "cwe": finding.cwe,
        "owasp": finding.owasp,
        "message": finding.message,
        "snippet": finding.snippet,
        "engines": sorted(e.value for e in finding.engines),
        "taint_path": [asdict(step) for step in finding.taint_path],
        "remediation": finding.remediation,
        "safe_example": finding.safe_example,
        "references": finding.references,
        "status": "open",
        "ai": None,
    }


# ------------------------------------------------------------------ arquivos
def _collect(paths: list[str], diff_ref: str | None) -> list[SourceFile]:
    candidates: list[Path] = []
    if diff_ref:
        changed = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", f"{diff_ref}...HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
        candidates = [Path(p) for p in changed]
    else:
        for raw in paths:
            path = Path(raw)
            if path.is_dir():
                for child in sorted(path.rglob("*")):
                    if child.is_file() and not (set(child.parts) & _SKIP_DIRS):
                        candidates.append(child)
            elif path.is_file():
                candidates.append(path)

    files = []
    for path in candidates:
        rel = path.as_posix().removeprefix("./")
        if not path.is_file() or detect_language(rel) is None:
            continue
        try:
            files.append(SourceFile(path=rel, content=path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return files


# ------------------------------------------------------------------- saída
def _print_report(findings: list[dict], gate: dict, file_count: int) -> None:
    color = sys.stdout.isatty()
    print(f"\nSentinela {__version__} — {file_count} arquivo(s) analisado(s), {len(findings)} achado(s)\n")
    for f in findings:
        sev = f["severity"].upper()
        tag = f"{_COLORS[f['severity']]}{sev:8}{_RESET}" if color else f"{sev:8}"
        ai = f.get("ai") or {}
        verdict = f"  [IA: {ai['verdict']}/{ai['confidence']}]" if ai else ""
        print(f"{tag} {f['file_path']}:{f['line']}  {f['title']} ({f['cwe']}){verdict}")
        print(f"         {f['snippet'].splitlines()[0] if f['snippet'] else ''}")
        for step in f.get("taint_path", []):
            print(f"           ↳ linha {step['line']} {step['kind']}: {step['code']}")
    status = {"passed": "APROVADO", "warned": "APROVADO COM AVISOS", "failed": "BLOQUEADO"}[gate["status"]]
    print(f"\nSecurity Gate: {status}")
    for reason in gate["reasons"][:20]:
        print(f"  - {reason}")
    if gate.get("dashboard"):
        print(f"\nDashboard: {gate['dashboard']}")


def _write(path: str, content: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(content, encoding="utf-8")


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    from sentinela.storage.db import create_all

    create_all()
    uvicorn.run("sentinela.api.app:app", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
