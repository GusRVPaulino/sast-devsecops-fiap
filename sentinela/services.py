"""Casos de uso da plataforma — usados pela API, pelos workers e pela CLI.

Pipeline de um scan (cada etapa é uma tarefa Celery em modo ``queue``):

    create_scan  ->  analyze_scan  ->  assess_finding (xN, fila "ai")  ->  finalize_scan
    (API)            (fila "analysis")                                      (gate + status)
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinela.ai.assistant import AIAssessment, OllamaAssistant, assistant_from_env
from sentinela.config import get_settings
from sentinela.engine.models import Finding, Severity, SourceFile
from sentinela.engine.scanner import ScanOptions, scan_files
from sentinela.gate import GatePolicy, evaluate
from sentinela.storage.db import session_scope
from sentinela.storage.models import FindingRow, FindingState, Project, Scan, ScanFile, StateHistory

REVIEW_STATUSES = ("open", "confirmed", "false_positive", "accepted_risk", "fixed")


class NotFound(Exception):
    pass


# --------------------------------------------------------------------- scans
def get_or_create_project(session: Session, name: str) -> Project:
    project = session.scalar(select(Project).where(Project.name == name))
    if project is None:
        project = Project(name=name)
        session.add(project)
        session.flush()
    return project


def create_scan(
    session: Session,
    *,
    project: str,
    files: list[tuple[str, str]],
    trigger: str = "api",
    commit_sha: str | None = None,
    branch: str | None = None,
    pr_number: int | None = None,
    policy: dict[str, Any] | None = None,
) -> Scan:
    proj = get_or_create_project(session, project)
    scan = Scan(
        project_id=proj.id,
        trigger=trigger,
        commit_sha=commit_sha,
        branch=branch,
        pr_number=pr_number,
        policy=GatePolicy.from_dict(policy).to_dict(),
        status="queued",
    )
    session.add(scan)
    session.flush()
    session.add_all(ScanFile(scan_id=scan.id, path=path, content=content) for path, content in files)
    return scan


def analyze_scan(scan_id: str) -> list[str]:
    """Roda o motor SAST e grava os achados. Retorna os ids dos achados."""

    with session_scope() as session:
        scan = _scan(session, scan_id)
        scan.status = "analyzing"
        project_name = scan.project.name
        sources = [SourceFile(path=f.path, content=f.content) for f in scan.files]

    try:
        result = scan_files(
            sources,
            ScanOptions(use_bandit=get_settings().use_bandit, scope=project_name),
        )
    except Exception as exc:
        _fail(scan_id, f"Erro no motor de análise: {type(exc).__name__}")
        raise

    with session_scope() as session:
        scan = _scan(session, scan_id)
        scan.files_scanned = result.files_scanned
        scan.files_skipped = [list(item) for item in result.files_skipped]
        scan.languages = result.languages
        scan.duration_ms = result.duration_ms
        rows = [_row_from_finding(scan, finding) for finding in result.findings]
        session.add_all(rows)
        scan.status = "ai_review" if rows else "finalizing"
        # Código-fonte não precisa ficar guardado depois da análise.
        for file in list(scan.files):
            session.delete(file)
        session.flush()
        return [row.id for row in rows]


def assess_finding(finding_id: str, assistant: OllamaAssistant | None = None) -> bool:
    """Pede à IA local a triagem/correção de um achado. Falha silenciosa."""

    assistant = assistant if assistant is not None else assistant_from_env()
    if assistant is None or not assistant.available:
        return False
    with session_scope() as session:
        row = session.get(FindingRow, finding_id)
        if row is None:
            return False
        finding = _finding_from_row(row)
    assessment = assistant.assess(finding)
    if assessment is None:
        return False
    with session_scope() as session:
        row = session.get(FindingRow, finding_id)
        if row is not None:
            _apply_assessment(row, assessment)
    return True


def finalize_scan(scan_id: str) -> dict[str, Any]:
    with session_scope() as session:
        scan = _scan(session, scan_id)
        states = _states(session, scan.project_id)
        findings = [finding_dict(row, states) for row in scan.findings]
        decision = evaluate(findings, GatePolicy.from_dict(scan.policy))
        scan.gate_status = decision.status
        scan.gate_reasons = decision.reasons
        scan.status = "completed"
        scan.finished_at = datetime.now(UTC)
        return decision.to_dict()


def process_inline(scan_id: str, assistant: OllamaAssistant | None = None) -> dict[str, Any]:
    """Executa todas as etapas na sequência (modo ``inline``, testes, CLI)."""

    finding_ids = analyze_scan(scan_id)
    assistant = assistant if assistant is not None else assistant_from_env()
    for finding_id in finding_ids:
        if assistant is None or not assistant.available:
            break
        assess_finding(finding_id, assistant)
    return finalize_scan(scan_id)


def _fail(scan_id: str, message: str) -> None:
    with session_scope() as session:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = message
            scan.finished_at = datetime.now(UTC)


# ----------------------------------------------------------------- revisão
def update_finding_state(finding_id: str, *, status: str, note: str, actor: str) -> dict[str, Any]:
    if status not in REVIEW_STATUSES:
        raise ValueError(f"status deve ser um de {', '.join(REVIEW_STATUSES)}")
    with session_scope() as session:
        row = session.get(FindingRow, finding_id)
        if row is None:
            raise NotFound("achado não encontrado")
        state = session.scalar(
            select(FindingState).where(
                FindingState.project_id == row.project_id,
                FindingState.fingerprint == row.fingerprint,
            ),
        )
        previous = state.status if state else "open"
        if state is None:
            state = FindingState(project_id=row.project_id, fingerprint=row.fingerprint, status=status)
            session.add(state)
        state.status = status
        state.note = note
        state.updated_by = actor
        session.add(
            StateHistory(
                project_id=row.project_id,
                fingerprint=row.fingerprint,
                from_status=previous,
                to_status=status,
                note=note,
                actor=actor,
            ),
        )
        session.flush()
        return finding_dict(row, {row.fingerprint: state}, include_history=_history(session, row))


# ----------------------------------------------------------- serialização
def finding_dict(
    row: FindingRow,
    states: dict[str, FindingState],
    *,
    include_history: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    state = states.get(row.fingerprint)
    data = {
        "id": row.id,
        "scan_id": row.scan_id,
        "fingerprint": row.fingerprint,
        "rule_id": row.rule_id,
        "title": row.title,
        "language": row.language,
        "file_path": row.file_path,
        "line": row.line,
        "end_line": row.end_line,
        "column": row.column,
        "severity": row.severity,
        "confidence": row.confidence,
        "cwe": row.cwe,
        "owasp": row.owasp,
        "message": row.message,
        "snippet": row.snippet,
        "engines": list(row.engines or []),
        "taint_path": list(row.taint_path or []),
        "remediation": row.remediation,
        "safe_example": row.safe_example,
        "references": list(row.references or []),
        "status": state.status if state else "open",
        "review_note": state.note if state else "",
        "ai": None,
    }
    if row.ai_verdict:
        data["ai"] = {
            "verdict": row.ai_verdict,
            "confidence": row.ai_confidence,
            "rationale": row.ai_rationale,
            "suggested_severity": row.ai_suggested_severity,
            "fix_explanation": row.ai_fix_explanation,
            "fix_code": row.ai_fix_code,
            "model": row.ai_model,
        }
    if include_history is not None:
        data["history"] = include_history
    return data


def scan_dict(scan: Scan, *, counts: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "id": scan.id,
        "project": scan.project.name,
        "status": scan.status,
        "trigger": scan.trigger,
        "commit_sha": scan.commit_sha,
        "branch": scan.branch,
        "pr_number": scan.pr_number,
        "files_scanned": scan.files_scanned,
        "files_skipped": scan.files_skipped,
        "languages": scan.languages,
        "duration_ms": scan.duration_ms,
        "gate": {"status": scan.gate_status, "reasons": scan.gate_reasons, "policy": scan.policy},
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "counts": counts or {},
    }


def scan_findings(session: Session, scan_id: str) -> list[dict[str, Any]]:
    scan = _scan(session, scan_id)
    states = _states(session, scan.project_id)
    rows = sorted(scan.findings, key=lambda r: (-Severity.parse(r.severity).rank, r.file_path, r.line))
    return [finding_dict(row, states) for row in rows]


# ----------------------------------------------------------------- métricas
def project_metrics(session: Session, project_name: str) -> dict[str, Any]:
    """Dados do dashboard executivo para um projeto."""

    project = session.scalar(select(Project).where(Project.name == project_name))
    if project is None:
        raise NotFound("projeto não encontrado")
    states = _states(session, project.id)
    scans = session.scalars(
        select(Scan).where(Scan.project_id == project.id, Scan.status == "completed").order_by(Scan.created_at),
    ).all()
    latest = scans[-1] if scans else None
    current = [finding_dict(row, states) for row in latest.findings] if latest else []
    open_now = [f for f in current if f["status"] in {"open", "confirmed"}]

    severity = Counter(f["severity"] for f in open_now)
    by_file = Counter(f["file_path"] for f in open_now)
    critical_by_file = Counter(f["file_path"] for f in open_now if f["severity"] in {"critical", "high"})
    by_cwe = Counter(f["cwe"] for f in open_now)
    by_owasp = Counter(f["owasp"] for f in open_now if f["owasp"])
    by_language = Counter(f["language"] for f in open_now)
    ai = Counter((f["ai"] or {}).get("verdict", "sem_ia") for f in current)

    trend = []
    for scan in scans[-30:]:
        counts = Counter(row.severity for row in scan.findings if _status(states, row) in {"open", "confirmed"})
        trend.append(
            {
                "scan_id": scan.id,
                "date": scan.created_at.isoformat(),
                "commit": (scan.commit_sha or "")[:7],
                "gate": scan.gate_status,
                **{s.value: counts.get(s.value, 0) for s in Severity},
                "total": sum(counts.values()),
            },
        )

    files_detail = defaultdict(lambda: Counter())
    for f in open_now:
        files_detail[f["file_path"]][f["severity"]] += 1

    return {
        "project": project.name,
        "latest_scan": scan_dict(latest) if latest else None,
        "totals": {
            "open": len(open_now),
            "critical": severity.get("critical", 0),
            "high": severity.get("high", 0),
            "scans": len(scans),
            "gate_failed": sum(1 for s in scans if s.gate_status == "failed"),
            "reviewed": sum(1 for f in current if f["status"] not in {"open"}),
        },
        "severity": {s.value: severity.get(s.value, 0) for s in Severity},
        "trend": trend,
        "top_files": [
            {
                "file": path,
                "total": total,
                "critical_high": critical_by_file.get(path, 0),
                **dict(files_detail[path]),
            }
            for path, total in sorted(by_file.items(), key=lambda kv: (-critical_by_file.get(kv[0], 0), -kv[1]))[:5]
        ],
        "cwe": [{"cwe": k, "count": v} for k, v in by_cwe.most_common(10)],
        "owasp": [{"category": k, "count": v} for k, v in by_owasp.most_common(10)],
        "languages": dict(by_language),
        "ai": dict(ai),
    }


def list_projects(session: Session) -> list[dict[str, Any]]:
    rows = session.execute(
        select(Project.name, func.count(Scan.id), func.max(Scan.created_at))
        .join(Scan, Scan.project_id == Project.id, isouter=True)
        .group_by(Project.id)
        .order_by(func.max(Scan.created_at).desc()),
    ).all()
    return [
        {"name": name, "scans": count, "last_scan": last.isoformat() if last else None} for name, count, last in rows
    ]


# ----------------------------------------------------------------- helpers
def _scan(session: Session, scan_id: str) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise NotFound("scan não encontrado")
    return scan


def _states(session: Session, project_id: int) -> dict[str, FindingState]:
    return {
        state.fingerprint: state
        for state in session.scalars(select(FindingState).where(FindingState.project_id == project_id))
    }


def _status(states: dict[str, FindingState], row: FindingRow) -> str:
    state = states.get(row.fingerprint)
    return state.status if state else "open"


def _history(session: Session, row: FindingRow) -> list[dict[str, Any]]:
    entries = session.scalars(
        select(StateHistory)
        .where(StateHistory.project_id == row.project_id, StateHistory.fingerprint == row.fingerprint)
        .order_by(StateHistory.at),
    )
    return [
        {
            "from": e.from_status,
            "to": e.to_status,
            "note": e.note,
            "actor": e.actor,
            "at": e.at.isoformat() if e.at else None,
        }
        for e in entries
    ]


def _row_from_finding(scan: Scan, finding: Finding) -> FindingRow:
    return FindingRow(
        scan_id=scan.id,
        project_id=scan.project_id,
        fingerprint=finding.fingerprint,
        rule_id=finding.rule_id,
        title=finding.title,
        language=finding.language,
        file_path=finding.file_path,
        line=finding.line,
        end_line=finding.end_line,
        column=finding.column,
        severity=finding.severity.value,
        confidence=finding.confidence,
        cwe=finding.cwe,
        owasp=finding.owasp,
        message=finding.message,
        snippet=finding.snippet,
        context=finding.context,
        engines=sorted(engine.value for engine in finding.engines),
        taint_path=[asdict(step) for step in finding.taint_path],
        remediation=finding.remediation,
        safe_example=finding.safe_example,
        references=finding.references,
    )


def _finding_from_row(row: FindingRow) -> Finding:
    from sentinela.engine.models import Engine, TaintStep

    return Finding(
        rule_id=row.rule_id,
        title=row.title,
        language=row.language,
        file_path=row.file_path,
        line=row.line,
        end_line=row.end_line,
        column=row.column,
        severity=Severity.parse(row.severity),
        cwe=row.cwe,
        owasp=row.owasp,
        message=row.message,
        snippet=row.snippet,
        engines={Engine(e) for e in row.engines or []},
        taint_path=[TaintStep(**step) for step in row.taint_path or []],
        remediation=row.remediation,
        safe_example=row.safe_example,
        context=row.context,
        fingerprint=row.fingerprint,
    )


def _apply_assessment(row: FindingRow, assessment: AIAssessment) -> None:
    row.ai_verdict = assessment.verdict
    row.ai_confidence = assessment.confidence
    row.ai_rationale = assessment.rationale
    row.ai_suggested_severity = assessment.suggested_severity
    row.ai_fix_explanation = assessment.fix_explanation
    row.ai_fix_code = assessment.fix_code
    row.ai_model = assessment.model
