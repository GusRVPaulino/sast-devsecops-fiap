"""API REST do Sentinela (FastAPI)."""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from sentinela import __version__, services
from sentinela.config import get_settings
from sentinela.engine.languages import detect_language
from sentinela.engine.rules import load_rules
from sentinela.engine.taint import load_taint_spec
from sentinela.reporting.markdown import pr_comment
from sentinela.reporting.sarif import to_sarif
from sentinela.storage.db import session_scope

logger = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "target", ".idea"}


# ------------------------------------------------------------------ schemas
class FileIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str


class ScanIn(BaseModel):
    project: str = Field(min_length=1, max_length=200)
    files: list[FileIn] = Field(min_length=1)
    commit_sha: str | None = None
    branch: str | None = None
    pr_number: int | None = None
    trigger: str = "api"
    policy: dict[str, Any] | None = None


class ReviewIn(BaseModel):
    status: str
    note: str = ""
    actor: str = "dashboard"


# ---------------------------------------------------------------------- app
def require_token(x_api_token: str | None = Header(default=None)) -> None:
    expected = get_settings().api_token
    if expected and x_api_token != expected:
        raise HTTPException(status_code=401, detail="X-API-Token inválido ou ausente")


app = FastAPI(
    title="Sentinela",
    version=__version__,
    description="Plataforma SAST & DevSecOps: análise estática multi-linguagem, taint analysis, IA local e Security Gate.",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "PATCH"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["sistema"])
def health() -> dict[str, Any]:
    settings = get_settings()
    return {"status": "ok", "version": __version__, "mode": settings.execution_mode, "ai_enabled": settings.ai_enabled}


# -------------------------------------------------------------------- scans
@app.post("/api/scans", status_code=202, tags=["scans"], dependencies=[Depends(require_token)])
def create_scan(body: ScanIn) -> dict[str, Any]:
    files = [(_safe_path(f.path), f.content) for f in body.files]
    return _start_scan(
        project=body.project,
        files=files,
        trigger=body.trigger,
        commit_sha=body.commit_sha,
        branch=body.branch,
        pr_number=body.pr_number,
        policy=body.policy,
    )


@app.post("/api/scans/upload", status_code=202, tags=["scans"], dependencies=[Depends(require_token)])
async def upload_scan(
    project: str = Form(...),
    archive: UploadFile = File(..., description="Arquivo .zip com o código"),
    commit_sha: str | None = Form(default=None),
    branch: str | None = Form(default=None),
) -> dict[str, Any]:
    limit = get_settings().max_upload_mb * 1024 * 1024
    data = await archive.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"Arquivo maior que {get_settings().max_upload_mb} MB")
    files = _files_from_zip(data)
    if not files:
        raise HTTPException(422, "Nenhum arquivo .py, .js ou .java encontrado no zip")
    return _start_scan(project=project, files=files, trigger="upload", commit_sha=commit_sha, branch=branch)


@app.get("/api/scans", tags=["scans"])
def list_scans(project: str | None = None, limit: int = Query(20, le=100)) -> list[dict[str, Any]]:
    from sqlalchemy import select

    from sentinela.storage.models import Project, Scan

    with session_scope() as session:
        query = select(Scan).order_by(Scan.created_at.desc()).limit(limit)
        if project:
            query = query.join(Project).where(Project.name == project)
        return [services.scan_dict(scan, counts=_counts(scan)) for scan in session.scalars(query)]


@app.get("/api/scans/{scan_id}", tags=["scans"])
def get_scan(scan_id: str) -> dict[str, Any]:
    with session_scope() as session:
        scan = _get_scan(session, scan_id)
        return services.scan_dict(scan, counts=_counts(scan))


@app.get("/api/scans/{scan_id}/findings", tags=["scans"])
def get_findings(
    scan_id: str,
    severity: str | None = None,
    status: str | None = None,
    ai_verdict: str | None = None,
) -> list[dict[str, Any]]:
    with session_scope() as session:
        _get_scan(session, scan_id)
        findings = services.scan_findings(session, scan_id)
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if status:
        findings = [f for f in findings if f["status"] == status]
    if ai_verdict:
        findings = [f for f in findings if (f["ai"] or {}).get("verdict") == ai_verdict]
    return findings


@app.get("/api/scans/{scan_id}/gate", tags=["relatórios"])
def get_gate(scan_id: str) -> dict[str, Any]:
    with session_scope() as session:
        scan = _get_scan(session, scan_id)
        if scan.status != "completed":
            raise HTTPException(409, f"Scan ainda em andamento (status: {scan.status})")
        return {"scan_id": scan.id, "status": scan.gate_status, "reasons": scan.gate_reasons, "policy": scan.policy}


@app.get("/api/scans/{scan_id}/sarif", tags=["relatórios"])
def get_sarif(scan_id: str) -> dict[str, Any]:
    with session_scope() as session:
        scan = _ensure_completed(session, scan_id)
        findings = services.scan_findings(session, scan_id)
        return to_sarif(findings, commit_sha=scan.commit_sha, repository=scan.project.name)


@app.get("/api/scans/{scan_id}/report.md", tags=["relatórios"], response_class=PlainTextResponse)
def get_markdown(scan_id: str) -> str:
    with session_scope() as session:
        scan = _ensure_completed(session, scan_id)
        findings = services.scan_findings(session, scan_id)
        gate = {"status": scan.gate_status, "blocking": _blocking(findings, scan.policy)}
        return pr_comment(findings, gate)


# ------------------------------------------------------------------ achados
@app.patch("/api/findings/{finding_id}", tags=["achados"], dependencies=[Depends(require_token)])
def review_finding(finding_id: str, body: ReviewIn) -> dict[str, Any]:
    try:
        return services.update_finding_state(finding_id, status=body.status, note=body.note, actor=body.actor)
    except services.NotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


# ----------------------------------------------------------------- projetos
@app.get("/api/projects", tags=["projetos"])
def projects() -> list[dict[str, Any]]:
    with session_scope() as session:
        return services.list_projects(session)


@app.get("/api/projects/{name}/metrics", tags=["projetos"])
def metrics(name: str) -> dict[str, Any]:
    with session_scope() as session:
        try:
            return services.project_metrics(session, name)
        except services.NotFound as exc:
            raise HTTPException(404, str(exc)) from exc


@app.get("/api/rules", tags=["regras"])
def rules() -> list[dict[str, Any]]:
    catalog = []
    for language in ("python", "javascript", "java"):
        for rule in load_rules(language):
            catalog.append(
                {
                    "id": rule.id,
                    "language": language,
                    "kind": "padrão",
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "cwe": rule.cwe,
                    "owasp": rule.owasp,
                },
            )
        spec = load_taint_spec(language)
        for sink in spec.sinks if spec else ():
            catalog.append(
                {
                    "id": sink.id,
                    "language": language,
                    "kind": "taint",
                    "title": sink.title,
                    "severity": sink.severity.value,
                    "cwe": sink.cwe,
                    "owasp": sink.owasp,
                },
            )
    catalog.append(
        {
            "id": "secrets.hardcoded-credential",
            "language": "todas",
            "kind": "segredos",
            "title": "Credencial no código-fonte",
            "severity": "high",
            "cwe": "CWE-798",
            "owasp": "A07:2021 - Identification and Authentication Failures",
        },
    )
    return catalog


# ------------------------------------------------------------------ helpers
def _start_scan(*, project: str, files: list[tuple[str, str]], **meta: Any) -> dict[str, Any]:
    with session_scope() as session:
        scan = services.create_scan(session, project=project, files=files, **meta)
        scan_id = scan.id

    if get_settings().execution_mode == "queue":
        try:
            from sentinela.worker.tasks import enqueue_scan

            enqueue_scan(scan_id)
        except Exception:
            logger.warning("Fila indisponível; processando o scan %s na própria API.", scan_id, exc_info=True)
            services.process_inline(scan_id)
    else:
        services.process_inline(scan_id)
    return get_scan(scan_id)


def _get_scan(session: Any, scan_id: str) -> Any:
    from sentinela.storage.models import Scan

    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan não encontrado")
    return scan


def _ensure_completed(session: Any, scan_id: str) -> Any:
    scan = _get_scan(session, scan_id)
    if scan.status != "completed":
        raise HTTPException(409, f"Scan ainda em andamento (status: {scan.status})")
    return scan


def _counts(scan: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in scan.findings:
        counts[row.severity] = counts.get(row.severity, 0) + 1
    counts["total"] = len(scan.findings)
    return counts


def _blocking(findings: list[dict[str, Any]], policy: dict[str, Any]) -> list[str]:
    from sentinela.gate import GatePolicy, evaluate

    return evaluate(findings, GatePolicy.from_dict(policy)).blocking


def _safe_path(path: str) -> str:
    parts = [p for p in PurePosixPath(path.replace("\\", "/")).parts if p not in {"..", "/", "."}]
    return "/".join(parts) or "arquivo"


def _files_from_zip(data: bytes) -> list[tuple[str, str]]:
    """Lê o zip em memória (nada é extraído em disco, então não há zip slip)."""

    files = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise HTTPException(422, "Arquivo enviado não é um .zip válido") from exc
    total = 0
    for info in archive.infolist():
        if info.is_dir() or info.file_size > 1_000_000:
            continue
        path = _safe_path(info.filename)
        if set(PurePosixPath(path).parts) & _SKIP_DIRS or detect_language(path) is None:
            continue
        total += info.file_size
        if total > 50_000_000:  # proteção contra zip bomb
            raise HTTPException(413, "Conteúdo descompactado grande demais")
        files.append((path, archive.read(info).decode("utf-8", errors="replace")))
    return files
