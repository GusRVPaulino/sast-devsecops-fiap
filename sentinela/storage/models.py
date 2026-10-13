"""Tabelas do PostgreSQL (SQLAlchemy 2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list[Scan]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    # queued -> analyzing -> ai_review -> completed | failed
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    trigger: Mapped[str] = mapped_column(String(20), default="api")  # api | upload | ci | cli
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(200))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0)
    files_skipped: Mapped[list] = mapped_column(JSON, default=list)
    languages: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    gate_status: Mapped[str | None] = mapped_column(String(20))
    gate_reasons: Mapped[list] = mapped_column(JSON, default=list)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="scans")
    files: Mapped[list[ScanFile]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list[FindingRow]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanFile(Base):
    """Conteúdo enviado para análise — é como o worker recebe o código."""

    __tablename__ = "scan_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(String(1024))
    content: Mapped[str] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="files")


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(300))
    language: Mapped[str] = mapped_column(String(30))
    file_path: Mapped[str] = mapped_column(String(1024), index=True)
    line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    column: Mapped[int] = mapped_column(Integer, default=1)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    cwe: Mapped[str] = mapped_column(String(20), index=True)
    owasp: Mapped[str] = mapped_column(String(120), default="")
    message: Mapped[str] = mapped_column(Text)
    snippet: Mapped[str] = mapped_column(Text, default="")
    context: Mapped[str] = mapped_column(Text, default="")
    engines: Mapped[list] = mapped_column(JSON, default=list)
    taint_path: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str] = mapped_column(Text, default="")
    safe_example: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    # Análise da IA (consultiva)
    ai_verdict: Mapped[str | None] = mapped_column(String(20))
    ai_confidence: Mapped[str | None] = mapped_column(String(10))
    ai_rationale: Mapped[str | None] = mapped_column(Text)
    ai_suggested_severity: Mapped[str | None] = mapped_column(String(10))
    ai_fix_explanation: Mapped[str | None] = mapped_column(Text)
    ai_fix_code: Mapped[str | None] = mapped_column(Text)
    ai_model: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class FindingState(Base):
    """Decisão do revisor sobre um achado — vale para todos os scans futuros.

    Chaveada por fingerprint: marcar algo como falso positivo hoje continua
    valendo no próximo PR, mesmo que o código tenha mudado de linha.
    """

    __tablename__ = "finding_states"
    __table_args__ = (UniqueConstraint("project_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class StateHistory(Base):
    __tablename__ = "finding_state_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    from_status: Mapped[str] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    note: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(200), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
