"""esquema inicial

Revision ID: 0001
Revises:
Create Date: 2026-10-13 16:02:46.540590
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("projects", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_projects_name"), ["name"], unique=True)

    op.create_table(
        "finding_state_history",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("from_status", sa.String(length=20), nullable=False),
        sa.Column("to_status", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("finding_state_history", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_finding_state_history_fingerprint"), ["fingerprint"], unique=False)
        batch_op.create_index(batch_op.f("ix_finding_state_history_project_id"), ["project_id"], unique=False)

    op.create_table(
        "finding_states",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "fingerprint"),
    )
    with op.batch_alter_table("finding_states", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_finding_states_project_id"), ["project_id"], unique=False)

    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("trigger", sa.String(length=20), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=200), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("files_scanned", sa.Integer(), nullable=False),
        sa.Column("files_skipped", sa.JSON(), nullable=False),
        sa.Column("languages", sa.JSON(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("gate_status", sa.String(length=20), nullable=True),
        sa.Column("gate_reasons", sa.JSON(), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scans_created_at"), ["created_at"], unique=False)
        batch_op.create_index(batch_op.f("ix_scans_project_id"), ["project_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_scans_status"), ["status"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("language", sa.String(length=30), nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("column", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("confidence", sa.String(length=10), nullable=False),
        sa.Column("cwe", sa.String(length=20), nullable=False),
        sa.Column("owasp", sa.String(length=120), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=False),
        sa.Column("context", sa.Text(), nullable=False),
        sa.Column("engines", sa.JSON(), nullable=False),
        sa.Column("taint_path", sa.JSON(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("safe_example", sa.Text(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("ai_verdict", sa.String(length=20), nullable=True),
        sa.Column("ai_confidence", sa.String(length=10), nullable=True),
        sa.Column("ai_rationale", sa.Text(), nullable=True),
        sa.Column("ai_suggested_severity", sa.String(length=10), nullable=True),
        sa.Column("ai_fix_explanation", sa.Text(), nullable=True),
        sa.Column("ai_fix_code", sa.Text(), nullable=True),
        sa.Column("ai_model", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_findings_cwe"), ["cwe"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_file_path"), ["file_path"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_fingerprint"), ["fingerprint"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_project_id"), ["project_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_rule_id"), ["rule_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_scan_id"), ["scan_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_findings_severity"), ["severity"], unique=False)

    op.create_table(
        "scan_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scan_files", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_scan_files_scan_id"), ["scan_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("scan_files", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scan_files_scan_id"))

    op.drop_table("scan_files")
    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_findings_severity"))
        batch_op.drop_index(batch_op.f("ix_findings_scan_id"))
        batch_op.drop_index(batch_op.f("ix_findings_rule_id"))
        batch_op.drop_index(batch_op.f("ix_findings_project_id"))
        batch_op.drop_index(batch_op.f("ix_findings_fingerprint"))
        batch_op.drop_index(batch_op.f("ix_findings_file_path"))
        batch_op.drop_index(batch_op.f("ix_findings_cwe"))

    op.drop_table("findings")
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_scans_status"))
        batch_op.drop_index(batch_op.f("ix_scans_project_id"))
        batch_op.drop_index(batch_op.f("ix_scans_created_at"))

    op.drop_table("scans")
    with op.batch_alter_table("finding_states", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_finding_states_project_id"))

    op.drop_table("finding_states")
    with op.batch_alter_table("finding_state_history", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_finding_state_history_project_id"))
        batch_op.drop_index(batch_op.f("ix_finding_state_history_fingerprint"))

    op.drop_table("finding_state_history")
    with op.batch_alter_table("projects", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_projects_name"))

    op.drop_table("projects")
