"""Add durable single-worker assessment orchestration."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0004_orchestration"
down_revision = "0003_nuclei"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assessment_manifests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", sa.Text, sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("scope_snapshot_id", sa.String(64), nullable=False),
        sa.Column("config_snapshot", JSONB, nullable=False),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("worker_token", UUID(as_uuid=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("reason", sa.Text),
        sa.ForeignKeyConstraint(
            ["scope_snapshot_id", "project_id"],
            ["scope_snapshots.id", "scope_snapshots.project_id"],
        ),
        sa.UniqueConstraint("id", "project_id"),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed','interrupted')",
            name="assessment_manifest_status",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND finished_at IS NULL AND worker_token IS NULL AND reason IS NULL) OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL AND worker_token IS NOT NULL AND reason IS NULL) OR (status = 'completed' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND worker_token IS NULL AND reason IS NULL) OR (status IN ('failed','interrupted') AND started_at IS NOT NULL AND finished_at IS NOT NULL AND worker_token IS NULL AND reason IS NOT NULL)",
            name="assessment_manifest_lifecycle",
        ),
        sa.CheckConstraint(
            "finished_at IS NULL OR finished_at >= started_at",
            name="assessment_manifest_time_order",
        ),
    )
    op.create_index(
        "ix_assessment_manifests_pending",
        "assessment_manifests",
        ["created_at", "id"],
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        "ix_assessment_manifests_project",
        "assessment_manifests",
        ["project_id", "created_at", "id"],
    )
    op.create_table(
        "assessment_stages",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("assessment_id", UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", sa.Text, nullable=False),
        sa.Column("ordinal", sa.Integer, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("request", JSONB, nullable=False),
        sa.Column("planned_run_id", UUID(as_uuid=True), unique=True),
        sa.Column("result_run_id", UUID(as_uuid=True), unique=True),
        sa.Column("status", sa.Text, nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("reason", sa.Text),
        sa.ForeignKeyConstraint(
            ["assessment_id", "project_id"],
            ["assessment_manifests.id", "assessment_manifests.project_id"],
        ),
        sa.ForeignKeyConstraint(
            ["result_run_id", "project_id"], ["runs.id", "runs.project_id"]
        ),
        sa.UniqueConstraint("assessment_id", "ordinal"),
        sa.UniqueConstraint("id", "project_id"),
        sa.CheckConstraint("ordinal >= 0", name="assessment_stage_ordinal"),
        sa.CheckConstraint(
            "kind IN ('nmap','httpx','nuclei','web_recheck')",
            name="assessment_stage_kind",
        ),
        sa.CheckConstraint(
            "status IN ('pending','running','completed','failed','skipped','interrupted')",
            name="assessment_stage_status",
        ),
        sa.CheckConstraint(
            "(kind = 'web_recheck' AND planned_run_id IS NULL) OR (kind <> 'web_recheck' AND planned_run_id IS NOT NULL)",
            name="assessment_stage_planned_run",
        ),
        sa.CheckConstraint(
            "(kind = 'web_recheck' AND result_run_id IS NULL) OR (kind <> 'web_recheck' AND (result_run_id IS NULL OR result_run_id = planned_run_id))",
            name="assessment_stage_result_run",
        ),
        sa.CheckConstraint(
            "status <> 'completed' OR kind = 'web_recheck' OR result_run_id IS NOT NULL",
            name="assessment_stage_completed_result",
        ),
        sa.CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND finished_at IS NULL AND reason IS NULL AND result_run_id IS NULL) OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL AND reason IS NULL AND result_run_id IS NULL) OR (status = 'completed' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND reason IS NULL) OR (status = 'skipped' AND started_at IS NULL AND finished_at IS NOT NULL AND reason IS NOT NULL AND result_run_id IS NULL) OR (status IN ('failed','interrupted') AND started_at IS NOT NULL AND finished_at IS NOT NULL AND reason IS NOT NULL)",
            name="assessment_stage_lifecycle",
        ),
        sa.CheckConstraint(
            "finished_at IS NULL OR started_at IS NULL OR finished_at >= started_at",
            name="assessment_stage_time_order",
        ),
    )
    op.create_index(
        "ix_assessment_stages_project",
        "assessment_stages",
        ["project_id", "assessment_id"],
    )
    op.create_table(
        "recheck_reports",
        sa.Column("stage_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", sa.Text, nullable=False),
        sa.Column("report", JSONB, nullable=False),
        sa.ForeignKeyConstraint(
            ["stage_id", "project_id"],
            ["assessment_stages.id", "assessment_stages.project_id"],
        ),
    )
    op.create_table(
        "recheck_artifacts",
        sa.Column("acquisition_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("stage_id", UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", sa.Text, nullable=False),
        sa.Column("relative_path", sa.Text, nullable=False, unique=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("health", sa.Text, nullable=False),
        sa.ForeignKeyConstraint(
            ["stage_id", "project_id"],
            ["assessment_stages.id", "assessment_stages.project_id"],
        ),
        sa.UniqueConstraint("acquisition_id", "stage_id"),
        sa.CheckConstraint(
            "relative_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/response[.]http$'",
            name="recheck_artifact_path",
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="recheck_artifact_digest"),
        sa.CheckConstraint(
            "size_bytes BETWEEN 0 AND 8388608", name="recheck_artifact_size"
        ),
        sa.CheckConstraint(
            "health IN ('ready','missing','corrupt')", name="recheck_artifact_health"
        ),
    )
    op.create_index(
        "ix_recheck_artifacts_stage", "recheck_artifacts", ["stage_id", "project_id"]
    )


def downgrade() -> None:
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM assessment_manifests)")
    ):
        raise RuntimeError("cannot downgrade while assessment manifests exist")
    op.drop_index("ix_recheck_artifacts_stage", table_name="recheck_artifacts")
    op.drop_table("recheck_artifacts")
    op.drop_table("recheck_reports")
    op.drop_index("ix_assessment_stages_project", table_name="assessment_stages")
    op.drop_table("assessment_stages")
    op.drop_index("ix_assessment_manifests_project", table_name="assessment_manifests")
    op.drop_index("ix_assessment_manifests_pending", table_name="assessment_manifests")
    op.drop_table("assessment_manifests")
