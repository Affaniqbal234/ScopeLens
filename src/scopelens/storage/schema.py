"""Relational contracts for scan history."""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = sa.MetaData()

projects = sa.Table(
    "projects",
    metadata,
    sa.Column("id", sa.Text, primary_key=True),
    sa.Column("name", sa.Text, nullable=False),
)

scope_snapshots = sa.Table(
    "scope_snapshots",
    metadata,
    sa.Column("id", sa.String(64), primary_key=True),
    sa.Column("project_id", sa.Text, sa.ForeignKey("projects.id"), nullable=False),
    sa.Column("scope", JSONB, nullable=False),
    sa.UniqueConstraint("id", "project_id"),
    sa.CheckConstraint("id ~ '^[0-9a-f]{64}$'", name="scope_snapshot_digest"),
)

runs = sa.Table(
    "runs",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("project_id", sa.Text, sa.ForeignKey("projects.id"), nullable=False),
    sa.Column("scope_snapshot_id", sa.String(64), nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("profile", JSONB, nullable=False),
    sa.Column("profile_revision", sa.String(64), nullable=False),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    ),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("error_code", sa.Text),
    sa.ForeignKeyConstraint(
        ["scope_snapshot_id", "project_id"],
        ["scope_snapshots.id", "scope_snapshots.project_id"],
    ),
    sa.UniqueConstraint("id", "project_id"),
    sa.CheckConstraint("kind IN ('scan', 'import')", name="run_kind"),
    sa.CheckConstraint(
        "status IN ('running', 'succeeded', 'failed', 'interrupted')", name="run_status"
    ),
    sa.CheckConstraint(
        "(status = 'running') = (finished_at IS NULL)", name="run_finished"
    ),
    sa.CheckConstraint(
        "status NOT IN ('running', 'succeeded') OR error_code IS NULL", name="run_error"
    ),
    sa.CheckConstraint(
        "finished_at IS NULL OR finished_at >= created_at", name="run_time_order"
    ),
    sa.CheckConstraint("profile_revision ~ '^[0-9a-f]{64}$'", name="profile_digest"),
)

stages = sa.Table(
    "stages",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("run_id", UUID(as_uuid=True), nullable=False, unique=True),
    sa.Column("project_id", sa.Text, nullable=False),
    sa.Column("scanner", sa.Text, nullable=False),
    sa.Column(
        "input_context", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")
    ),
    sa.Column("reported_exit", sa.Text),
    sa.CheckConstraint(
        "reported_exit IS NULL OR reported_exit IN ('success', 'error')",
        name="stage_reported_exit",
    ),
    sa.Column("status", sa.Text, nullable=False),
    sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
    ),
    sa.Column("finished_at", sa.DateTime(timezone=True)),
    sa.Column("error_code", sa.Text),
    sa.ForeignKeyConstraint(["run_id", "project_id"], ["runs.id", "runs.project_id"]),
    sa.UniqueConstraint("id", "project_id"),
    sa.CheckConstraint(
        "status IN ('running', 'succeeded', 'failed', 'interrupted')",
        name="stage_status",
    ),
    sa.CheckConstraint(
        "(status = 'running') = (finished_at IS NULL)", name="stage_finished"
    ),
    sa.CheckConstraint(
        "status NOT IN ('running', 'succeeded') OR error_code IS NULL",
        name="stage_error",
    ),
    sa.CheckConstraint(
        "finished_at IS NULL OR finished_at >= created_at", name="stage_time_order"
    ),
)

entities = sa.Table(
    "entities",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("project_id", sa.Text, sa.ForeignKey("projects.id"), nullable=False),
    sa.Column("identity", sa.Text, nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("address", sa.Text, nullable=False),
    sa.Column("transport", sa.Text),
    sa.Column("port", sa.Integer),
    sa.UniqueConstraint("project_id", "identity"),
    sa.UniqueConstraint("id", "project_id"),
    sa.CheckConstraint("kind IN ('host', 'service', 'origin')", name="entity_kind"),
    sa.CheckConstraint(
        "(kind = 'service' AND transport IS NOT NULL AND transport IN ('tcp', 'udp', 'sctp') AND port IS NOT NULL AND port BETWEEN 1 AND 65535) OR (kind <> 'service' AND transport IS NULL AND port IS NULL)",
        name="entity_service",
    ),
)

artifacts = sa.Table(
    "artifacts",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column(
        "stage_id", UUID(as_uuid=True), sa.ForeignKey("stages.id"), nullable=False
    ),
    sa.Column("role", sa.Text, nullable=False),
    sa.Column("relative_path", sa.Text, nullable=False, unique=True),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("size_bytes", sa.BigInteger, nullable=False),
    sa.Column("health", sa.Text, nullable=False),
    sa.UniqueConstraint("stage_id", "role"),
    sa.UniqueConstraint("id", "stage_id"),
    sa.CheckConstraint("role IN ('stdout', 'stderr')", name="artifact_role"),
    sa.CheckConstraint(
        "relative_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(stdout[.](xml|jsonl)|stderr[.]txt)$'",
        name="artifact_path",
    ),
    sa.CheckConstraint(
        "(role = 'stdout' AND (relative_path LIKE '%/stdout.xml' OR relative_path LIKE '%/stdout.jsonl')) OR (role = 'stderr' AND relative_path LIKE '%/stderr.txt')",
        name="artifact_role_path",
    ),
    sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="artifact_digest"),
    sa.CheckConstraint("size_bytes BETWEEN 0 AND 8388608", name="artifact_size"),
    sa.CheckConstraint(
        "health IN ('ready', 'missing', 'corrupt')", name="artifact_health"
    ),
)


evidence = sa.Table(
    "evidence",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column(
        "stage_id", UUID(as_uuid=True), sa.ForeignKey("stages.id"), nullable=False
    ),
    sa.Column("artifact_id", UUID(as_uuid=True), nullable=False),
    sa.Column("metadata", JSONB, nullable=False),
    sa.Column("record_locator", sa.Text, nullable=False),
    sa.ForeignKeyConstraint(
        ["artifact_id", "stage_id"], ["artifacts.id", "artifacts.stage_id"]
    ),
    sa.UniqueConstraint("id", "stage_id"),
    sa.UniqueConstraint("stage_id", "artifact_id", "record_locator"),
)

observations = sa.Table(
    "observations",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("stage_id", UUID(as_uuid=True), nullable=False),
    sa.Column("project_id", sa.Text, sa.ForeignKey("projects.id"), nullable=False),
    sa.Column("entity_id", UUID(as_uuid=True), nullable=False),
    sa.Column("ordinal", sa.Integer, nullable=False),
    sa.Column("key", sa.Text, nullable=False),
    sa.Column("value", JSONB, nullable=False),
    sa.ForeignKeyConstraint(
        ["stage_id", "project_id"], ["stages.id", "stages.project_id"]
    ),
    sa.ForeignKeyConstraint(
        ["entity_id", "project_id"], ["entities.id", "entities.project_id"]
    ),
    sa.UniqueConstraint("stage_id", "ordinal"),
    sa.UniqueConstraint("id", "stage_id"),
    sa.CheckConstraint("ordinal >= 0", name="observation_ordinal"),
    sa.CheckConstraint(
        "jsonb_typeof(value) IN ('string', 'boolean', 'number')",
        name="observation_scalar",
    ),
)

observation_evidence = sa.Table(
    "observation_evidence",
    metadata,
    sa.Column("observation_id", UUID(as_uuid=True), primary_key=True),
    sa.Column("evidence_id", UUID(as_uuid=True), primary_key=True),
    sa.Column("stage_id", UUID(as_uuid=True), nullable=False),
    sa.ForeignKeyConstraint(
        ["observation_id", "stage_id"], ["observations.id", "observations.stage_id"]
    ),
    sa.ForeignKeyConstraint(
        ["evidence_id", "stage_id"], ["evidence.id", "evidence.stage_id"]
    ),
)


scanner_matches = sa.Table(
    "scanner_matches",
    metadata,
    sa.Column("id", UUID(as_uuid=True), primary_key=True),
    sa.Column("stage_id", UUID(as_uuid=True), nullable=False),
    sa.Column("ordinal", sa.Integer, nullable=False),
    sa.Column("evidence_id", UUID(as_uuid=True), nullable=False),
    sa.Column("metadata", JSONB, nullable=False),
    sa.ForeignKeyConstraint(
        ["evidence_id", "stage_id"], ["evidence.id", "evidence.stage_id"]
    ),
    sa.UniqueConstraint("stage_id", "ordinal"),
    sa.CheckConstraint("ordinal >= 0", name="match_ordinal"),
    sa.CheckConstraint(
        "metadata->>'assessment' IS NOT NULL AND metadata->>'assessment' = 'unvalidated'",
        name="match_assessment",
    ),
    sa.CheckConstraint(
        "metadata->>'scanner_severity' IS NOT NULL AND metadata->>'scanner_severity' IN ('info','low','medium','high','critical','unknown')",
        name="match_severity",
    ),
)
