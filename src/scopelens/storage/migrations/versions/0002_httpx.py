"""Store scanner input context and JSONL artifact references."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0002_httpx"
down_revision = "0001_scan_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "stages",
        sa.Column(
            "input_context",
            JSONB,
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.drop_constraint("artifact_path", "artifacts", type_="check")
    op.drop_constraint("artifact_role_path", "artifacts", type_="check")
    op.create_check_constraint(
        "artifact_path",
        "artifacts",
        "relative_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(stdout[.](xml|jsonl)|stderr[.]txt)$'",
    )
    op.create_check_constraint(
        "artifact_role_path",
        "artifacts",
        "(role = 'stdout' AND (relative_path LIKE '%/stdout.xml' OR relative_path LIKE '%/stdout.jsonl')) OR (role = 'stderr' AND relative_path LIKE '%/stderr.txt')",
    )


def downgrade() -> None:
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM stages WHERE scanner = 'httpx')")
    ):
        raise RuntimeError("cannot downgrade while httpx history exists")
    op.drop_constraint("artifact_path", "artifacts", type_="check")
    op.drop_constraint("artifact_role_path", "artifacts", type_="check")
    op.create_check_constraint(
        "artifact_path",
        "artifacts",
        "relative_path ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(stdout[.]xml|stderr[.]txt)$'",
    )
    op.create_check_constraint(
        "artifact_role_path",
        "artifacts",
        "(role = 'stdout' AND relative_path LIKE '%/stdout.xml') OR (role = 'stderr' AND relative_path LIKE '%/stderr.txt')",
    )
    op.drop_column("stages", "input_context")
