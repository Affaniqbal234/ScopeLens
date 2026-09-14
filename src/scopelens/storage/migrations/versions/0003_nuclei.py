"""Store per-run scanner matches separately from validated findings."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0003_nuclei"
down_revision = "0002_httpx"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scanner_matches",
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


def downgrade() -> None:
    if op.get_bind().scalar(
        sa.text("SELECT EXISTS (SELECT 1 FROM stages WHERE scanner = 'nuclei')")
    ):
        raise RuntimeError("cannot downgrade while Nuclei history exists")
    op.drop_table("scanner_matches")
