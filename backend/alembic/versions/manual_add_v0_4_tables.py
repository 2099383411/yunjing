"""v0.4 手动迁移：新增接地层 + 推理捕获 + 信任关系 + 负向验证 + 痕迹审计表

创建步骤:
    1. 备份数据库
    2. alembic upgrade head
    3. 导入 CVE 数据: python -m app.grounding.import_nvd /path/to/nvd_data/
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "manual_add_v0_4_tables"
down_revision = "0a2d4f099b02"
branch_labels = None
depends_on = None


def upgrade():
    # ── CVE 数据库 ─────────────────────────────────────────────────────
    op.create_table(
        "cve_database",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cve_id", sa.String(20), unique=True, nullable=False, index=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("affected_versions", JSONB, default=list),
        sa.Column("fixed_in_versions", JSONB, default=list),
        sa.Column("vuln_type", sa.String(50), nullable=True),
        sa.Column("poc_available", sa.Boolean, default=False),
        sa.Column("poc_path", sa.String(512), nullable=True),
        sa.Column("poc_command", sa.String(1024), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("references", JSONB, default=list),
        sa.Column("source", sa.String(20), default="NVD"),
        sa.Column("coverage_note", sa.String(256), nullable=True),
        sa.Column("last_updated", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )

    # ── CVE 校验缓存 ──────────────────────────────────────────────────
    op.create_table(
        "cve_verification_cache",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("cve_id", sa.String(20), nullable=False, index=True),
        sa.Column("product", sa.String(100), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("is_affected", sa.Boolean, nullable=False),
        sa.Column("confidence", sa.Float, default=0.0),
        sa.Column("notes", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_cve_verify_lookup", "cve_verification_cache",
                    ["cve_id", "product", "version"], unique=True)

    # ── 执行步骤 + 推理日志 ──────────────────────────────────────────
    op.create_table(
        "execution_steps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), nullable=False, index=True),
        sa.Column("turn_id", sa.Integer, nullable=False),
        sa.Column("llm_input_summary", sa.String(512), nullable=True),
        sa.Column("llm_decision", sa.String(256), nullable=False),
        sa.Column("llm_reasoning", sa.Text, nullable=True),
        sa.Column("evidence_type", sa.String(32), default="推理"),
        sa.Column("tool", sa.String(50), nullable=True),
        sa.Column("target", sa.String(512), nullable=True),
        sa.Column("payload", sa.Text, nullable=True),
        sa.Column("result_summary", sa.String(512), nullable=True),
        sa.Column("confidence_before", sa.Float, nullable=True),
        sa.Column("confidence_after", sa.Float, nullable=True),
        sa.Column("linked_step_ids", JSONB, default=list),
        sa.Column("phase", sa.String(32), nullable=True),
        sa.Column("risk_level", sa.String(10), default="低"),
        sa.Column("status", sa.String(20), default="planned"),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )
    op.create_index("ix_execution_steps_task_turn", "execution_steps",
                    ["task_id", "turn_id"], unique=True)

    # ── 信任关系 ─────────────────────────────────────────────────────
    op.create_table(
        "trust_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), nullable=False, index=True),
        sa.Column("from_host", sa.String(256), nullable=False),
        sa.Column("to_host", sa.String(256), nullable=False),
        sa.Column("edge_type", sa.String(32), nullable=False),
        sa.Column("credential", JSONB, nullable=True),
        sa.Column("route", sa.String(128), nullable=True),
        sa.Column("status", sa.String(20), default="available"),
        sa.Column("discovered_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
    )

    # ── 负向验证记录 ────────────────────────────────────────────────
    op.create_table(
        "negative_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), nullable=False, index=True),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("vuln_id", sa.String(50), nullable=True),
        sa.Column("vuln_name", sa.String(256), nullable=False),
        sa.Column("verification_method", sa.String(128), nullable=False),
        sa.Column("verification_detail", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), default="confirmed_safe"),
        sa.Column("reason", sa.String(256), nullable=True),
        sa.Column("suggestion", sa.Text, nullable=True),
        sa.Column("verified_at", sa.DateTime, nullable=True),
    )

    # ── 痕迹审计 ─────────────────────────────────────────────────────
    op.create_table(
        "trace_audits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), nullable=False, index=True),
        sa.Column("operation_type", sa.String(20), nullable=False),
        sa.Column("operation_detail", sa.Text, nullable=True),
        sa.Column("before_state", sa.Text, nullable=True),
        sa.Column("after_state", sa.Text, nullable=True),
        sa.Column("cleaned", sa.Boolean, default=False),
        sa.Column("clean_method", sa.String(128), nullable=True),
        sa.Column("clean_confirmed", sa.Boolean, default=False),
        sa.Column("residual_risk", sa.String(20), default="低"),
        sa.Column("risk_detail", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("cleaned_at", sa.DateTime, nullable=True),
    )

    # ── 审计摘要 ─────────────────────────────────────────────────────
    op.create_table(
        "audit_summaries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("task_id", sa.String(36), nullable=False, index=True),
        sa.Column("total_ops", JSONB, default=dict),
        sa.Column("cleaned_ops", JSONB, default=dict),
        sa.Column("residual_ops", JSONB, default=dict),
        sa.Column("overall_risk", sa.String(10), default="低"),
        sa.Column("summary_text", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
    )


def downgrade():
    op.drop_table("audit_summaries")
    op.drop_table("trace_audits")
    op.drop_table("negative_results")
    op.drop_table("trust_edges")
    op.drop_table("execution_steps")
    op.drop_index("ix_cve_verify_lookup", "cve_verification_cache")
    op.drop_table("cve_verification_cache")
    op.drop_table("cve_database")
