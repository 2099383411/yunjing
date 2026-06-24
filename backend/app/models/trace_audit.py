"""痕迹审计模型 — 执行痕迹管理与干净退场证明"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Text, Boolean
from app.models.task import Base


class TraceAudit(Base):
    """痕迹审计：每轮执行结束时的痕迹清单"""
    __tablename__ = "trace_audits"

    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)

    operation_type = Column(String(20), nullable=False)       # file_ops / network_ops / db_ops
    operation_detail = Column(Text, nullable=True)            # 操作描述
    before_state = Column(Text, nullable=True)                # 执行前快照 (文件hash, 配置备份)
    after_state = Column(Text, nullable=True)                 # 执行后状态
    cleaned = Column(Boolean, default=False)                  # 是否已清理
    clean_method = Column(String(128), nullable=True)         # 清理方式 (删除/回滚/还原)
    clean_confirmed = Column(Boolean, default=False)          # 清理是否确认成功
    residual_risk = Column(String(20), default="低")         # 残留风险: 低/中/高
    risk_detail = Column(Text, nullable=True)                 # 残留风险说明
    created_at = Column(DateTime, default=datetime.utcnow)
    cleaned_at = Column(DateTime, nullable=True)


class AuditSummary(Base):
    """审计摘要：每轮执行的总览"""
    __tablename__ = "audit_summaries"

    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)

    total_ops = Column(JSON, default=dict)                    # {file: 3, network: 5, db: 1}
    cleaned_ops = Column(JSON, default=dict)                  # {file: 3, network: 3, db: 1}
    residual_ops = Column(JSON, default=dict)                 # {network: 2} — web日志无法清理
    overall_risk = Column(String(10), default="低")
    summary_text = Column(Text, nullable=True)                # 可读摘要
    created_at = Column(DateTime, default=datetime.utcnow)
