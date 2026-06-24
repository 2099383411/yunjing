"""执行步骤 + 推理日志 — 支撑对话即证据链"""
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Text
from app.models.task import Base


class ExecutionStep(Base):
    """执行步骤：记录每次 LLM 决策 + 工具执行 + 结果"""
    __tablename__ = "execution_steps"

    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)

    # 推理过程 (来自推理过程捕获器)
    turn_id = Column(Integer, nullable=False)                # 对话轮次
    llm_input_summary = Column(String(512), nullable=True)   # LLM 输入摘要
    llm_decision = Column(String(256), nullable=False)       # LLM 的决策内容
    llm_reasoning = Column(Text, nullable=True)              # LLM 的推理理由
    evidence_type = Column(String(32), default="推理")       # 推理/执行/异常

    # 执行细节
    tool = Column(String(50), nullable=True)                 # 调用工具
    target = Column(String(512), nullable=True)              # 目标
    payload = Column(Text, nullable=True)                    # Payload / 参数
    result_summary = Column(String(512), nullable=True)      # 结果摘要

    # 置信度变化
    confidence_before = Column(Float, nullable=True)         # 执行前置信度
    confidence_after = Column(Float, nullable=True)          # 执行后置信度

    # 关联
    linked_step_ids = Column(JSON, default=list)             # 关联的步骤 ID 列表
    phase = Column(String(32), nullable=True)                # 所属阶段

    risk_level = Column(String(10), default="低")
    status = Column(String(20), default="planned")          # planned/running/success/failed/skipped
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
