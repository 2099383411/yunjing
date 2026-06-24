"""推理过程捕获器 — 对话即证据链 的技术支撑

拦截 LLM 的每次决策 + 理由 → 格式化 → 写入 execution_steps 表
不是独立服务，是推理层与数据库之间的中间件"""
import uuid
import json
from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.execution_step import ExecutionStep


async def capture_reasoning(
    db: AsyncSession,
    task_id: str,
    turn_id: int,
    llm_decision: str,
    llm_reasoning: Optional[str] = None,
    llm_input_summary: Optional[str] = None,
    evidence_type: str = "推理",
    tool: Optional[str] = None,
    target: Optional[str] = None,
    payload: Optional[str] = None,
    result_summary: Optional[str] = None,
    confidence_before: Optional[float] = None,
    confidence_after: Optional[float] = None,
    linked_step_ids: Optional[list] = None,
    phase: Optional[str] = None,
    risk_level: str = "低",
    status: str = "planned",
    duration_ms: Optional[int] = None,
) -> str:
    """捕获并持久化一条推理/执行记录"""
    step_id = str(uuid.uuid4())
    step = ExecutionStep(
        id=step_id,
        task_id=task_id,
        turn_id=turn_id,
        llm_input_summary=llm_input_summary,
        llm_decision=llm_decision,
        llm_reasoning=llm_reasoning,
        evidence_type=evidence_type,
        tool=tool,
        target=target,
        payload=payload,
        result_summary=result_summary,
        confidence_before=confidence_before,
        confidence_after=confidence_after,
        linked_step_ids=linked_step_ids or [],
        phase=phase,
        risk_level=risk_level,
        status=status,
        duration_ms=duration_ms,
    )
    db.add(step)
    await db.commit()
    return step_id


async def get_reasoning_chain(
    db: AsyncSession,
    task_id: str,
    limit: int = 50,
) -> list[dict]:
    """获取任务的推理链（按轮次排序）"""
    from sqlalchemy import select
    result = await db.execute(
        select(ExecutionStep)
        .where(ExecutionStep.task_id == task_id)
        .order_by(ExecutionStep.turn_id.asc())
        .limit(limit)
    )
    return [
        {
            "id": s.id,
            "turn_id": s.turn_id,
            "llm_input_summary": s.llm_input_summary,
            "llm_decision": s.llm_decision,
            "llm_reasoning": s.llm_reasoning,
            "evidence_type": s.evidence_type,
            "tool": s.tool,
            "target": s.target,
            "result_summary": s.result_summary,
            "confidence_before": s.confidence_before,
            "confidence_after": s.confidence_after,
            "risk_level": s.risk_level,
            "status": s.status,
            "phase": s.phase,
            "duration_ms": s.duration_ms,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in result.scalars().all()
    ]


def format_llm_decision(
    turn_id: int,
    llm_decision: str,
    llm_reasoning: str,
    options: Optional[list[str]] = None,
    chosen_index: Optional[int] = None,
) -> dict:
    """格式化 LLM 决策为结构化日志"""
    entry = {
        "turn_id": turn_id,
        "decision": llm_decision,
        "reasoning": llm_reasoning,
        "options": options or [],
        "chosen_index": chosen_index,
        "timestamp": datetime.utcnow().isoformat(),
    }
    return entry


async def mark_step_complete(
    db: AsyncSession,
    step_id: str,
    status: str,
    result_summary: Optional[str] = None,
    duration_ms: Optional[int] = None,
    confidence_after: Optional[float] = None,
):
    """标记步骤完成并更新结果"""
    from sqlalchemy import update
    updates = {"status": status, "result_summary": result_summary}
    if duration_ms is not None:
        updates["duration_ms"] = duration_ms
    if confidence_after is not None:
        updates["confidence_after"] = confidence_after
    await db.execute(
        update(ExecutionStep).where(ExecutionStep.id == step_id).values(**updates)
    )
    await db.commit()
