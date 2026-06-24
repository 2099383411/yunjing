"""扫描任务 API - 真实数据库查询"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select, desc, delete as sa_delete, or_
from app.database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.task import ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
import uuid
from pydantic import BaseModel
from app.api.deps import get_current_user
from app.models.user import User
from app.services.scan_tools import create_and_start_scan
import os, json, asyncio

router = APIRouter()


class CreateTaskRequest(BaseModel):
    targets: list[str]
    scan_type: str = "full"
    tools: list[str] | None = None
    port_range: str | None = None
    rate_limit: int | None = None
    timeout: int | None = None
    verify: bool | None = None
    threads: int | None = None


@router.get("/")
async def list_tasks(
    user: User = Depends(get_current_user),
    limit: int = Query(20, le=100),
    offset: int = Query(0, ge=0),
    status: str | None = None,
    search: str | None = None,
):
    async with AsyncSessionLocal() as sess:
        query = select(ScanTask).order_by(desc(ScanTask.created_at)).offset(offset).limit(limit)
        if status:
            query = query.where(ScanTask.status == status.upper())
        if search:
            query = query.where(
                or_(
                    ScanTask.target.ilike(f"%{search}%"),
                    ScanTask.id.ilike(f"%{search}%"),
                    ScanTask.scan_type.ilike(f"%{search}%"),
                )
            )
        result = await sess.execute(query)
        tasks = result.scalars().all()
    return [{
        "id": t.id, "target": t.target, "scan_type": t.scan_type,
        "status": t.status.value if hasattr(t.status, "value") else t.status,
        "progress": t.progress, "result": t.result,
        "created_at": t.created_at.isoformat() if t.created_at else "",
        "completed_at": t.completed_at.isoformat() if t.completed_at else "",
        "duration": (t.completed_at - t.created_at).total_seconds() if t.completed_at and t.created_at else None,
    } for t in tasks]


@router.post("/")
async def create_task(data: CreateTaskRequest, user: User = Depends(get_current_user)):
    """手动配置页创建扫描任务"""
    tasks_created = []
    for target in data.targets:
        kwargs = {"target": target, "scan_type": data.scan_type}
        if data.tools:
            kwargs["skills"] = data.tools
        task_id = await create_and_start_scan(**kwargs)
        tasks_created.append(task_id)
    return {"task_ids": tasks_created, "count": len(tasks_created)}


@router.get("/{task_id}")
async def get_task(task_id: str, user: User = Depends(get_current_user)):
    """获取任务详情（含结果）"""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "Task not found")
    return {
        "id": task.id, "target": task.target, "scan_type": task.scan_type,
        "status": task.status.value if hasattr(task.status, "value") else task.status,
        "progress": task.progress, "result": task.result, "error": task.error,
        "created_at": task.created_at.isoformat() if task.created_at else "",
        "completed_at": task.completed_at.isoformat() if task.completed_at else "",
        "duration": (task.completed_at - task.created_at).total_seconds() if task.completed_at and task.created_at else None,
    }


@router.delete("/{task_id}")
async def delete_task(task_id: str, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        await sess.execute(sa_delete(ScanTask).where(ScanTask.id == task_id))
        await sess.commit()
    return {"deleted": task_id}


@router.get("/{task_id}/vulnerabilities")
async def get_task_vulnerabilities(task_id: str, user: User = Depends(get_current_user)):
    """获取任务的漏洞列表"""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.task_id == task_id)
        )
        vulns = result.scalars().all()
    return [{
        "id": v.id,
        "title": v.title,
        "severity": v.severity,
        "target": v.target,
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "description": v.description,
        "evidence": v.evidence,
        "remediation": v.remediation,
        "tool_source": v.tool_source,
        "confidence": v.confidence,
        "discovered_at": v.discovered_at.isoformat() if v.discovered_at else None,
        "references": v.references if v.references else [],
    } for v in vulns]


@router.post("/{task_id}/cancel")
async def cancel_task(task_id: str, user: User = Depends(get_current_user)):
    """取消一个正在运行的任务"""
    async with AsyncSessionLocal() as sess:
        task = await sess.get(ScanTask, task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        if task.status in (TaskStatus.CANCELLED, TaskStatus.COMPLETED, TaskStatus.FAILED):
            raise HTTPException(status_code=400, detail="Task cannot be cancelled in its current state")
        from sqlalchemy import update
        await sess.execute(
            update(ScanTask).where(ScanTask.id == task_id).values(status=TaskStatus.CANCELLED)
        )
        await sess.commit()
    return {"status": "cancelled", "task_id": task_id}


@router.get("/{task_id}/report")
async def get_round_report(task_id: str, user: User = Depends(get_current_user)):
    """获取当前任务的轮次报告"""
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ScanTask).where(ScanTask.id == task_id))
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(404, "Task not found")
    return {
        "task_id": task.id,
        "target": task.target,
        "status": task.status.value if hasattr(task.status, "value") else task.status,
        "result": task.result,
    }
