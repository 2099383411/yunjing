"""扫描计划 / 定时扫描管理"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models.scan_schedule import ScanSchedule
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()

class ScheduleCreate(BaseModel):
    name: str
    target: str
    cron_expression: str = "0 2 * * *"
    profile: str = "quick"

class ScheduleUpdate(BaseModel):
    name: str | None = None
    target: str | None = None
    cron_expression: str | None = None
    profile: str | None = None
    enabled: bool | None = None

@router.get("/")
async def list_schedules(user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSchedule).order_by(ScanSchedule.created_at.desc()))
        schedules = result.scalars().all()
    return [{
        "id": s.id,
        "name": s.name,
        "target": s.target,
        "cron_expression": s.cron_expression,
        "profile": s.profile,
        "enabled": s.enabled,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else "",
    } for s in schedules]

@router.post("/")
async def create_schedule(data: ScheduleCreate, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        schedule = ScanSchedule(
            id=str(uuid.uuid4()),
            name=data.name,
            target=data.target,
            cron_expression=data.cron_expression,
            profile=data.profile,
            created_by=user.id,
        )
        sess.add(schedule)
        await sess.commit()
    return {"id": schedule.id, "name": schedule.name}

@router.put("/{schedule_id}")
async def update_schedule(schedule_id: str, data: ScheduleUpdate, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, "计划不存在")
        if data.name is not None: s.name = data.name
        if data.target is not None: s.target = data.target
        if data.cron_expression is not None: s.cron_expression = data.cron_expression
        if data.profile is not None: s.profile = data.profile
        if data.enabled is not None: s.enabled = data.enabled
        await sess.commit()
    return {"updated": schedule_id}

@router.delete("/{schedule_id}")
async def delete_schedule(schedule_id: str, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, "计划不存在")
        await sess.delete(s)
        await sess.commit()
    return {"deleted": schedule_id}

@router.post("/{schedule_id}/toggle")
async def toggle_schedule(schedule_id: str, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
        s = result.scalar_one_or_none()
        if not s:
            raise HTTPException(404, "计划不存在")
        s.enabled = not s.enabled
        await sess.commit()
    return {"id": schedule_id, "enabled": s.enabled}
