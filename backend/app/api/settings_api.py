"""设置 API：LLM Key + 系统配置持久化"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.models.user import User
from app.config import settings
from app.api.deps import get_current_user

router = APIRouter()

PUBLIC_KEYS = ["llm_provider", "llm_api_base", "llm_model", "llm_max_tokens", "llm_temperature", "max_concurrent_scans"]
SENSITIVE_KEYS = ["llm_api_key"]
ALL_KEYS = PUBLIC_KEYS + SENSITIVE_KEYS

@router.get("/")
async def get_settings():
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(SystemSetting).where(SystemSetting.key.in_(PUBLIC_KEYS)))
        rows = result.scalars().all()
    db = {r.key: r.value for r in rows}
    return {key: db.get(key, getattr(settings, key.upper(), "")) for key in PUBLIC_KEYS}

@router.get("/all")
async def get_all_settings(user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(SystemSetting))
        rows = result.scalars().all()
    db = {r.key: r.value for r in rows}
    return {key: db.get(key, getattr(settings, key.upper(), "")) for key in ALL_KEYS}

class SettingsUpdate(BaseModel):
    settings: dict[str, str]

@router.put("/")
async def update_settings(update: SettingsUpdate, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        for key, value in update.settings.items():
            stmt = select(SystemSetting).where(SystemSetting.key == key)
            result = await sess.execute(stmt)
            row = result.scalar_one_or_none()
            if row:
                row.value = str(value)
            else:
                sess.add(SystemSetting(key=key, value=str(value)))
        await sess.commit()
    return {"saved": list(update.settings.keys())}

@router.get("/llm-status")
async def llm_status():
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(SystemSetting).where(SystemSetting.key == "llm_api_key"))
        row = result.scalar_one_or_none()
    return {"configured": bool(row and row.value), "provider": settings.LLM_PROVIDER}
