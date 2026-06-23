"""Webhook 通知渠道管理"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models.webhook import Webhook
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()

class WebhookCreate(BaseModel):
    name: str
    url: str
    events: list[str] = ["scan_complete"]

class WebhookUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    events: list[str] | None = None
    enabled: bool | None = None

@router.get("/")
async def list_webhooks(user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(Webhook).order_by(Webhook.created_at.desc()))
        hooks = result.scalars().all()
    return [{
        "id": h.id,
        "name": h.name,
        "url": h.url,
        "events": h.events,
        "enabled": h.enabled,
        "created_at": h.created_at.isoformat() if h.created_at else "",
    } for h in hooks]

@router.post("/")
async def create_webhook(data: WebhookCreate, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        hook = Webhook(
            id=str(uuid.uuid4()),
            name=data.name,
            url=data.url,
            events=data.events,
            created_by=user.id,
        )
        sess.add(hook)
        await sess.commit()
    return {"id": hook.id, "name": hook.name}

@router.put("/{webhook_id}")
async def update_webhook(webhook_id: str, data: WebhookUpdate, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(Webhook).where(Webhook.id == webhook_id))
        h = result.scalar_one_or_none()
        if not h:
            raise HTTPException(404, "Webhook 不存在")
        if data.name is not None: h.name = data.name
        if data.url is not None: h.url = data.url
        if data.events is not None: h.events = data.events
        if data.enabled is not None: h.enabled = data.enabled
        await sess.commit()
    return {"updated": webhook_id}

@router.delete("/{webhook_id}")
async def delete_webhook(webhook_id: str, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(Webhook).where(Webhook.id == webhook_id))
        h = result.scalar_one_or_none()
        if not h:
            raise HTTPException(404, "Webhook 不存在")
        await sess.delete(h)
        await sess.commit()
    return {"deleted": webhook_id}
