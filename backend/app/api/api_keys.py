"""API Key 管理"""
import uuid
import hashlib
import secrets
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models.api_key import ApiKey
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()

class ApiKeyCreate(BaseModel):
    name: str

class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    created_at: str
    last_used_at: str | None
    is_active: bool

@router.get("/")
async def list_api_keys(user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
        keys = result.scalars().all()
    return [{
        "id": k.id,
        "name": k.name,
        "key_prefix": k.key_prefix + "...",
        "created_at": k.created_at.isoformat() if k.created_at else "",
        "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        "is_active": k.is_active,
    } for k in keys]

@router.post("/")
async def create_api_key(data: ApiKeyCreate, user: User = Depends(get_current_user)):
    key_id = str(uuid.uuid4())
    raw_key = "yj_" + secrets.token_hex(20)  # 40 chars
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]

    async with AsyncSessionLocal() as sess:
        sess.add(ApiKey(
            id=key_id, name=data.name,
            key_hash=key_hash, key_prefix=key_prefix,
            created_by=user.id,
        ))
        await sess.commit()

    return {"id": key_id, "name": data.name, "api_key": raw_key, "message": "请立即复制保存，此 Key 不会再显示"}


@router.delete("/{key_id}")
async def delete_api_key(key_id: str, user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ApiKey).where(ApiKey.id == key_id))
        key = result.scalar_one_or_none()
        if not key:
            raise HTTPException(404, "Key 不存在")
        await sess.delete(key)
        await sess.commit()
    return {"deleted": key_id}
