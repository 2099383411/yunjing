"""LLM 提供商管理 API（多提供商 + 优先级）"""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.llm_provider import LLMProvider
from app.api.deps import require_admin
import httpx

router = APIRouter(dependencies=[Depends(require_admin)])


class CreateProviderReq(BaseModel):
    name: str
    provider_type: str = "deepseek"
    api_key: str = ""
    api_base: str = ""
    model: str = ""
    priority: int = 0
    is_default: bool = False


def mask_key(key: str) -> str:
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]


@router.get("/providers")
async def list_providers():
    async with AsyncSessionLocal() as sess:
        rows = (await sess.execute(select(LLMProvider).order_by(LLMProvider.priority.desc()))).scalars().all()
    return [{
        "id": p.id, "name": p.name, "provider_type": p.provider_type,
        "api_key": mask_key(p.api_key) if p.api_key else "",
        "api_base": p.api_base, "model": p.model,
        "priority": p.priority, "is_active": p.is_active, "is_default": p.is_default,
    } for p in rows]


@router.post("/providers")
async def create_provider(req: CreateProviderReq):
    async with AsyncSessionLocal() as sess:
        if req.is_default:
            existing = (await sess.execute(select(LLMProvider).where(LLMProvider.is_default == True))).scalars().all()
            for e in existing:
                e.is_default = False
        provider = LLMProvider(
            id=str(uuid.uuid4()), name=req.name, provider_type=req.provider_type,
            api_key=req.api_key, api_base=req.api_base, model=req.model,
            priority=req.priority, is_default=req.is_default,
        )
        sess.add(provider)
        await sess.commit()
    return {"id": provider.id, "name": provider.name}


@router.put("/providers/{provider_id}")
async def update_provider(provider_id: str, data: dict):
    async with AsyncSessionLocal() as sess:
        p = await sess.get(LLMProvider, provider_id)
        if not p:
            raise HTTPException(404, "提供商不存在")
        for field in ("name", "provider_type", "api_key", "api_base", "model", "priority", "is_active", "is_default"):
            if field in data:
                setattr(p, field, data[field])
        if data.get("is_default"):
            existing = (await sess.execute(select(LLMProvider).where(
                LLMProvider.is_default == True, LLMProvider.id != provider_id
            ))).scalars().all()
            for e in existing:
                e.is_default = False
        await sess.commit()
    return {"ok": True}


@router.delete("/providers/{provider_id}")
async def delete_provider(provider_id: str):
    async with AsyncSessionLocal() as sess:
        p = await sess.get(LLMProvider, provider_id)
        if not p:
            raise HTTPException(404, "提供商不存在")
        await sess.delete(p)
        await sess.commit()
    return {"ok": True}


@router.post("/providers/{provider_id}/test")
async def test_provider(provider_id: str):
    async with AsyncSessionLocal() as sess:
        p = await sess.get(LLMProvider, provider_id)
        if not p:
            raise HTTPException(404, "提供商不存在")
        if not p.api_key:
            raise HTTPException(400, "API Key 未配置")
        try:
            base = p.api_base or "https://api.deepseek.com/v1"
            async with httpx.AsyncClient(timeout=10) as cli:
                resp = await cli.get(f"{base}/models", headers={"Authorization": f"Bearer {p.api_key}"})
                if resp.status_code == 200:
                    return {"success": True, "message": "连接成功"}
                return {"success": False, "message": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as e:
            return {"success": False, "message": str(e)}


@router.put("/providers/default/{provider_id}")
async def set_default_provider(provider_id: str):
    async with AsyncSessionLocal() as sess:
        p = await sess.get(LLMProvider, provider_id)
        if not p:
            raise HTTPException(404, "提供商不存在")
        existing = (await sess.execute(select(LLMProvider).where(LLMProvider.is_default == True))).scalars().all()
        for e in existing:
            e.is_default = False
        p.is_default = True
        await sess.commit()
    return {"ok": True, "default": provider_id}


@router.put("/providers/priority")
async def batch_priority(data: dict):
    """批量设置优先级：{provider_id: priority, ...}"""
    async with AsyncSessionLocal() as sess:
        for pid, pri in data.items():
            p = await sess.get(LLMProvider, pid)
            if p:
                p.priority = int(pri)
        await sess.commit()
    return {"ok": True}
