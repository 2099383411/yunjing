"""设置 API：LLM Key + 系统配置持久化"""
import os
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


@router.get("/llm-config")
async def get_llm_config():
    """读取系统 LLM 配置"""
    return {
        "provider": os.getenv("LLM_PROVIDER", settings.LLM_PROVIDER),
        "model": os.getenv("LLM_MODEL", settings.LLM_MODEL),
        "base_url": os.getenv("LLM_API_BASE", settings.LLM_API_BASE),
        "api_key": "••••••" + (os.getenv("LLM_API_KEY", "")[-4:] if len(os.getenv("LLM_API_KEY", "")) > 4 else ""),
    }


@router.put("/llm-config")
async def update_llm_config(data: dict):
    """更新 LLM 配置"""
    provider = data.get("provider", "deepseek")
    model = data.get("model", "deepseek-chat")
    base_url = data.get("base_url", "")
    api_key = data.get("api_key", "")

    # 更新环境变量（运行时生效）
    if provider:
        os.environ["LLM_PROVIDER"] = provider
    if model:
        os.environ["LLM_MODEL"] = model
    if base_url:
        os.environ["LLM_API_BASE"] = base_url
    if api_key and api_key != "••••••":
        os.environ["LLM_API_KEY"] = api_key

    # 写入 .env 文件（持久化，重启后生效）
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.exists(env_path):
        # 容器内路径
        env_path = "/app/.env"

    updates = {
        "LLM_PROVIDER": provider,
        "LLM_MODEL": model,
        "LLM_API_BASE": base_url,
    }
    if api_key and api_key != "••••••":
        updates["LLM_API_KEY"] = api_key

    try:
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()
        else:
            lines = []

        new_lines = []
        updated_keys = set()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            key = stripped.split("=")[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates.pop(key)}\n")
                updated_keys.add(key)
            else:
                new_lines.append(line)
        for k, v in updates.items():
            new_lines.append(f"{k}={v}\n")

        with open(env_path, "w") as f:
            f.writelines(new_lines)
    except Exception as e:
        return {"status": "error", "message": f"写入配置文件失败: {e}"}

    return {"status": "ok", "message": "LLM 配置已更新，重启后永久生效"}
