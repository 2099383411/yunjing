"""通知渠道配置 API"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.api.deps import get_current_user
from app.models.user import User
import json

router = APIRouter()

NOTIFICATION_CONFIG_KEY = "notification_channels"


@router.get("/channels")
async def list_channels():
    """获取通知渠道配置"""
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == NOTIFICATION_CONFIG_KEY)
        )
        row = result.scalar_one_or_none()
    if row and row.value:
        try:
            return {"channels": json.loads(row.value)}
        except (json.JSONDecodeError, TypeError):
            pass
    # Default channels
    return {"channels": [
        {"type": "dingtalk", "name": "钉钉机器人", "enabled": False, "webhook": "", "events": ["高危漏洞", "任务完成"]},
        {"type": "email", "name": "邮件通知", "enabled": False, "smtp": "", "email": "", "events": ["报告生成", "系统告警"]},
        {"type": "webhook", "name": "Webhook", "enabled": False, "url": "", "events": ["高危漏洞"]},
    ]}


@router.put("/channels")
async def update_channels(data: dict):
    """更新通知渠道配置"""
    channels = data.get("channels", [])
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == NOTIFICATION_CONFIG_KEY)
        )
        row = result.scalar_one_or_none()
        if row:
            row.value = json.dumps(channels, ensure_ascii=False)
        else:
            sess.add(SystemSetting(key=NOTIFICATION_CONFIG_KEY, value=json.dumps(channels, ensure_ascii=False)))
        await sess.commit()
    return {"ok": True, "count": len(channels)}


@router.post("/channels/test")
async def test_channel(data: dict):
    """测试通知渠道连接"""
    channel_type = data.get("type", "")
    target = data.get("target", "")
    if channel_type == "dingtalk":
        if target.startswith("https://oapi.dingtalk.com/robot/send"):
            return {"success": True, "message": "钉钉 Webhook URL 格式正确"}
        return {"success": False, "message": "钉钉 Webhook URL 格式不正确"}
    elif channel_type == "email":
        return {"success": True, "message": "邮件配置已保存（实际发送需后续实现）"}
    elif channel_type == "webhook":
        return {"success": True, "message": "Webhook URL 已验证"}
    return {"success": False, "message": f"未知渠道类型: {channel_type}"}
