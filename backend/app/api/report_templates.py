"""报告模板配置 API"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.setting import SystemSetting
from app.api.deps import get_current_user
from app.models.user import User
import json

router = APIRouter()

REPORT_TEMPLATE_KEY = "report_template_config"


@router.get("/templates")
async def get_report_templates():
    """获取报告模板配置"""
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == REPORT_TEMPLATE_KEY)
        )
        row = result.scalar_one_or_none()
    if row and row.value:
        try:
            return {"templates": json.loads(row.value)}
        except (json.JSONDecodeError, TypeError):
            pass
    return {"templates": [
        {
            "name": "标准渗透测试报告",
            "format": "pdf",
            "sections": ["漏洞列表", "漏洞详情", "修复建议", "攻击链"],
            "language": "zh-CN",
            "is_default": True,
        },
        {
            "name": "合规差距分析报告",
            "format": "word",
            "sections": ["合规要求", "差距分析", "整改建议"],
            "language": "zh-CN",
            "is_default": False,
        },
    ]}


@router.put("/templates")
async def update_report_templates(data: dict):
    """更新报告模板配置"""
    templates = data.get("templates", [])
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == REPORT_TEMPLATE_KEY)
        )
        row = result.scalar_one_or_none()
        if row:
            row.value = json.dumps(templates, ensure_ascii=False)
        else:
            sess.add(SystemSetting(key=REPORT_TEMPLATE_KEY, value=json.dumps(templates, ensure_ascii=False)))
        await sess.commit()
    return {"ok": True, "count": len(templates)}
