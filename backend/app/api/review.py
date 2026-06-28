"""复盘系统 API — 渗透完成后的经验沉淀"""
import json, logging
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.user import User
from app.api.deps import optional_user

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/review/generate")
async def generate_review(data: dict, user: User = Depends(optional_user)):
    """生成复盘草稿"""
    task_id = data.get("task_id", "")
    async with AsyncSessionLocal() as sess:
        from app.models.task import ScanTask
        task = await sess.get(ScanTask, task_id)
        if not task:
            return {"status": "error", "message": "任务不存在"}

        result = task.result or {}
        findings = result.get("findings", []) if isinstance(result, dict) else []
        error = task.error

        draft = {
            "task_id": task_id,
            "target": task.target,
            "scan_type": task.scan_type,
            "status": task.status,
            "successes": [],
            "failures": [],
            "process_notes": "",
        }

        for f_item in findings:
            if isinstance(f_item, dict):
                sev = f_item.get("severity", "unknown")
                if sev in ("critical", "high"):
                    draft["successes"].append({
                        "vuln": f_item.get("name", f_item.get("title", "?")),
                        "detail": f_item.get("description", "")[:200],
                        "severity": sev,
                    })

        if error:
            draft["failures"].append({"reason": str(error)[:200]})

        return {"status": "ok", "draft": draft}


@router.post("/review/confirm")
async def confirm_review(data: dict, user: User = Depends(optional_user)):
    """确认复盘，回流到经验库"""
    task_id = data.get("task_id", "")
    notes = data.get("notes", "")
    successes = data.get("successes", [])
    failures = data.get("failures", [])

    try:
        from app.engine.learning import LearningEngine
        le = LearningEngine()
        for s_item in successes:
            exp = {
                "type": "review_success",
                "task_id": task_id,
                "vuln": s_item.get("vuln", "?"),
                "detail": s_item.get("detail", ""),
                "notes": notes,
                "created_at": datetime.utcnow().timestamp(),
            }
            le._data.setdefault("experiences", []).append(exp)
        for f_item in failures:
            exp = {
                "type": "review_failure",
                "task_id": task_id,
                "reason": f_item.get("reason", ""),
                "notes": notes,
                "created_at": datetime.utcnow().timestamp(),
            }
            le._data.setdefault("experiences", []).append(exp)
        le._save()
        total = len(successes) + len(failures)
        msg = f"已记录{total}条经验（{len(successes)}成功+{len(failures)}失败）"
        logger.info(f"[复盘] 任务%s: %s", task_id, msg)
        return {"status": "ok", "message": msg}
    except Exception as e:
        logger.error("[复盘] 保存失败: %s", e, exc_info=True)
        return {"status": "error", "message": str(e)}
