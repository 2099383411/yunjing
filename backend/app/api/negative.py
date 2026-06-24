"""负向结果 API — 记录已验证不存在的漏洞和攻击面"""
from fastapi import APIRouter, Query, HTTPException
from sqlalchemy import select, text
from datetime import datetime
import uuid
from app.database import AsyncSessionLocal
from app.models.negative_result import NegativeResult

router = APIRouter()

@router.post("/record")
async def record_negative_result(
    task_id: str, target: str, vuln_name: str,
    vuln_id: str = "", verification_method: str = "auto_perception",
    verification_detail: str = "", status: str = "confirmed_safe",
    reason: str = "", suggestion: str = "",
):
    """记录一条负向验证结果"""
    async with AsyncSessionLocal() as sess:
        nr = NegativeResult(
            id=str(uuid.uuid4()),
            task_id=task_id,
            target=target,
            vuln_id=vuln_id,
            vuln_name=vuln_name,
            verification_method=verification_method,
            verification_detail=verification_detail,
            status=status,
            reason=reason,
            suggestion=suggestion,
        )
        sess.add(nr)
        await sess.commit()
        return {"id": nr.id, "status": "recorded"}


@router.get("/list")
async def list_negative_results(
    task_id: str = Query("", description="按任务筛选"),
    target: str = Query("", description="按目标筛选"),
    limit: int = Query(50, le=200),
):
    """查询负向验证记录"""
    async with AsyncSessionLocal() as sess:
        conditions = []
        params = {}
        if task_id:
            conditions.append("task_id = :task_id")
            params["task_id"] = task_id
        if target:
            conditions.append("target LIKE :target")
            params["target"] = f"%{target}%"
        
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        rows = await sess.execute(
            text(f"SELECT id, task_id, target, vuln_id, vuln_name, verification_method, status, verified_at FROM negative_results{where} ORDER BY verified_at DESC LIMIT :limit"),
            {**params, "limit": limit},
        )
        return [{
            "id": r[0], "task_id": r[1], "target": r[2],
            "vuln_id": r[3], "vuln_name": r[4],
            "verification_method": r[5], "status": r[6],
            "verified_at": str(r[7]) if r[7] else "",
        } for r in rows]


@router.get("/stats")
async def get_negative_stats():
    """负向结果统计"""
    async with AsyncSessionLocal() as sess:
        rows = await sess.execute(text("""
            SELECT status, COUNT(*) as cnt FROM negative_results GROUP BY status
        """))
        stats = {r[0]: r[1] for r in rows}
        
        total = await sess.execute(text("SELECT COUNT(*) FROM negative_results"))
        return {
            "total": total.scalar(),
            "by_status": stats,
        }
