"""并发控制 — 限制同时运行的扫描任务数"""
from app.database import AsyncSessionLocal
from sqlalchemy import text

MAX_CONCURRENT_SCANS = 6


async def check_concurrent_scans() -> tuple[bool, int]:
    """检查当前正在运行的扫描数是否超过限制"""
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text(
            "SELECT COUNT(*) FROM scan_tasks WHERE status='RUNNING'"
        ))).fetchone()
        running = row[0] if row else 0
    return running < MAX_CONCURRENT_SCANS, running
