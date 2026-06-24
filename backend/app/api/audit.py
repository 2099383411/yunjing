"""审计日志 API + 中间件"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.orm import Session

from app.config import settings; DB_URL = settings.DATABASE_URL.replace("+asyncpg", "")
router = APIRouter()


def log_audit(target: str, ip_address: str = "", confirmed: bool = False, confirmed_by: str = ""):
    """写入审计日志"""
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        db.execute(sa_text("""
            INSERT INTO authorization_logs (id, target, confirmed, ip_address, confirmed_by, created_at)
            VALUES (:id, :target, :confirmed, :ip, :by, :now)
        """), {
            "id": str(uuid.uuid4()),
            "target": target,
            "confirmed": confirmed,
            "ip": ip_address or "",
            "by": confirmed_by or "",
            "now": datetime.utcnow(),
        })
        db.commit()


@router.get("/logs")
async def list_audit_logs(limit: int = 50):
    """查询审计日志"""
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        rows = db.execute(sa_text(
            "SELECT * FROM authorization_logs ORDER BY created_at DESC LIMIT :limit"
        ), {"limit": limit}).fetchall()
        logs = [dict(r._mapping) for r in rows]
    return {"logs": logs, "total": len(logs)}


@router.post("/log")
async def create_audit_log(target: str, confirmed: bool = False, ip_address: str = ""):
    """手动写入审计日志"""
    log_audit(target, ip_address, confirmed)
    return {"status": "logged"}
