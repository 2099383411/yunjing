import os
import json
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.orm import Session
from app.services.report_service import generate_report

from app.config import settings; DB_URL = settings.DATABASE_URL.replace("+asyncpg", "")
REPORT_DIR = "/app/data/reports"
os.makedirs(REPORT_DIR, exist_ok=True)

router = APIRouter()

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "html": "text/html",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


@router.get("/")
async def list_reports():
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        rows = db.execute(sa_text("""
            SELECT r.id, r.task_id, r.format, r.file_path, r.summary, r.created_at,
                   s.target, s.scan_type, s.status
            FROM reports r
            LEFT JOIN scan_tasks s ON r.task_id = s.id
            ORDER BY r.created_at DESC
            LIMIT 50
        """)).fetchall()
        reports = []
        for row in rows:
            d = dict(row._mapping)
            summary = d.get("summary")
            if isinstance(summary, str):
                try:
                    d["summary"] = json.loads(summary)
                except (json.JSONDecodeError, TypeError):
                    d["summary"] = {}
            d["exists"] = os.path.exists(d.get("file_path", "")) if d.get("file_path") else False
            reports.append(d)
    return {"reports": reports, "total": len(reports)}


@router.api_route("/generate/{task_id}", methods=["GET", "POST"])
async def create_report(task_id: str, format: str = Query("pdf", description="Report format: pdf, docx, html, xlsx")):
    """为指定任务生成多格式安全检测报告（支持 GET 和 POST）"""
    if format not in MEDIA_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'. Use: {', '.join(MEDIA_TYPES.keys())}")
    try:
        result = generate_report(task_id, fmt=format)
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        fp = result.get("file_path", "")
        if fp and os.path.exists(fp):
            media_type = MEDIA_TYPES.get(format, "application/octet-stream")
            filename = f"yunjing-report-{task_id[:8]}.{format}"
            return FileResponse(fp, media_type=media_type, filename=filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{report_id}")
async def delete_report(report_id: str):
    """删除报告（删除数据库记录和文件）"""
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        row = db.execute(sa_text("SELECT file_path FROM reports WHERE id=:id"), {"id": report_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        fp = row[0]
        # Delete file if exists
        if fp and os.path.exists(fp):
            os.remove(fp)
        # Delete DB record
        db.execute(sa_text("DELETE FROM reports WHERE id=:id"), {"id": report_id})
        db.commit()
    return {"ok": True, "message": "报告已删除"}


@router.get("/{report_id}")
async def get_report(report_id: str):
    """获取报告信息"""
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        row = db.execute(sa_text("SELECT * FROM reports WHERE id=:id"), {"id": report_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        d = dict(row._mapping)
        summary = d.get("summary")
        if isinstance(summary, str):
            try:
                d["summary"] = json.loads(summary)
            except (json.JSONDecodeError, TypeError):
                d["summary"] = {}
        d["exists"] = os.path.exists(d.get("file_path", "")) if d.get("file_path") else False
        return d


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    """下载报告文件（自动适配格式）"""
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        row = db.execute(sa_text("SELECT file_path, format FROM reports WHERE id=:id"), {"id": report_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        fp, fmt = row[0], row[1]
        if not fp or not os.path.exists(fp):
            raise HTTPException(status_code=404, detail="Report file not found")
        media_type = MEDIA_TYPES.get(fmt, "application/octet-stream")
        filename = f"yunjing-report-{report_id[:8]}.{fmt}"
        return FileResponse(fp, media_type=media_type, filename=filename)
