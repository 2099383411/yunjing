"""系统信息聚合 API"""
import os
import socket
import time
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from app.database import AsyncSessionLocal
from app.models.task import ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.llm_provider import LLMProvider
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()

SERVER_START_TIME = time.time()


def _get_loadavg() -> str:
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().strip().split()
            return parts[0]
    except Exception:
        return "-"


def _get_memory() -> dict:
    try:
        with open("/proc/meminfo") as f:
            data = {}
            for line in f:
                p = line.split(":")
                if len(p) == 2:
                    k = p[0].strip()
                    v = p[1].strip().replace(" kB", "")
                    try:
                        data[k] = int(v)
                    except ValueError:
                        data[k] = v
        total = data.get("MemTotal", 0)
        avail = data.get("MemAvailable", 0)
        used = total - avail if total and avail else 0
        if total:
            return {
                "total": round(total / 1024, 1),
                "used": round(used / 1024, 1),
                "percent": round(used / total * 100, 1),
            }
        return {}
    except Exception:
        return {}


def _get_disk() -> dict:
    try:
        s = os.statvfs("/")
        total = s.f_frsize * s.f_blocks
        free = s.f_frsize * s.f_bfree
        used = total - free
        pct = round(used / total * 100, 1) if total else 0
        return {
            "total": round(total / (1024 ** 3), 1),
            "used": round(used / (1024 ** 3), 1),
            "percent": pct,
        }
    except Exception:
        return {}


@router.get("/info")
async def system_info(user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        total_tasks = await sess.scalar(select(func.count(ScanTask.id)))
        completed_tasks = await sess.scalar(
            select(func.count(ScanTask.id)).where(ScanTask.status == TaskStatus.COMPLETED)
        )
        running_tasks = await sess.scalar(
            select(func.count(ScanTask.id)).where(ScanTask.status == TaskStatus.RUNNING)
        )
        failed_tasks = await sess.scalar(
            select(func.count(ScanTask.id)).where(ScanTask.status == TaskStatus.FAILED)
        )
        total_vulns = await sess.scalar(select(func.count(Vulnerability.id)))
        provider_count = await sess.scalar(select(func.count(LLMProvider.id)))
        severity_raw = await sess.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .group_by(Vulnerability.severity)
        )
        severity_counts = {row[0]: row[1] for row in severity_raw}

    uptime_seconds = int(time.time() - SERVER_START_TIME)
    days, rem = divmod(uptime_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    uptime_str = f"{days}天 {hours}小时 {minutes}分钟" if days > 0 else f"{hours}小时 {minutes}分钟"
    memory = _get_memory()
    disk = _get_disk()

    return {
        "version": "0.2.0",
        "hostname": socket.gethostname(),
        "platform": "Linux",
        "uptime": uptime_str,
        "cpu_count": os.cpu_count() or 0,
        "loadavg": _get_loadavg(),
        "memory": memory,
        "disk": disk,
        "tasks": {
            "total": total_tasks or 0,
            "completed": completed_tasks or 0,
            "running": running_tasks or 0,
            "failed": failed_tasks or 0,
        },
        "vulnerabilities": {
            "total": total_vulns or 0,
            "by_severity": severity_counts,
        },
        "llm_providers": provider_count or 0,
        "build_time": "2026-06-02",
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
