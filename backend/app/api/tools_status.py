"""扫描工具状态检测 — 通过 Celery 调用 worker 检测 Kali Sandbox 内工具"""
from fastapi import APIRouter, Depends
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter()

TOOLS = [
    {"name": "nmap",     "version_flag": "--version"},
    {"name": "nuclei",   "version_flag": "-version"},
    {"name": "gobuster", "version_flag": "--version"},
    {"name": "subfinder","version_flag": "-version"},
    {"name": "httpx",    "version_flag": "-version"},
    {"name": "naabu",    "version_flag": "-version"},
    {"name": "katana",   "version_flag": "-version"},
    {"name": "ffuf",     "version_flag": "-V"},
    {"name": "nikto",    "version_flag": "-Version"},
    {"name": "hydra",    "version_flag": "--version"},
    {"name": "sqlmap",   "version_flag": "--version"},
    {"name": "dirb",     "version_flag": ""},
    {"name": "wfuzz",    "version_flag": "--version"},
    {"name": "whatweb",  "version_flag": "--version"},
]

CHECK_TOOL_TASK = "tasks.scan_tasks.check_tool"


def check_via_celery(name: str, version_flag: str) -> dict:
    try:
        from celery import Celery
        celery_app = Celery("yunjing", broker="redis://redis:6379/1", backend="redis://redis:6379/2")
        task = celery_app.send_task(CHECK_TOOL_TASK, args=[name, version_flag], queue="scan")
        result = task.get(timeout=30)
        return result
    except Exception as e:
        return {"name": name, "installed": False, "version": None, "status": "error", "error": str(e)[:80]}


@router.get("/status", dependencies=[Depends(get_current_user)])
async def tools_status():
    results = [check_via_celery(t["name"], t["version_flag"]) for t in TOOLS]
    return {"tools": results}


@router.get("/status/public")
async def tools_status_public():
    results = [check_via_celery(t["name"], t["version_flag"]) for t in TOOLS]
    return {"tools": results}
