import asyncio
"""扫描工具服务 — 工具定义 + Celery 任务调度"""
import uuid, json
from datetime import datetime
from sqlalchemy import text
from app.database import AsyncSessionLocal
from app.services.concurrency import check_concurrent_scans, MAX_CONCURRENT_SCANS
from celery import Celery
from app.config import settings

celery_app = Celery("yunjing", broker=settings.REDIS_URL or "redis://redis:6379/1")
EXECUTE_SCAN_TASK = "tasks.scan_tasks.execute_scan"

# ═══════════════════════════════════════════════════════════
#  LLM Function Calling 工具定义
# ═══════════════════════════════════════════════════════════

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "start_scan",
            "description": "对目标 IP、域名或 URL 执行安全扫描",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "扫描目标（IP、域名或URL）"},
                    "scan_type": {
                        "type": "string",
                        "enum": ["round", "full", "quick", "web"],
                        "description": "渗透测试模式（LLM自动选择）：round=轮次制深度渗透（推荐，端口全覆盖+漏洞利用+后渗透）, full=全链路PTES渗透测试, quick=快速侦察+漏洞验证, web=Web安全专项",
                    },
                    "skills": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "指定要使用的技能ID列表（可选，不指定则使用全部已启用技能）",
                    },
                },
                "required": ["target"],
            },
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_task_status",
            "description": "查询扫描任务的当前状态和进度",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "任务ID"},
                },
                "required": ["task_id"],
            },
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_task_vulnerabilities",
            "description": "获取扫描任务的漏洞详情列表",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "任务ID"},
                },
                "required": ["task_id"],
            },
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_scan_phase",
            "description": "执行单个渗透测试阶段，LLM逐阶段驱动。每次只跑一个阶段，返回结果后LLM分析并决策下一阶段",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标IP/域名/URL"},
                    "phase": {
                        "type": "string",
                        "enum": ["asset_discovery", "port_scan", "service_detect", "vuln_scan", "web_scan", "web_fingerprint", "dir_scan", "osint_gather", "exploitation", "post_exploit", "threat_model"],
                        "description": "渗透测试阶段: asset_discovery=资产发现/存活探测, port_scan=端口扫描, service_detect=服务版本识别, vuln_scan=漏洞扫描(Nuclei+弱口令+SSL), web_scan=Web漏洞扫描(Nikto), web_fingerprint=Web指纹识别(WhatWeb), dir_scan=目录扫描, osint_gather=OSINT情报收集(子域名/DNS记录), exploitation=漏洞利用(searchsploit+msf), post_exploit=后渗透(横向移动/凭证扫描/提权), threat_model=威胁建模(自动分析资产画像和攻击路径)",
                    },
                    "context": {
                        "type": "object",
                        "description": "前序阶段的上下文，传入之前阶段发现的结果供当前阶段使用",
                        "properties": {
                            "ports": {"type": "array", "items": {"type": "integer"}, "description": "已知开放端口列表"},
                            "findings": {"type": "array", "items": {"type": "object"}, "description": "已知漏洞发现列表"},
                        }
                    },
                },
                "required": ["target", "phase"],
            },
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_tools_status",
            "description": "查询所有扫描工具的安装状态",
            "parameters": {"type": "object", "properties": {}},
        }
    },
]

TOOL_NAMES = {t["function"]["name"]: t for t in TOOLS}


async def execute_tool_call(tool_call: dict) -> str:
    """执行 LLM Function Calling 的工具调用
    
    tool_call format:
    {
        "id": "call_xxx",
        "type": "function",
        "function": {"name": "start_scan", "arguments": '{"target":"..."}'}
    }
    """
    try:
        name = tool_call["function"]["name"]
        raw_args = tool_call["function"]["arguments"]
        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
    except (KeyError, json.JSONDecodeError) as e:
        return json.dumps({"error": f"Invalid tool call: {e}"})

    if name == "start_scan":
        target = args.get("target")
        scan_type = args.get("scan_type", "full")
        # Call Agent V2 for skill enrichment
        enriched_skills = None
        try:
            import httpx
            user_message = f"帮我扫一下{target}"
            agent_resp = httpx.post(
                "http://agent:8001/chat",
                json={"session_id": f"scan-{target}", "message": user_message},
                timeout=10
            )
            if agent_resp.status_code == 200:
                agent_data = agent_resp.json()
                plan = agent_data.get("plan")
                if plan and plan.get("selected_skills"):
                    enriched_skills = plan["selected_skills"]
        except Exception:
            pass  # Agent unavailable, use default
        result = await create_and_start_scan(target, scan_type, skills=enriched_skills)
        return json.dumps(result, ensure_ascii=False)

    if name == "get_task_status":
        result = await _get_task_status(args.get("task_id"))
        return json.dumps(result, ensure_ascii=False)

    if name == "get_task_vulnerabilities":
        result = await _get_vulns(args.get("task_id"))
        return json.dumps(result, ensure_ascii=False)

    if name == "get_tools_status":
        import httpx
        async with httpx.AsyncClient() as client:
            resp = await client.get("http://localhost:8000/api/tools/status/public")
            return json.dumps(resp.json(), ensure_ascii=False)

    if name == "execute_scan_phase":
        target = args.get("target")
        phase = args.get("phase")
        context = args.get("context", {})
        task_id = str(uuid.uuid4())
        now = datetime.utcnow()

        async with AsyncSessionLocal() as sess:
            sql = "INSERT INTO scan_tasks (id, target, scan_type, status, progress, result, created_at, updated_at) VALUES (:id, :target, :type, 'RUNNING', 0, :result, :now, :now)"
            await sess.execute(text(sql), {
                "id": task_id, "target": target,
                "type": "phase_" + phase,
                "result": json.dumps({"phase_mode": True, "phase": phase, "context": context}),
                "now": now,
            })
            await sess.commit()

        celery_app.send_task(EXECUTE_SCAN_TASK, args=[task_id, target, "phase_" + phase], queue="scan")
        return json.dumps({"task_id": task_id, "target": target, "phase": phase, "status": "PENDING"}, ensure_ascii=False)

    return json.dumps({"error": f"Unknown tool: {name}"})


# ═══════════════════════════════════════════════════════════
#  扫描生命周期管理
# ═══════════════════════════════════════════════════════════

async def create_and_start_scan(target: str, scan_type: str = "full", user_id: str = None, skills: list = None) -> dict:

    """创建扫描任务并发送到 Celery Worker"""
    task_id = str(uuid.uuid4())
    now = datetime.utcnow()

    async with AsyncSessionLocal() as sess:
        result_json = "{}"
        if skills:
            import json
            result_json = json.dumps({"selected_skills": skills})
        await sess.execute(text("""
            INSERT INTO scan_tasks (id, target, scan_type, status, progress, result, created_at, updated_at)
            VALUES (:id, :target, :type, 'PENDING', 0, :result, :now, :now)
        """), {"id": task_id, "target": target, "type": scan_type, "now": now, "result": result_json})
        await sess.commit()

    celery_app.send_task(EXECUTE_SCAN_TASK, args=[task_id, target, scan_type], queue="scan")

    return {"task_id": task_id, "target": target, "scan_type": scan_type, "status": "PENDING"}


async def cancel_scan(task_id: str) -> bool:
    async with AsyncSessionLocal() as sess:
        row = await sess.execute(text("SELECT status FROM scan_tasks WHERE id=:id"), {"id": task_id})
        row = row.fetchone()
        if not row or row[0] not in ("PENDING", "RUNNING"):
            return False
        await sess.execute(text("UPDATE scan_tasks SET status='CANCELLED', updated_at=:now WHERE id=:id"),
                           {"now": datetime.utcnow(), "id": task_id})
        await sess.commit()
        return True


async def _get_task_status(task_id: str) -> dict:
    async with AsyncSessionLocal() as sess:
        row = await sess.execute(text("SELECT status, progress, target, scan_type, error FROM scan_tasks WHERE id=:id"), {"id": task_id})
        row = row.fetchone()
        if not row:
            return {"error": "任务不存在"}
        return {"task_id": task_id, "status": row[0], "progress": row[1], "target": row[2], "scan_type": row[3], "error": row[4]}


async def _get_vulns(task_id: str) -> list:
    async with AsyncSessionLocal() as sess:
        rows = await sess.execute(text("""
            SELECT title, severity, cve_id, cvss_score, target, description, remediation, tool_source
            FROM vulnerabilities WHERE task_id=:id
        """), {"id": task_id})
        return [dict(r._mapping) for r in rows.fetchall()]
