"""扫描工具检测与执行任务 — 辅助函数模块"""

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

from app.core.config import targets

logger = logging.getLogger(__name__)


# ─── 数据库 + Redis ──────────────────────────────────────

DB_URL = os.environ.get("SYNC_DATABASE_URL", os.environ.get("DATABASE_URL", "postgresql://yunjing:***@postgres:5432/yunjing").replace("+asyncpg", ""))

_engine = create_engine(DB_URL, pool_pre_ping=True, pool_size=5)

_redis = redis.Redis.from_url("redis://redis:6379/1", decode_responses=True)



SANDBOX_NAME = "yunjing-sbx"

SANDBOX_ENV = "/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"



# URL helper


def _strip_url(url):
    """Strip http:// or https:// prefix. Handle CIDR and host:port without scheme."""
    from urllib.parse import urlparse
    if "/" in url and not url.startswith("http"):
        return url.split("/")[0]
    # host:port without scheme - urlparse gives None hostname
    if not url.startswith("http") and ":" in url:
        return url.rsplit(":", 1)[0]
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


# ═══════════════════════════════════════════════════════════
#  严重度评分
# ═══════════════════════════════════════════════════════════

SEVERITY_MAP = {
    "critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
    "none": 0, "unknown": 0,
}


def _severity_score(s: str) -> int:
    return SEVERITY_MAP.get(s.lower().strip(), 0)


# ═══════════════════════════════════════════════════════════
#  Helper 函数
# ═══════════════════════════════════════════════════════════


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


def _dedup_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for f in sorted(findings, key=lambda x: -_severity_score(x.get("severity", "info"))):
        key = f.get("title", "").lower()[:100]
        if key and key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _log_phase(log: list, name: str, status: str, data=None):
    entry = {"name": name, "status": status}
    if data:
        entry["data"] = data
    log.append(entry)


# ═══════════════════════════════════════════════════════════
#  决策循环辅助函数 — 动作调度器 + 状态管理器
# ═══════════════════════════════════════════════════════════

ACTION_ROUTER = {}


def _register_actions():
    """注册所有可用动作到路由表"""
    global ACTION_ROUTER
    # 延迟导入避免循环依赖
    from tasks.scan_actions import (
        _action_port_scan, _action_full_port_scan, _action_service_detect,
        _action_vuln_scan, _action_dir_bruteforce, _action_web_tech,
        _action_nikto_scan, _action_credential_test, _action_sql_injection,
        _action_auth_bypass, _action_web_fuzz, _action_api_scan,
        _action_smb_enum, _action_lateral_probe, _action_exploit,
        _action_post_exploit,
    )
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
