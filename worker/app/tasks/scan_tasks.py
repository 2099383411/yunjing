"""扫描工具检测与执行任务 — 技能驱动的动态 DAG 编排引擎"""

import re
import json
import logging

from celery_app import app

from tasks.scan_helpers import (
    _exec, _exec_tool, _publish, _publish_phase, _gen_id,
    _strip_url, _parse_target, _check_target_alive,
    _severity_score, _dedup_findings, _log_phase,
    _execute_in_sandbox,
    _register_actions, _execute_decision_action, _update_scan_state,
    TOOLS_CONFIG, SANDBOX_ENV, SANDBOX_NAME, _engine,
    ACTION_ROUTER, SEVERITY_MAP, SKILL_PHASES, PHASE_ORDER, PHASE_WEIGHT,
    logger,
)

from tasks.scan_actions import (
    _action_port_scan, _action_full_port_scan, _action_service_detect,
    _action_vuln_scan, _action_dir_bruteforce, _action_web_tech,
    _action_nikto_scan, _action_credential_test, _action_sql_injection,
    _action_auth_bypass, _action_web_fuzz, _action_api_scan,
    _action_smb_enum, _action_lateral_probe, _action_exploit,
    _action_post_exploit,
    _phase_asset_discovery, _phase_port_scan, _phase_service_detect,
    _phase_nuclei_scan, _phase_nikto_scan, _phase_whatweb,
    _phase_directory_scan, _phase_osint_gather, _phase_exploitation,
    _phase_post_exploit as _phase_post_exploit_fn,
    _phase_web_fuzz, _phase_api_scan, _phase_auth_test,
    _phase_krb_scan, _phase_ad_enum, _phase_code_scan, _phase_threat_model,
)

from tasks.scan_monitor import monitor_loop

# ═══════════════════════════════════════════════════════════
#  扫描执行主入口（Celery 任务注册 → 委托给 scan_decision）
# ═══════════════════════════════════════════════════════════

@app.task(bind=True, max_retries=3)
def execute_scan(self, task_id: str, target: str, scan_type: str = "full") -> dict:
    """Celery 任务入口：执行扫描（委托给 scan_decision.execute_scan）"""
    from tasks.scan_decision import execute_scan as _exec
    return _exec(self, task_id, target, scan_type)


# ═══════════════════════════════════════════════════════════
#  工具版本检测
# ═══════════════════════════════════════════════════════════

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
        m = re.search(r"version[:\\s]*([vV]?[\\d][\\w.]*)", output, re.IGNORECASE)
        ver = m.group(1).strip() if m else (output.strip().split("\\n")[0][:80] if output else "unknown")
        return {"name": name, "installed": True, "version": ver, "status": "ready"}
    except Exception as e:
        return {"name": name, "installed": False, "version": None, "status": "error", "error": str(e)[:80]}


# ═══════════════════════════════════════════════════════════
#  报告生成 (占位 → Phase 3 完善)
# ═══════════════════════════════════════════════════════════

@app.task(bind=True)
def generate_report(self, task_id):
    return {"status": "pending", "task_id": task_id}


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
            data = _phase_post_exploit_fn(target, ports)
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


# ─── 启动 Monitor Agent ──────────────────────────
import threading
_monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
_monitor_thread.start()
logger.info("[Monitor] Monitor Agent 已启动")
