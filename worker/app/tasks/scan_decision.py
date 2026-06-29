"""扫描工具检测与执行任务 — 主 DAG 引擎（决策循环）"""

import json
import logging
import uuid
from datetime import datetime

from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.orm import Session

from tasks.scan_helpers import (
    _engine, _publish, _check_target_alive, _parse_target, _gen_id,
    _dedup_findings, _execute_decision_action, _update_scan_state, _publish_phase,
    _severity_score, _log_phase, _strip_url,
)
from tasks.scan_actions import (
    _phase_port_scan, _phase_service_detect, _phase_nuclei_scan, _phase_nikto_scan,
    _phase_whatweb, _phase_directory_scan, _phase_osint_gather, _phase_exploitation,
    _phase_post_exploit, _phase_web_fuzz, _phase_api_scan, _phase_auth_test,
    _phase_krb_scan, _phase_ad_enum, _phase_code_scan, _phase_threat_model,
    _phase_asset_discovery,
)
from tasks.scan_observer import ScanObserver

logger = logging.getLogger(__name__)


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
                _publish(task_id, "round_start", {"round": 1,
        "phases_log": [],
        "phases_log": [], "target": target, "scan_type": "round"})
                report = execute_round_1(
                    task_id=task_id, target=target, host=host,
                    start_time=start_time, db=db, _engine=_engine,
                    _publish=_publish,
                    execute_action_func=_execute_decision_action,
                    _update_state_func=_update_scan_state,
                )
                _publish(task_id, "round_complete", {"round": 1,
        "phases_log": [],
        "phases_log": [], "report": {
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
                        findings_list = action.get("findings") or action.get("result", {}).get("findings", [])
                        if isinstance(findings_list, list):
                            for f in findings_list:
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
            state.setdefault("phases_log", []).append({"name": action_name, "status": "done", "data": {"findings_count": result.get("findings_count", 0)}})

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
