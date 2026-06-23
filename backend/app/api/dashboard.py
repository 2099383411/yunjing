"""云镜渗透态势 API — 统计/拓扑/攻击链"""
from fastapi import APIRouter
from sqlalchemy import create_engine, text as sa_text
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import json

from app.config import settings; DB_URL = settings.DATABASE_URL.replace("+asyncpg", "")
router = APIRouter()

PTES_PHASES = [
    "intelligence_gathering", "threat_modeling", "vulnerability_analysis",
    "exploitation", "post_exploitation", "reporting",
]


def _safe_json(val):
    if val is None:
        return {}
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            pass
    return {}


# ═══════════════════════════════════════════════════
# GET /stats  — Dashboard statistics
# ═══════════════════════════════════════════════════
@router.get("/stats")
async def dashboard_stats():
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        task_row = db.execute(sa_text("""
            SELECT COUNT(*),
                   COUNT(*) FILTER (WHERE status = 'COMPLETED'),
                   COUNT(*) FILTER (WHERE status = 'RUNNING'),
                   COUNT(*) FILTER (WHERE status = 'FAILED'),
                   COUNT(*) FILTER (WHERE status = 'PENDING'),
                   COUNT(DISTINCT target)
            FROM scan_tasks
        """)).fetchone()
        task_stats = {
            "total": task_row[0], "completed": task_row[1], "running": task_row[2],
            "failed": task_row[3], "pending": task_row[4], "unique_targets": task_row[5],
        }

        vuln_row = db.execute(sa_text("""
            SELECT COUNT(*),
                   COUNT(*) FILTER (WHERE severity = 'critical'),
                   COUNT(*) FILTER (WHERE severity = 'high'),
                   COUNT(*) FILTER (WHERE severity = 'medium'),
                   COUNT(*) FILTER (WHERE severity = 'low'),
                   COUNT(*) FILTER (WHERE severity = 'info')
            FROM vulnerabilities
        """)).fetchone()
        vuln_stats = {
            "total": vuln_row[0], "critical": vuln_row[1], "high": vuln_row[2],
            "medium": vuln_row[3], "low": vuln_row[4], "info": vuln_row[5],
            "total_high_risk": (vuln_row[1] or 0) + (vuln_row[2] or 0),
        }

        # Phase progress
        result_rows = db.execute(sa_text("""
            SELECT id, result FROM scan_tasks
            WHERE result IS NOT NULL AND result::text != '' AND result::text != 'null'
        """)).fetchall()

        phase_completed = {p: 0 for p in PTES_PHASES}
        phase_total = {p: 0 for p in PTES_PHASES}
        all_ports, all_services = {}, {}

        for row in result_rows:
            res = _safe_json(row[1])
            if not isinstance(res, dict):
                continue
            phases = res.get("phases", [])
            if isinstance(phases, list):
                for entry in phases:
                    name = entry.get("name", "") if isinstance(entry, dict) else ""
                    status = entry.get("status", "") if isinstance(entry, dict) else ""
                    ptes_map = {"port_scan": "intelligence_gathering", "service_detect": "intelligence_gathering",
                                "vuln_scan": "vulnerability_analysis", "web_test": "vulnerability_analysis"}
                    ptes = ptes_map.get(name)
                    if ptes:
                        phase_total[ptes] += 1
                        if status == "done":
                            phase_completed[ptes] += 1

            phases_log = res.get("phases_log", {})
            if isinstance(phases_log, dict):
                for p, info in phases_log.items():
                    if p in phase_completed:
                        phase_total[p] += 1
                        if isinstance(info, dict) and info.get("status") == "completed":
                            phase_completed[p] += 1

            summary = res.get("summary", {})
            if isinstance(summary, dict):
                ports = summary.get("ports_detailed", [])
                if isinstance(ports, list):
                    for p in ports:
                        if isinstance(p, dict):
                            key = f"{p.get('port', '?')}/{p.get('protocol', 'tcp')}"
                            all_ports[key] = all_ports.get(key, 0) + 1
                svcs = summary.get("services_detailed", [])
                if isinstance(svcs, list):
                    for s in svcs:
                        if isinstance(s, dict) and s.get("service"):
                            all_services[s["service"]] = all_services.get(s["service"], 0) + 1

        phase_progress = {p: {"completed": phase_completed[p], "total": phase_total[p]} for p in PTES_PHASES}
        total_done = sum(phase_completed.values())
        total_possible = sum(phase_total.values()) or 1

        attack_surface = {
            "ports_count": len(all_ports),
            "services_count": len(all_services),
            "ports": [{"name": k, "count": v} for k, v in sorted(all_ports.items(), key=lambda x: -x[1])[:20]],
            "services": [{"name": k, "count": v} for k, v in sorted(all_services.items(), key=lambda x: -x[1])[:20]],
        }

        # Trend
        trend_rows = db.execute(sa_text("""
            SELECT DATE(created_at), COUNT(*),
                   COUNT(*) FILTER (WHERE status = 'COMPLETED'),
                   COUNT(*) FILTER (WHERE status = 'FAILED')
            FROM scan_tasks WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(created_at) ORDER BY DATE(created_at)
        """)).fetchall()
        trend_map = {}
        for r in trend_rows:
            d = str(r[0]) if hasattr(r[0], 'isoformat') else str(r[0])
            trend_map[d] = {"scans": r[1], "completed": r[2], "failed": r[3]}
        trend = []
        for i in range(6, -1, -1):
            day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
            data = trend_map.get(day, {"scans": 0, "completed": 0, "failed": 0})
            trend.append({"date": day, **data})

        top_vulns = db.execute(sa_text("""
            SELECT title, severity, COUNT(*) AS cnt FROM vulnerabilities
            GROUP BY title, severity
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, cnt DESC
            LIMIT 10
        """)).fetchall()

        recent_rows = db.execute(sa_text("""
            SELECT id, target, scan_type, status, progress, created_at, completed_at
            FROM scan_tasks ORDER BY created_at DESC LIMIT 10
        """)).fetchall()

        vuln_risk = (vuln_stats["critical"] or 0) * 10 + (vuln_stats["high"] or 0) * 5 + (vuln_stats["medium"] or 0) * 2
        phase_score = int((total_done / total_possible) * 100)
        overall_score = max(0, min(100, 100 - vuln_risk + phase_score // 5))

    return {
        "task_stats": task_stats,
        "vuln_stats": vuln_stats,
        "phase_progress": phase_progress,
        "phase_summary": {"total_done": total_done, "total": total_possible, "progress_pct": int(total_done / total_possible * 100)},
        "attack_surface": attack_surface,
        "trend": trend,
        "top_vulns": [{"title": r[0], "severity": r[1], "count": r[2]} for r in top_vulns],
        "recent_tasks": [{"id": r[0], "target": r[1], "scan_type": r[2], "status": r[3], "progress": r[4], "created_at": str(r[5]) if r[5] else None, "completed_at": str(r[6]) if r[6] else None} for r in recent_rows],
        "score": overall_score,
    }


# ═══════════════════════════════════════════════════
# GET /topology  — Network topology graph
# ═══════════════════════════════════════════════════
@router.get("/topology")
async def topology():
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        rows = db.execute(sa_text("""
            SELECT id, target, result FROM scan_tasks
            WHERE status = 'COMPLETED' AND result IS NOT NULL AND result::text != ''
        """)).fetchall()

    nodes = {}
    edges = []

    for task_id, target, result_raw in rows:
        res = _safe_json(result_raw)
        if not isinstance(res, dict):
            continue

        ip = target
        compromised = False
        ports_found = []
        services = []

        summary = res.get("summary", {})
        if isinstance(summary, dict):
            ports_found = summary.get("ports_detailed", []) or []
            services = summary.get("services_detailed", []) or []
            compromised = summary.get("compromised", False)

        phases_log = res.get("phases_log", {})
        if isinstance(phases_log, dict):
            for pn, pi in phases_log.items():
                if isinstance(pi, dict):
                    f = pi.get("findings", {})
                    if isinstance(f, dict):
                        for p in (f.get("ports", []) or []):
                            if isinstance(p, dict):
                                ports_found.append(p)

        if ip not in nodes:
            nodes[ip] = {
                "id": f"host-{ip.replace('.', '-')}", "label": ip, "ip": ip,
                "type": "host", "ports": [], "services": [], "vuln_count": 0,
                "vuln_by_severity": {}, "vuln_high_count": 0,
                "compromised": False, "risk_score": 0,
            }

        node = nodes[ip]
        for p in ports_found:
            if isinstance(p, dict) and p.get("port"):
                existing = [x.get("port") for x in node["ports"]]
                if p["port"] not in existing:
                    node["ports"].append({"port": p["port"], "protocol": p.get("protocol", "tcp"), "service": p.get("service", "unknown")})
        for s in services:
            if isinstance(s, dict) and s.get("service"):
                existing = [x.get("service") for x in node["services"]]
                if s["service"] not in existing:
                    node["services"].append({"service": s["service"], "version": s.get("version", "?"), "port": s.get("port", "?")})
        if compromised:
            node["compromised"] = True

    # Vulnerability counts per target
    with Session(engine) as db:
        for ip in nodes:
            vuln_rows = db.execute(sa_text(f"""
                SELECT severity, COUNT(*) FROM vulnerabilities WHERE target = '{ip}'
                GROUP BY severity
            """)).fetchall()
            node = nodes[ip]
            node["vuln_by_severity"] = {r[0]: r[1] for r in vuln_rows}
            node["vuln_high_count"] = sum(c for s, c in vuln_rows if s in ("critical", "high"))
            node["vuln_count"] = sum(c for _, c in vuln_rows)
            node["risk_score"] = min(100, len(node["ports"]) * 8 + node["vuln_high_count"] * 12 + (35 if node["compromised"] else 0))

    # Label specific hosts
    if "172.18.0.11" in nodes:
        nodes["172.18.0.11"]["label"] = "DVWA靶场"
    if "172.18.0.1" in nodes:
        nodes["172.18.0.1"]["label"] = "网关"
    if "192.168.1.165" in nodes:
        nodes["192.168.1.165"]["label"] = "开发机"
    if "scanme.nmap.org" in nodes:
        nodes["scanme.nmap.org"]["label"] = "scanme.nmap.org"
        nodes["scanme.nmap.org"]["type"] = "external"

    # Edges
    edge_pairs = [("172.18.0.11", "172.18.0.1", "network", "网关")]
    if "192.168.1.165" in nodes and "192.168.1.1" in nodes:
        edge_pairs.append(("192.168.1.165", "192.168.1.1", "network", "网关"))
    if "scanme.nmap.org" in nodes:
        edge_pairs.append(("scanme.nmap.org", "Internet", "network", "外网"))

    for src, tgt, etype, elabel in edge_pairs:
        if src in nodes and tgt in nodes:
            edges.append({"id": f"e-{src}-{tgt}", "source": nodes[src]["id"], "target": nodes[tgt]["id"], "type": etype, "label": elabel})

    # Attack path
    if "172.18.0.11" in nodes and nodes["172.18.0.11"]["compromised"]:
        edges.append({
            "id": "attack-dvwa", "source": "Internet",
            "target": nodes["172.18.0.11"]["id"],
            "type": "attack", "label": "HTTP(80) 渗透",
            "animated": True, "style": {"stroke": "#ff3366", "strokeWidth": 3},
        })

    all_nodes = list(nodes.values())
    all_nodes.insert(0, {"id": "Internet", "label": "互联网", "type": "internet", "ip": "0.0.0.0",
                         "ports": [], "services": [], "vuln_count": 0, "vuln_by_severity": {},
                         "vuln_high_count": 0, "compromised": False, "risk_score": 0})

    return {"nodes": all_nodes, "edges": edges}


# ═══════════════════════════════════════════════════
# GET /attack-chain  — Attack chain steps
# ═══════════════════════════════════════════════════
@router.get("/attack-chain")
async def attack_chain():
    engine = create_engine(DB_URL)
    with Session(engine) as db:
        rows = db.execute(sa_text("""
            SELECT id, target, result FROM scan_tasks
            WHERE status = 'COMPLETED' AND result IS NOT NULL AND result::text != ''
            ORDER BY created_at DESC LIMIT 5
        """)).fetchall()

    chains = []
    for task_id, target, result_raw in rows:
        res = _safe_json(result_raw)
        if not isinstance(res, dict):
            continue
        phases_log = res.get("phases_log", {})
        if not isinstance(phases_log, dict):
            continue

        phase_order = [
            ("intelligence_gathering", "情报收集", "🔍"),
            ("threat_modeling", "威胁建模", "🧠"),
            ("vulnerability_analysis", "漏洞分析", "💥"),
            ("exploitation", "漏洞利用", "⚡"),
            ("post_exploitation", "后渗透", "🕳️"),
            ("reporting", "报告生成", "📋"),
        ]

        steps = []
        for key, label, icon in phase_order:
            phase = phases_log.get(key, {})
            if not isinstance(phase, dict):
                continue
            status = phase.get("status", "pending")
            findings = phase.get("findings", {})
            if not isinstance(findings, dict):
                findings = {}

            description, detail_items = "", []

            if key == "intelligence_gathering":
                ports = findings.get("ports", [])
                os_info = findings.get("os", "")
                description = f"发现 {len(ports)} 个开放端口, {os_info}" if ports else "资产发现"
                detail_items = [f"端口 {p.get('port')}/{p.get('protocol','tcp')} - {p.get('service','?')} {p.get('version','')}" for p in ports[:5] if isinstance(p, dict)]
            elif key == "threat_modeling":
                risk = findings.get("risk_score", 0)
                surface = findings.get("attack_surface", [])
                description = f"攻击面评分: {risk}" if risk else "威胁建模"
                detail_items = surface[:3] if isinstance(surface, list) else []
            elif key == "vulnerability_analysis":
                vulns = findings.get("vulnerabilities", [])
                description = f"发现 {len(vulns)} 个漏洞"
                detail_items = [f"[{v.get('severity','?')}] {v.get('title','?')}" for v in vulns[:5] if isinstance(v, dict)]
            elif key == "exploitation":
                exploits = findings.get("exploits_attempted", [])
                success = sum(1 for e in exploits if isinstance(e, dict) and e.get("success"))
                description = f"尝试 {len(exploits)} 个利用, {success} 成功"
                detail_items = [f"{'✅' if e.get('success') else '❌'} {e.get('name','?')}" for e in exploits[:5] if isinstance(e, dict)]
            elif key == "post_exploitation":
                hosts = findings.get("compromised_hosts", [])
                foothold = findings.get("foothold", "")
                description = f"已控制 {len(hosts)} 台主机" if hosts else "后渗透"
                detail_items = [f"据点: {foothold}"] if foothold else []
            elif key == "reporting":
                risk_level = findings.get("risk_level", "")
                summary = findings.get("summary", "")
                description = f"风险等级: {risk_level}" if risk_level else "报告"
                detail_items = [summary] if summary else []

            steps.append({"phase": key, "label": label, "icon": icon, "status": status, "description": description, "details": detail_items, "target": target})

        chains.append({"id": task_id, "task_id": task_id, "target": target, "steps": steps,
                       "total_steps": len(steps), "completed_steps": sum(1 for s in steps if s["status"] == "completed")})

    return {"chains": chains}
