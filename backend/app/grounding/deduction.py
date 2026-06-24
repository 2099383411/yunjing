"""攻击链推演引擎 (Deduction Engine)
将感知结果 → CVE匹配 → 攻击路径构建 → 风险排序"""
import json, re, asyncio
from typing import Optional
from sqlalchemy import select, cast, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models.cve_entry import CveEntry
from app.grounding.cve_database import find_cves_for_product, lookup_cve

# ── 攻击向量分类 ─────────────────────────────────────────
ATTACK_VECTORS = {
    "web": {
        "label": "Web 应用攻击",
        "order": 1,
        "color": "#ef4444",
        "sub_types": ["xss", "sql_injection", "csrf", "ssrf", "rce", "lfi", "ssti"],
    },
    "network": {
        "label": "网络服务攻击",
        "order": 2,
        "color": "#f97316",
        "sub_types": ["buffer_overflow", "dos", "mitm", "port_scan_exploit"],
    },
    "authentication": {
        "label": "认证与授权绕过",
        "order": 3,
        "color": "#eab308",
        "sub_types": ["auth_bypass", "privilege_escalation", "session_hijack"],
    },
    "information": {
        "label": "信息泄露",
        "order": 4,
        "color": "#3b82f6",
        "sub_types": ["path_disclosure", "information_exposure", "debug_endpoint"],
    },
    "crypto": {
        "label": "加密与协议攻击",
        "order": 5,
        "color": "#8b5cf6",
        "sub_types": ["weak_crypto", "protocol_downgrade", "ssl_tls"],
    },
}


def _detect_vuln_category(vuln_type: str, description: str) -> str:
    """根据漏洞类型和描述推断攻击链分类"""
    text = f"{vuln_type} {description}".lower()
    if any(w in text for w in ["xss", "cross-site", "cross_site", "csrf"]):
        return "web"
    if any(w in text for w in ["sql", "injection", "sqli"]):
        return "web"
    if any(w in text for w in ["rce", "remote code", "command", "exec", "arbitrary"]):
        return "web"
    if any(w in text for w in ["buffer", "overflow", "dos", "denial"]):
        return "network"
    if any(w in text for w in ["auth", "bypass", "privilege", "escalation"]):
        return "authentication"
    if any(w in text for w in ["information", "disclosure", "leak", "exposure"]):
        return "information"
    if any(w in text for w in ["ssl", "tls", "crypto", "certificate"]):
        return "crypto"
    return "network"


def _score_attack_path(cves: list, confidence: float = 0.5) -> dict:
    if not cves:
        return {"likelihood": 0, "impact": 0, "risk_score": 0, "priority": "low"}
    max_cvss = max((c.get("cvss_score", 0) or 0) for c in cves)
    avg_cvss = sum((c.get("cvss_score", 0) or 0) for c in cves) / len(cves)
    poc_count = sum(1 for c in cves if c.get("poc_available"))
    high_count = sum(1 for c in cves if (c.get("cvss_score", 0) or 0) >= 7.0)
    exploitability = min(10, (
        (poc_count / max(len(cves), 1)) * 5 +
        (high_count / max(len(cves), 1)) * 3 +
        min(confidence * 2, 2)
    ))
    impact = min(10, max_cvss + (avg_cvss * 0.3))
    risk_score = exploitability * 0.4 + impact * 0.6
    priority = "critical" if risk_score >= 8 else \
               "high" if risk_score >= 6 else \
               "medium" if risk_score >= 4 else "low"
    return {
        "likelihood": round(exploitability, 1),
        "impact": round(impact, 1),
        "risk_score": round(risk_score, 1),
        "priority": priority,
        "cve_count": len(cves),
        "poc_available_count": poc_count,
    }


PRODUCT_KEYWORDS = {
    "nginx": ["nginx", "openresty"],
    "apache": ["apache", "httpd", "tomcat"],
    "openssh": ["openssh", "ssh"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql", "postgres"],
    "redis": ["redis"],
    "php": ["php"],
    "wordpress": ["wordpress", "wp"],
    "iis": ["iis"],
    "gitlab": ["gitlab"],
    "jenkins": ["jenkins"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "mongodb": ["mongodb", "mongo"],
    "python": ["python", "flask", "django", "fastapi"],
    "java": ["java", "spring", "struts", "weblogic", "jboss"],
    "node": ["node.js", "nodejs", "express", "next.js"],
}


async def _keyword_search_cves(sess, keywords: list[str]) -> list[CveEntry]:
    """通过 description 关键词搜索 CVE"""
    all_hits = []
    seen = set()
    for kw in keywords:
        if len(kw) < 3:
            continue
        r = await sess.execute(
            select(CveEntry).where(
                CveEntry.description.ilike(f"%{kw}%")
            ).limit(20)
        )
        for entry in r.scalars():
            if entry.cve_id not in seen:
                seen.add(entry.cve_id)
                all_hits.append(entry)
        
        # 也搜 affected_versions (cast to string)
        r2 = await sess.execute(
            select(CveEntry).where(
                CveEntry.affected_versions.isnot(None),
                cast(CveEntry.affected_versions, String).ilike(f"%{kw}%")
            ).limit(20)
        )
        for entry in r2.scalars():
            if entry.cve_id not in seen:
                seen.add(entry.cve_id)
                all_hits.append(entry)
    
    return all_hits


async def match_cves_for_product(tech: dict) -> list[CveEntry]:
    product = (tech.get("product") or tech.get("name") or "").lower()
    version = tech.get("version", "")
    
    all_cves = []
    seen = set()
    async with AsyncSessionLocal() as sess:
        # 策略1: 精确产品型号匹配
        cves = await find_cves_for_product(sess, product, version)
        for c in cves:
            if c.cve_id not in seen:
                seen.add(c.cve_id)
                all_cves.append(c)
        
        # 策略2: 关键词匹配 (description)
        keywords = [product]
        for key, kw_list in PRODUCT_KEYWORDS.items():
            if any(kw in product for kw in kw_list):
                keywords.append(key)
                keywords.extend(kw_list)
        
        desc_cves = await _keyword_search_cves(sess, keywords)
        for c in desc_cves:
            if c.cve_id not in seen:
                seen.add(c.cve_id)
                all_cves.append(c)
    
    return all_cves


async def deduce_attack_paths(technologies: list[dict], subdomains: list[dict] = None) -> dict:
    all_paths = []
    all_cves = []
    vector_stats = {}
    
    for tech in technologies:
        product = tech.get("product") or tech.get("name") or "?"
        version = tech.get("version", "")
        cves = await match_cves_for_product(tech)
        
        if cves:
            cve_list = [{
                "cve_id": c.cve_id,
                "description": c.description,
                "cvss_score": c.cvss_score,
                "severity": c.severity,
                "vuln_type": c.vuln_type,
                "poc_available": c.poc_available,
                "poc_command": c.poc_command,
            } for c in cves]
            
            category = _detect_vuln_category(cves[0].vuln_type or "", cves[0].description or "")
            vector = ATTACK_VECTORS.get(category, ATTACK_VECTORS["network"])
            
            path = {
                "entry_point": f"{product} {version}".strip(),
                "product": product,
                "version": version,
                "category": category,
                "category_label": vector["label"],
                "vector_color": vector["color"],
                "cves": cve_list,
                "scores": _score_attack_path(cve_list, confidence=1.0 if version else 0.5),
            }
            all_paths.append(path)
            all_cves.extend(cve_list)
            
            if category not in vector_stats:
                vector_stats[category] = {"label": vector["label"], "count": 0, "max_cvss": 0}
            vector_stats[category]["count"] += len(cves)
            max_cv = max((c.get("cvss_score", 0) or 0) for c in cve_list)
            vector_stats[category]["max_cvss"] = max(vector_stats[category]["max_cvss"], max_cv)
        else:
            all_paths.append({
                "entry_point": f"{product} {version}".strip(),
                "product": product,
                "version": version,
                "category": "unknown",
                "category_label": "无已知CVE",
                "vector_color": "#6b7280",
                "cves": [],
                "scores": {"likelihood": 0.5, "impact": 0, "risk_score": 0.5, "priority": "low", "cve_count": 0},
            })
    
    # 攻击链图
    edges = []
    nodes = set()
    for path in all_paths:
        if path["cves"]:
            from_node = path["product"]
            nodes.add(from_node)
            for cve in path["cves"][:3]:
                nodes.add(cve["cve_id"])
                edges.append({
                    "from": from_node,
                    "to": cve["cve_id"],
                    "label": f"CVSS {cve.get('cvss_score', 'N/A')}",
                    "color": path["vector_color"],
                })
    
    all_paths.sort(key=lambda p: p["scores"]["risk_score"], reverse=True)
    
    top_risks = []
    for p in all_paths:
        if p["cves"]:
            top_risks.append({
                "entry_point": p["entry_point"],
                "risk_score": p["scores"]["risk_score"],
                "priority": p["scores"]["priority"],
                "cve_count": p["scores"]["cve_count"],
                "vector": p["category_label"],
            })
            if len(top_risks) >= 5:
                break
    
    return {
        "attack_paths": all_paths,
        "total_cves_found": len(all_cves),
        "total_paths": len(all_paths),
        "vector_distribution": vector_stats,
        "attack_graph": {"nodes": [{"id": n} for n in nodes], "edges": edges},
        "top_risks": top_risks,
    }
