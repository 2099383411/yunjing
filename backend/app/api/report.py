"""自动报告生成 API — 融合感知+推演+执行三层结果"""
import json, uuid
from fastapi import APIRouter, Query, HTTPException
from datetime import datetime

from app.grounding.perception import perceive_target
from app.grounding.cross_validation import cross_validate
from app.grounding.deduction import deduce_attack_paths
from app.grounding.smart_scanner import detect_target_type, optimize_strategy, prioritize_phases

router = APIRouter()


def _score_to_label(score: float) -> str:
    if score >= 8: return "critical"
    if score >= 6: return "high"
    if score >= 4: return "medium"
    return "low"


def _label_cn(label: str) -> str:
    return {
        "critical": "严重", "high": "高危", "medium": "中危", "low": "低危",
    }.get(label, label)


def _risk_color(label: str) -> str:
    return {
        "critical": "#ef4444", "high": "#f97316",
        "medium": "#eab308", "low": "#3b82f6",
    }.get(label, "#6b7280")


@router.get("/generate")
async def generate_report(
    target: str = Query(..., description="目标域名/IP"),
    include_perception: bool = Query(True),
    include_deduction: bool = Query(True),
    include_execution: bool = Query(False),
):
    """生成完整的安全评估报告"""
    report = {
        "report_id": str(uuid.uuid4())[:8],
        "target": target,
        "target_type": detect_target_type(target),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": "",
        "risk_level": "info",
        "sections": [],
        "executive_summary": "",
        "recommendations": [],
    }
    
    # ── Section 1: 情报概要 ──
    section1 = {
        "title": "情报概要",
        "icon": "📋",
        "items": [],
        "findings_count": 0,
    }
    section1["items"].append({
        "label": "目标类型",
        "value": report["target_type"],
        "severity": "info",
    })
    
    # ── Section 2: 感知层 — 资产画像 ──
    if include_perception:
        try:
            perception = await perceive_target(target)
            validated = cross_validate(perception)
            
            # 子域名
            all_subs = (
                validated.get("high_confidence_subdomains", []) +
                validated.get("medium_confidence_subdomains", []) +
                validated.get("low_confidence_subdomains", [])
            )
            
            section2 = {
                "title": "资产画像 (感知层)",
                "icon": "🔍",
                "subdomains": {
                    "count": len(all_subs),
                    "high_confidence": len(validated.get("high_confidence_subdomains", [])),
                    "medium_confidence": len(validated.get("medium_confidence_subdomains", [])),
                    "low_confidence": len(validated.get("low_confidence_subdomains", [])),
                    "items": [
                        {
                            "subdomain": s.get("subdomain", ""),
                            "confidence": s.get("confidence", 0),
                            "sources": s.get("sources", []),
                            "fingerprint": s.get("fingerprint", "")[:8],
                        }
                        for s in all_subs[:20]  # 前20个
                    ],
                },
                "technologies": {
                    "count": len(perception.get("technologies", [])),
                    "items": perception.get("technologies", []),
                },
                "endpoints": {
                    "count": len(perception.get("endpoints", [])),
                    "items": perception.get("endpoints", [])[:10],
                },
                "findings_count": len(all_subs) + len(perception.get("technologies", [])),
            }
            report["sections"].append(section2)
            
        except Exception as e:
            report["sections"].append({
                "title": "资产画像",
                "icon": "🔍",
                "error": str(e)[:100],
            })
    
    # ── Section 3: 推演层 — 攻击链分析 ──
    if include_deduction and include_perception:
        try:
            deduction = await deduce_attack_paths(
                perception.get("technologies", []),
                perception.get("subdomains", []),
            )
            
            paths = deduction.get("attack_paths", [])
            top_risks = deduction.get("top_risks", [])
            
            section3 = {
                "title": "攻击链分析 (推演层)",
                "icon": "🧠",
                "total_cves": deduction["total_cves_found"],
                "total_paths": deduction["total_paths"],
                "vector_distribution": deduction.get("vector_distribution", {}),
                "top_risks": top_risks,
                "attack_paths": [
                    {
                        "entry_point": p["entry_point"],
                        "category": p["category_label"],
                        "cve_count": len(p["cves"]),
                        "risk_score": p["scores"]["risk_score"],
                        "priority": p["scores"]["priority"],
                        "top_cves": [
                            {
                                "cve_id": c["cve_id"],
                                "cvss": c.get("cvss_score", 0),
                                "description": (c.get("description") or "")[:80],
                                "poc": c.get("poc_available", False),
                            }
                            for c in p["cves"][:3]
                        ],
                    }
                    for p in paths[:10]
                ],
                "attack_graph": deduction.get("attack_graph", {}),
                "findings_count": deduction["total_cves_found"],
            }
            report["sections"].append(section3)
            
        except Exception as e:
            report["sections"].append({
                "title": "攻击链分析",
                "icon": "🧠",
                "error": str(e)[:100],
            })
    
    # ── 计算总体风险 ──
    all_priorities = set()
    for path in paths if include_deduction else []:
        all_priorities.add(path["scores"]["priority"])
    
    if "critical" in all_priorities:
        report["risk_level"] = "critical"
        report["executive_summary"] = (
            f"对 {target} 的全面安全评估发现 **严重安全隐患**。"
            f"攻击面覆盖子域名、技术栈、已知CVE漏洞等多个维度，"
            f"存在可被远程利用的高危漏洞。"
        )
        report["recommendations"] = [
            "立即修复所有严重/高危漏洞",
            "对暴露面进行收窄和安全加固",
            "持续监控攻击链路变化",
        ]
    elif "high" in all_priorities:
        report["risk_level"] = "high"
        report["executive_summary"] = (
            f"对 {target} 的评估发现 **多处高风险暴露面**。"
            f"存在已知 CVE 漏洞，建议优先修复。"
        )
        report["recommendations"] = [
            "优先修复高危漏洞",
            "更新软件版本至最新",
            "实施 Web 应用防火墙",
        ]
    elif "medium" in all_priorities or perception:
        report["risk_level"] = "medium"
        report["executive_summary"] = (
            f"对 {target} 的评估发现 **中等风险暴露面**。"
            f"资产面较广，建议持续监控。"
        )
        report["recommendations"] = [
            "关注中危漏洞并及时修复",
            "定期进行安全扫描",
            "持续监控子域名变化",
        ]
    else:
        report["risk_level"] = "low"
        report["executive_summary"] = (
            f"对 {target} 的初步评估未发现明显安全隐患。"
        )
        report["recommendations"] = [
            "继续保持安全实践",
            "定期进行安全评估",
        ]
    
    # 摘要
    total_findings = sum(s.get("findings_count", 0) for s in report["sections"])
    report["summary"] = (
        f"共发现 **{total_findings} 项安全发现**，"
        f"整体风险等级: **{_label_cn(report['risk_level'])}**"
    )
    report["total_findings"] = total_findings
    
    return report


@router.get("/generate/summary")
async def report_summary(
    target: str = Query(..., description="目标"),
):
    """安全报告摘要 — 适合钉钉/IM 快速预览"""
    report = await generate_report(target)
    return {
        "target": target,
        "risk_level": report["risk_level"],
        "risk_label": _label_cn(report["risk_level"]),
        "risk_color": _risk_color(report["risk_level"]),
        "total_findings": report["total_findings"],
        "summary": report["summary"],
        "executive_summary": report["executive_summary"],
        "recommendations": report["recommendations"],
        "report_id": report["report_id"],
    }
