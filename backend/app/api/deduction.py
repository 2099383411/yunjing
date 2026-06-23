"""推演层 API — 攻击路径自动推演"""
import asyncio
from fastapi import APIRouter, Query, HTTPException
from typing import Optional
from app.grounding.perception import perceive_target
from app.grounding.deduction import deduce_attack_paths

router = APIRouter()


@router.get("/deduce")
async def deduce(
    target: str = Query(..., description="目标域名/IP"),
    with_perception: bool = Query(True, description="是否先执行感知层侦察"),
):
    """对目标进行攻击路径推演"""
    technologies = []
    subdomains = []
    
    if with_perception:
        try:
            perception = await perceive_target(target)
            technologies = perception.get("technologies", [])
            subdomains = perception.get("subdomains", [])
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"感知层失败: {str(e)[:100]}")
    
    # 没有技术栈但有子域名 → 用子域名逐个探测
    if not technologies and subdomains:
        # 取前3个子域名去推 Web 技术栈
        for sub in subdomains[:3]:
            sub_domain = sub.get("subdomain", "")
            if sub_domain:
                try:
                    sub_perception = await perceive_target(sub_domain)
                    sub_techs = sub_perception.get("technologies", [])
                    for t in sub_techs:
                        t["source_subdomain"] = sub_domain
                    technologies.extend(sub_techs)
                except Exception:
                    pass
    
    result = await deduce_attack_paths(technologies, subdomains)
    result["target"] = target
    result["technology_count"] = len(technologies)
    result["subdomain_count"] = len(subdomains)
    
    return result


@router.get("/deduce/summary")
async def deduce_summary(
    target: str = Query(..., description="目标域名/IP"),
):
    """攻击推演摘要"""
    result = await deduce(target=target, with_perception=True)
    
    summary = {
        "target": target,
        "total_attack_paths": result["total_paths"],
        "total_cves": result["total_cves_found"],
        "technology_count": result["technology_count"],
        "vector_distribution": result.get("vector_distribution", {}),
        "risk_summary": {},
    }
    
    # 风险概览
    for path in result.get("attack_paths", []):
        priority = path["scores"]["priority"]
        if priority not in summary["risk_summary"]:
            summary["risk_summary"][priority] = {"count": 0, "paths": []}
        summary["risk_summary"][priority]["count"] += 1
        if path["cves"]:
            summary["risk_summary"][priority]["paths"].append({
                "entry_point": path["entry_point"],
                "risk_score": path["scores"]["risk_score"],
                "cve_count": len(path["cves"]),
            })
    
    return summary
