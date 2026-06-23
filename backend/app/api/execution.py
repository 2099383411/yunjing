"""执行层 API — CVE-to-Exploit 自动利用验证"""
import json
from fastapi import APIRouter, Query, HTTPException, Body
from pydantic import BaseModel
from typing import Optional, Any
from app.grounding.executor import exploit_cve, batch_exploit

router = APIRouter()


class ExploitRequest(BaseModel):
    cve_id: str
    target: str
    poc_command: str = ""


class BatchExploitRequest(BaseModel):
    targets: list[ExploitRequest]


@router.post("/exploit")
async def single_exploit(req: ExploitRequest):
    """对单个 CVE + 目标执行利用验证"""
    result = exploit_cve(req.cve_id, req.target, req.poc_command)
    return {
        "cve_id": req.cve_id,
        "target": req.target,
        "exploit_found": result["exploit_found"],
        "tools_tried": result["tools_tried"],
        "summary": result["summary"],
        "evidence_summary": [
            {
                "tool": e.get("tool", ""),
                "success": e.get("success") or e.get("found", False),
                "detail": str(e.get("search_result") or e.get("poc_output") or e.get("full_output", ""))[:200],
            }
            for e in result.get("evidence", [])
        ],
    }


@router.post("/exploit/batch")
async def batch_exploit_endpoint(req: BatchExploitRequest):
    """批量执行 CVE 利用验证"""
    cve_targets = [
        {"cve_id": t.cve_id, "target": t.target, "poc_command": t.poc_command}
        for t in req.targets
    ]
    results = batch_exploit(cve_targets)
    return {
        "total": len(results),
        "exploit_found_count": sum(1 for r in results if r["exploit_found"]),
        "results": [
            {
                "cve_id": r["cve_id"],
                "target": r["target"],
                "exploit_found": r["exploit_found"],
                "summary": r["summary"],
            }
            for r in results
        ],
    }


@router.post("/exploit/from-deduction")
async def exploit_from_deduction(
    target: str = Query(..., description="目标"),
    risk_threshold: str = Query("medium", description="最低风险级别: critical/high/medium/low"),
):
    """从推演结果自动触发利用验证"""
    # 先调用推演层获取攻击路径
    from app.grounding.deduction import deduce_attack_paths
    from app.grounding.perception import perceive_target
    
    perception = await perceive_target(target)
    technologies = perception.get("technologies", [])
    subdomains = perception.get("subdomains", [])
    deduction = await deduce_attack_paths(technologies, subdomains)
    
    # 筛选符合条件的攻击路径
    priority_order = {"critical": 8, "high": 6, "medium": 4, "low": 0}
    threshold = priority_order.get(risk_threshold, 4)
    
    cve_targets = []
    for path in deduction.get("attack_paths", []):
        for cve in path.get("cves", []):
            if (cve.get("cvss_score") or 0) >= threshold:
                cve_targets.append({
                    "cve_id": cve["cve_id"],
                    "target": target,
                    "poc_command": cve.get("poc_command", ""),
                })
    
    if not cve_targets:
        return {
            "target": target,
            "exploitable_cves": 0,
            "message": f"未找到 CVSS >= {threshold} 的 CVE",
        }
    
    results = batch_exploit(cve_targets)
    return {
        "target": target,
        "exploitable_cves": len(cve_targets),
        "exploit_found_count": sum(1 for r in results if r["exploit_found"]),
        "results": [
            {
                "cve_id": r["cve_id"],
                "exploit_found": r["exploit_found"],
                "tools": r["tools_tried"],
                "summary": r["summary"],
            }
            for r in results
        ],
    }
