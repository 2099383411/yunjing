"""感知层完整 API — 多信源感知 + 交叉验证 + 置信度评分"""
import asyncio
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from typing import Optional, Any
from app.grounding.perception import perceive_target
from app.grounding.cross_validation import cross_validate
from app.grounding.smart_scanner import detect_target_type, optimize_strategy, analyze_ports, prioritize_phases

router = APIRouter()

class AssetProfileResponse(BaseModel):
    """完整的资产画像响应"""
    target: str
    domain: Optional[str] = None
    raw_perception: dict = {}          # 原始感知数据
    validated: dict = {}                # 交叉验证后的数据
    profile_summary: str = ""           # 资产画像摘要
    error: Optional[str] = None

class SubdomainResponse(BaseModel):
    subdomain: str
    source: str = ""
    confidence: float = 0.0
    not_after: Optional[str] = None
    ip: Optional[str] = None

class TechnologyResponse(BaseModel):
    name: str
    category: str = ""
    source: str = ""
    confidence: float = 0.0

class EndpointResponse(BaseModel):
    endpoint: str
    type: str = ""
    confidence: float = 0.0
    source_url: Optional[str] = None


@router.get("/profile", response_model=AssetProfileResponse)
async def get_asset_profile(
    target: str = Query(..., description="扫描目标 IP/域名/URL"),
    include_raw: bool = Query(False, description="是否包含原始感知数据"),
):
    """获取完整资产画像（感知 + 交叉验证 + 置信度评分）"""
    if not target or len(target) < 2:
        raise HTTPException(status_code=400, detail="目标无效")
    
    try:
        # Step 1: 感知
        perception_result = await perceive_target(target)
        
        # Step 2: 交叉验证
        validated = cross_validate(perception_result)
        
        return AssetProfileResponse(
            target=target,
            domain=perception_result.get("domain"),
            raw_perception=perception_result if include_raw else {},
            validated=validated,
            profile_summary=validated.get("profile_summary", ""),
        )
    except Exception as e:
        return AssetProfileResponse(
            target=target,
            error=str(e)[:200],
        )


@router.get("/profile/summary")
async def get_asset_summary(target: str = Query(..., description="目标")):
    """获取精简资产画像摘要"""
    try:
        perception_result = await perceive_target(target)
        validated = cross_validate(perception_result)
        return {
            "target": target,
            "profile_summary": validated.get("profile_summary", ""),
            "high_confidence_subdomains": len(validated.get("high_confidence_subdomains", [])),
            "high_confidence_technologies": len(validated.get("high_confidence_technologies", [])),
            "total_subdomains": validated.get("total_subdomains", 0),
            "total_technologies": validated.get("total_technologies", 0),
            "total_endpoints": validated.get("total_endpoints", 0),
        }
    except Exception as e:
        return {"target": target, "error": str(e)[:200]}


@router.get("/subdomains/validated")
async def get_validated_subdomains(
    domain: str = Query(..., description="域名"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, le=200),
):
    """获取经过置信度评分的子域名列表"""
    try:
        perception_result = await perceive_target(domain)
        validated = cross_validate(perception_result)
        
        all_subs = validated.get("high_confidence_subdomains", []) + \
                   validated.get("medium_confidence_subdomains", []) + \
                   validated.get("low_confidence_subdomains", [])
        
        filtered = [s for s in all_subs if s.get("confidence", 0) >= min_confidence][:limit]
        return {"domain": domain, "total": len(filtered), "subdomains": filtered}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


@router.get("/scan-strategy")
async def get_scan_strategy(
    target: str = Query(..., description="扫描目标"),
):
    """智能分析目标并推荐扫描策略"""
    target_type = detect_target_type(target)
    
    # 尝试获取感知信息
    try:
        perception = await perceive_target(target)
    except Exception:
        perception = None
    
    strategy = optimize_strategy(target_type, perception, target=target)
    
    return {
        "target": target,
        "target_type": target_type,
        "strategy": strategy["name"],
        "label": strategy["label"],
        "description": strategy["description"],
        "phases": prioritize_phases(strategy),
        "nmap_args": strategy["nmap_args"],
        "perception_summary": perception.get("summary", "") if perception else "",
    }
