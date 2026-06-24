"""接地层 REST API — CVE 查询 + 校验 + 批量验证"""
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.grounding.cve_database import (
    lookup_cve, find_cves_for_product, verify_cve, batch_verify,
)

router = APIRouter(prefix="/api/grounding", tags=["grounding"])


# 注意: 静态路径必须在动态路径 {cve_id} 之前定义！
@router.get("/cve/by-product")
async def get_cves_for_product(
    product: str = Query(..., description="产品名, 如 Apache"),
    version: str = Query(..., description="版本号, 如 2.4.49"),
    db: AsyncSession = Depends(get_db),
):
    """查询影响某产品特定版本的所有 CVE"""
    entries = await find_cves_for_product(db, product, version)
    return {
        "product": product,
        "version": version,
        "total": len(entries),
        "cves": [
            {
                "cve_id": e.cve_id,
                "cvss_score": e.cvss_score,
                "severity": e.severity,
                "vuln_type": e.vuln_type,
                "poc_available": e.poc_available,
                "notes": e.notes,
            }
            for e in entries
        ],
    }


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    """查询单个 CVE 详情"""
    entry = await lookup_cve(db, cve_id.upper())
    if not entry:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} 未在本地数据库")
    return {
        "cve_id": entry.cve_id,
        "description": entry.description,
        "cvss_score": entry.cvss_score,
        "severity": entry.severity,
        "affected_versions": entry.affected_versions,
        "fixed_in_versions": entry.fixed_in_versions,
        "vuln_type": entry.vuln_type,
        "poc_available": entry.poc_available,
        "poc_command": entry.poc_command,
        "notes": entry.notes,
        "references": entry.references,
        "source": entry.source,
        "coverage_note": entry.coverage_note,
    }


@router.get("/verify")
async def verify_single(
    cve_id: str = Query(...),
    product: str = Query(""),
    version: str = Query(""),
    db: AsyncSession = Depends(get_db),
):
    """校验 CVE 是否影响指定版本"""
    result = await verify_cve(db, cve_id.upper(), product, version)
    return result.to_dict()


@router.post("/verify/batch")
async def verify_batch(
    items: list[dict],
    db: AsyncSession = Depends(get_db),
):
    """批量校验 CVE"""
    results = await batch_verify(db, items)
    return {"total": len(results), "results": results}
