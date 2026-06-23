"""CVE 数据库服务：查询 + 版本匹配 + 校验"""
import re, json, uuid
from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from packaging.version import Version, InvalidVersion
from app.models.cve_entry import CveEntry, CveVerificationResult


class CveLookupResult:
    """CVE 查询结果"""
    def __init__(self, cve_id: str = "", affected: bool = False,
                 confidence: float = 0.0, cvss: float = 0.0,
                 poc_available: bool = False, poc_command: str = "",
                 notes: str = "", vuln_type: str = ""):
        self.cve_id = cve_id
        self.affected = affected
        self.confidence = confidence
        self.cvss = cvss
        self.poc_available = poc_available
        self.poc_command = poc_command
        self.notes = notes
        self.vuln_type = vuln_type

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "affected": self.affected,
            "confidence": self.confidence,
            "cvss": self.cvss,
            "poc_available": self.poc_available,
            "poc_command": self.poc_command,
            "notes": self.notes,
            "vuln_type": self.vuln_type,
        }


def _parse_version(ver: str) -> Optional[Version]:
    """安全解析版本号"""
    ver = ver.strip().lstrip("vV")
    try:
        return Version(ver)
    except InvalidVersion:
        return None


def _version_in_range(version_str: str, affected_versions: list) -> bool:
    """判断版本是否在受影响范围内"
    支持格式: "2.4.49", "<= 2.4.49", "< 2.4.50, >= 2.4.0"
    """
    ver = _parse_version(version_str)
    if not ver:
        return False

    for entry in affected_versions:
        if isinstance(entry, str):
            # 精确匹配
            if entry == version_str:
                return True
        elif isinstance(entry, dict):
            expr = entry.get("version", "")
            if not expr:
                continue
            # 简单范围匹配: "<= 2.4.49" 或 "< 2.4.50, >= 2.4.0"
            parts = [p.strip() for p in expr.split(",")]
            match = True
            for part in parts:
                m = re.match(r"([<>=!]+)\s*(.+)", part)
                if not m:
                    continue
                op, target_ver_str = m.group(1), m.group(2)
                target_ver = _parse_version(target_ver_str)
                if not target_ver:
                    match = False
                    break
                if op == "<=" and not (ver <= target_ver):
                    match = False
                elif op == "<" and not (ver < target_ver):
                    match = False
                elif op == ">=" and not (ver >= target_ver):
                    match = False
                elif op == ">" and not (ver > target_ver):
                    match = False
                elif op == "==" and not (ver == target_ver):
                    match = False
                elif op == "!=" and not (ver != target_ver):
                    match = False
            if match:
                return True
    return False


async def lookup_cve(db: AsyncSession, cve_id: str) -> Optional[CveEntry]:
    """按 CVE ID 查询"""
    result = await db.execute(select(CveEntry).where(CveEntry.cve_id == cve_id))
    return result.scalar_one_or_none()


async def find_cves_for_product(db: AsyncSession, product: str, version: str) -> list[CveEntry]:
    """查找影响某产品特定版本的所有 CVE"""
    all_entries = await db.execute(
        select(CveEntry).where(CveEntry.affected_versions.isnot(None))
    )
    matching = []
    for entry in all_entries.scalars().all():
        affected = entry.affected_versions or []
        for av in affected:
            if isinstance(av, dict):
                prod = av.get("product", "")
                if product.lower() in prod.lower():
                    if _version_in_range(version, [av]):
                        matching.append(entry)
                        break
            elif isinstance(av, str):
                if product.lower() in av.lower():
                    if _version_in_range(version, [av]):
                        matching.append(entry)
                        break
    return matching


async def verify_cve(db: AsyncSession, cve_id: str,
                     product: str, version: str) -> CveLookupResult:
    """校验指定 CVE 是否影响当前产品的版本"""
    # 查缓存
    cached = await db.execute(
        select(CveVerificationResult).where(and_(
            CveVerificationResult.cve_id == cve_id,
            CveVerificationResult.product == product,
            CveVerificationResult.version == version,
        ))
    )
    cached_result = cached.scalar_one_or_none()
    if cached_result:
        return CveLookupResult(
            cve_id=cve_id,
            affected=cached_result.is_affected,
            confidence=cached_result.confidence,
            notes=cached_result.notes or "",
        )

    # 查 CVE 库
    entry = await lookup_cve(db, cve_id)
    if not entry:
        return CveLookupResult(
            cve_id=cve_id,
            affected=False,
            confidence=0.1,
            notes="CVE 不在本地数据库中，可能已过期或未被收录",
        )

    is_affected = _version_in_range(version, entry.affected_versions or [])
    confidence = 0.8 if is_affected else 0.7
    if entry.poc_available:
        confidence = min(confidence + 0.15, 1.0)

    # Pass cvss score from DB entry
    cvss_score = entry.cvss_score or 0.0

    # 写入缓存
    cache_entry = CveVerificationResult(
        id=str(uuid.uuid4()),
        cve_id=cve_id, product=product, version=version,
        is_affected=is_affected, confidence=confidence,
        notes=entry.notes,
    )
    db.add(cache_entry)
    await db.commit()

    return CveLookupResult(
        cve_id=cve_id,
        affected=is_affected,
        confidence=confidence,
        cvss=entry.cvss_score or 0.0,
        poc_available=entry.poc_available or False,
        poc_command=entry.poc_command or "",
        notes=entry.notes or "",
        vuln_type=entry.vuln_type or "",
    )


async def batch_verify(db: AsyncSession,
                       cve_list: list[dict]) -> list[dict]:
    """批量校验：输入 [{"cve_id":"...", "product":"...", "version":"..."}]
    返回带校验结果的列表"""
    results = []
    for item in cve_list:
        result = await verify_cve(
            db, item["cve_id"], item.get("product", ""), item.get("version", "")
        )
        results.append(result.to_dict())
    return results
