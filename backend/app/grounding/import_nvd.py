"""NVD CVE 数据导入脚本 (支持 API 2.0 + 旧格式)
从 NVD JSON 文件导入到本地 CVE 数据库

支持两种格式:
1. NVD API 2.0 格式 (vulnerabilities 数组)
2. 旧 NVD Feed 格式 (CVE_Items 数组)

用法:
    python -m app.grounding.import_nvd /path/to/nvdcve-1.1-2025.json
    python -m app.grounding.import_nvd /data/nvd/  # 批量导入目录下所有json
"""
import json, os, sys, uuid
from datetime import datetime
from sqlalchemy import create_engine, text

from app.config import settings


def parse_cvss(data: dict) -> tuple:
    """从 CVSS 数据中提取评分和向量（兼容 API 2.0 和旧格式）"""
    # API 2.0 格式
    metrics = data.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        cvss_list = metrics.get(key, [])
        if cvss_list:
            cvss_data = cvss_list[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = _map_severity(score)
            vector = cvss_data.get("vectorString", "")
            return score, severity, vector

    # 旧 feed 格式
    impact = data.get("impact", {})
    for key in ["baseMetricV3", "baseMetricV2"]:
        bm = impact.get(key, {})
        cvss = bm.get("cvssV3") or bm.get("cvssV2") or {}
        score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity") or _map_severity(score)
        vector = cvss.get("vectorString", "")
        if score is not None:
            return score, severity, vector

    return None, None, None


def _map_severity(score: float) -> str:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score >= 0.1:
        return "LOW"
    return "NONE"


def parse_descriptions(cve_data: dict) -> str:
    """提取 CVE 描述（兼容两种格式）"""
    descriptions = cve_data.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") in ["en", "zh"]:
            return d.get("value", "")
    # 旧格式
    desc_data = cve_data.get("description", {}).get("description_data", [])
    for d in desc_data:
        if d.get("lang") in ["en", "zh"]:
            return d.get("value", "")
    return ""


def parse_affected_products(cve_data: dict) -> list:
    """提取受影响的产品版本列表"""
    products = []
    # API 2.0 格式
    for node in cve_data.get("configurations", []):
        for match in node.get("criteria", []):
            criteria = match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) >= 5:
                version = parts[4]
                if version and version not in ("*", "-"):
                    products.append({
                        "product": parts[3] if len(parts) > 3 else "",
                        "vendor": parts[2] if len(parts) > 2 else "",
                        "version": version,
                    })
        for match in node.get("nodes", []):
            for cpe in match.get("cpe_match", []):
                criteria = cpe.get("criteria", "")
                parts = criteria.split(":")
                if len(parts) >= 5:
                    version = parts[4]
                    if version and version not in ("*", "-"):
                        products.append({
                            "product": parts[3] if len(parts) > 3 else "",
                            "vendor": parts[2] if len(parts) > 2 else "",
                            "version": version,
                        })
    return products


def parse_vuln_type(description: str) -> str:
    """从描述中猜测漏洞类型"""
    if not description:
        return None
    desc_lower = description.lower()
    mappings = {
        "rce": ["remote code execution", "arbitrary code", "execute arbitrary"],
        "sql_injection": ["sql injection", "sqli"],
        "xss": ["cross-site scripting", "xss"],
        "path_traversal": ["path traversal", "directory traversal"],
        "csrf": ["cross-site request forgery", "csrf"],
        "ssrf": ["server-side request forgery", "ssrf"],
        "privilege_escalation": ["privilege escalation", "escalation of privilege"],
        "information_disclosure": ["information disclosure", "information leak"],
        "denial_of_service": ["denial of service", "dos", "denial-of-service"],
        "buffer_overflow": ["buffer overflow", "buffer over-read"],
        "command_injection": ["command injection", "os command"],
        "deserialization": ["deserialization", "deserialize"],
        "bypass": ["security bypass", "protection bypass", "authentication bypass"],
    }
    for vtype, keywords in mappings.items():
        if any(kw in desc_lower for kw in keywords):
            return vtype
    return None


def extract_cve_items(data: dict) -> list:
    """提取 CVE 条目列表（兼容两种格式）"""
    # API 2.0 格式
    vulns = data.get("vulnerabilities", [])
    if vulns:
        return vulns
    # 旧 feed 格式
    return data.get("CVE_Items", [])


def import_file(filepath: str, engine) -> int:
    """导入单个 NVD JSON 文件"""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = extract_cve_items(data)
    print(f"  解析到 {len(items)} 条 CVE 条目")
    count = 0

    for item in items:
        # API 2.0 格式: {"cve": {...}}
        # 旧格式: {"cve": {...}, "impact": {...}}
        cve_obj = item.get("cve", item) if isinstance(item, dict) else item
        cve_data = cve_obj.get("cve", cve_obj)
        if isinstance(cve_data, dict):
            cve_id = cve_data.get("id", "") or cve_data.get("CVE_data_meta", {}).get("ID", "")
        else:
            continue

        if not cve_id:
            continue

        description = parse_descriptions(cve_data)
        cvss_score, severity, cvss_vector = parse_cvss(cve_obj if "metrics" in cve_obj else item)
        affected_versions = parse_affected_products(cve_data)
        vuln_type = parse_vuln_type(description)

        try:
            with engine.begin() as conn:
                conn.execute(
                    text("""
                    INSERT INTO cve_database (id, cve_id, description, cvss_score,
                        cvss_vector, severity, affected_versions, vuln_type, source, last_updated, created_at)
                    VALUES (:id, :cve_id, :description, :cvss_score,
                        :cvss_vector, :severity, :affected_versions, :vuln_type, :source, NOW(), NOW())
                    ON CONFLICT (cve_id) DO UPDATE SET
                        cvss_score = EXCLUDED.cvss_score,
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        last_updated = NOW()
                    """),
                    {
                        "id": str(uuid.uuid4()),
                        "cve_id": cve_id,
                        "description": description[:2000] if description else None,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "severity": severity,
                        "affected_versions": json.dumps(affected_versions, ensure_ascii=False),
                        "vuln_type": vuln_type,
                        "source": "NVD",
                    }
                )
            count += 1
        except Exception as e:
            print(f"  导入 {cve_id} 失败: {e}")
            continue

        if count % 500 == 0:
            print(f"  已导入 {count} 条...")

    return count


def main():
    if len(sys.argv) < 2:
        print("用法: python -m app.grounding.import_nvd <json_file_or_dir>")
        sys.exit(1)

    path = sys.argv[1]

    # 同步引擎
    db_url = settings.DATABASE_URL.replace("+asyncpg", "+psycopg2")
    engine = create_engine(db_url)

    total = 0
    if os.path.isfile(path):
        print(f"导入文件: {path}")
        count = import_file(path, engine)
        print(f"  {path}: {count} 条")
        total += count
    elif os.path.isdir(path):
        for fname in sorted(os.listdir(path)):
            if fname.endswith(".json") and ("nvdcve" in fname or "recent" in fname):
                fpath = os.path.join(path, fname)
                print(f"导入: {fpath}")
                count = import_file(fpath, engine)
                print(f"  {fpath}: {count} 条")
                total += count

    print(f"\n总计导入 {total} 条 CVE 记录")


if __name__ == "__main__":
    main()
