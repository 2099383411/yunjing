"""多信源交叉验证 + 置信度评分引擎
感知层核心：融合多源情报，去噪，打分"""
import hashlib
from datetime import datetime
from typing import Optional

# ── 信源权重 ─────────────────────────────────────────────
SOURCE_WEIGHTS = {
    # 子域名信源
    "certspotter": 0.85,    # 证书日志，精准
    "crt.sh": 0.82,         # 证书日志，历史数据丰富
    "hackertarget": 0.60,   # DNS 枚举，噪声较多
    "alienvault": 0.65,     # OTX 数据，中等可信
    # 技术栈信源
    "header": 0.90,         # HTTP 响应头，高可信
    "cookie": 0.85,         # Cookie 值，高可信
    "meta": 0.70,           # HTML meta，可伪造
    "path": 0.60,           # URL 路径，可伪造
    # 端点信源
    "js_file": 0.75,        # JS 文件提取
    "inline_html": 0.50,    # HTML 内联，噪声大
}

# ── 已知 CDN/WAF/反向代理 IP 范围 ────────────────────────
CDN_RANGES = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula",
    "sucuri", "stackpath", "azure", "cdn-", "bws", "gws",
]


def compute_fingerprint(item: dict, item_type: str) -> str:
    """为资产项生成唯一指纹"""
    if item_type == "subdomain":
        return hashlib.md5(item.get("subdomain", "").encode()).hexdigest()[:12]
    elif item_type == "technology":
        return hashlib.md5(f"{item.get('name','')}|{item.get('category','')}".encode()).hexdigest()[:12]
    elif item_type == "endpoint":
        return hashlib.md5(item.get("endpoint", "").encode()).hexdigest()[:12]
    return hashlib.md5(str(item).encode()).hexdigest()[:12]


def score_subdomain(sub: dict, all_subs: list[dict], domain: str) -> float:
    """计算单个子域名的置信度"""
    base = SOURCE_WEIGHTS.get(sub.get("source", ""), 0.5)
    
    # 加分项
    score = base
    
    # 有 IP 地址 → 更可信
    if sub.get("ip"):
        score += 0.1
    
    # 多信源命中 → 加分
    name = sub.get("subdomain", "")
    other_sources = set()
    for s in all_subs:
        if s.get("subdomain") == name and s.get("source") != sub.get("source"):
            other_sources.add(s.get("source"))
    if len(other_sources) >= 2:
        score += 0.15
    elif len(other_sources) >= 1:
        score += 0.08
    
    # 常见模式加分
    common_prefixes = ["www", "mail", "api", "admin", "dev", "test", "vpn", "blog"]
    sub_name = name.replace(f".{domain}", "")
    if any(sub_name.startswith(p) for p in common_prefixes):
        score += 0.03
    
    return min(score, 1.0)


def score_tech(tech: dict, all_techs: list[dict]) -> float:
    """计算技术栈项的置信度"""
    base = SOURCE_WEIGHTS.get(tech.get("source", ""), 0.5)
    
    # CDN/WAF 类标记
    name = tech.get("name", "").lower()
    category = tech.get("category", "")
    
    # 安全头 → 不是漏洞，但可参考
    if category == "security_header":
        return 0.7
    
    # CDN/WAF 标记
    if any(cdn in name for cdn in CDN_RANGES):
        return 0.9
    
    return min(base + 0.1, 1.0)


def score_endpoint(ep: dict, all_eps: list[dict]) -> float:
    """计算 API 端点的置信度"""
    base = SOURCE_WEIGHTS.get(ep.get("type", ""), 0.5)
    
    # 多源命中
    name = ep.get("endpoint", "")
    other_types = set()
    for e in all_eps:
        if e.get("endpoint") == name and e.get("type") != ep.get("type"):
            other_types.add(e.get("type"))
    if other_types:
        base += 0.15
    
    # 路径深度加分
    depth = name.count("/")
    if depth >= 3:
        base += 0.05  # 深层路径更可能是真实 API
    
    return min(base, 1.0)


def cross_validate(perception_result: dict) -> dict:
    """对感知结果进行交叉验证和置信度评分"""
    domain = perception_result.get("domain", "")
    
    # 1. 子域名去重 + 评分
    sub_map = {}
    for sub in perception_result.get("subdomains", []):
        fp = compute_fingerprint(sub, "subdomain")
        if fp not in sub_map:
            sub_map[fp] = sub
            sub_map[fp]["confidence"] = 0.0
            sub_map[fp]["fingerprint"] = fp
            sub_map[fp]["sources"] = [sub.get("source", "unknown")]
        else:
            if sub.get("source") not in sub_map[fp]["sources"]:
                sub_map[fp]["sources"].append(sub.get("source"))
    
    all_subs = list(sub_map.values())
    for sub in all_subs:
        sub["confidence"] = round(score_subdomain(sub, all_subs, domain or ""), 2)
    
    # 按置信度降序
    all_subs.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    
    # 2. 技术栈去重 + 评分
    tech_map = {}
    for tech in perception_result.get("technologies", []):
        fp = compute_fingerprint(tech, "technology")
        if fp not in tech_map:
            tech_map[fp] = tech
            tech_map[fp]["confidence"] = 0.0
            tech_map[fp]["fingerprint"] = fp
    all_techs = list(tech_map.values())
    for tech in all_techs:
        tech["confidence"] = round(score_tech(tech, all_techs), 2)
    all_techs.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    
    # 3. 端点去重 + 评分
    ep_map = {}
    for ep in perception_result.get("endpoints", []):
        fp = compute_fingerprint(ep, "endpoint")
        if fp not in ep_map:
            ep_map[fp] = ep
            ep_map[fp]["confidence"] = 0.0
            ep_map[fp]["fingerprint"] = fp
    all_eps = list(ep_map.values())
    for ep in all_eps:
        ep["confidence"] = round(score_endpoint(ep, all_eps), 2)
    all_eps.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    
    # 4. 资产画像摘要
    high_conf_subs = [s for s in all_subs if s.get("confidence", 0) >= 0.7]
    med_conf_subs = [s for s in all_subs if 0.4 <= s.get("confidence", 0) < 0.7]
    
    high_conf_techs = [t for t in all_techs if t.get("confidence", 0) >= 0.7]
    high_conf_eps = [e for e in all_eps if e.get("confidence", 0) >= 0.7]
    
    return {
        "asset_type": "domain" if domain else "unknown",
        "domain": domain,
        "total_subdomains": len(all_subs),
        "high_confidence_subdomains": high_conf_subs,
        "medium_confidence_subdomains": med_conf_subs,
        "low_confidence_subdomains": [s for s in all_subs if s.get("confidence", 0) < 0.4],
        "total_technologies": len(all_techs),
        "technologies": all_techs,
        "high_confidence_technologies": high_conf_techs,
        "total_endpoints": len(all_eps),
        "high_confidence_endpoints": high_conf_eps,
        "all_endpoints": all_eps,
        "profile_summary": _build_profile_summary(domain, all_subs, all_techs, all_eps),
    }


def _build_profile_summary(domain: str, subs: list, techs: list, eps: list) -> str:
    """生成资产画像摘要"""
    parts = []
    
    high_subs = [s for s in subs if s.get("confidence", 0) >= 0.7]
    high_techs = [t for t in techs if t.get("confidence", 0) >= 0.7]
    
    if high_subs:
        sub_names = [s["subdomain"] for s in high_subs[:5]]
        parts.append(f"高置信子域名({len(high_subs)}个): {', '.join(sub_names)}")
    
    if high_techs:
        tech_names = [f"{t['name']}({t['category']})" for t in high_techs[:5]]
        parts.append(f"技术栈: {', '.join(tech_names)}")
    
    if high_techs:
        web_servers = [t for t in high_techs if t.get("category") == "web_server"]
        if web_servers:
            parts.append(f"Web服务器: {web_servers[0]['name']}")
    
    return " | ".join(parts) if parts else "基础信息不足，无法生成完整画像"
