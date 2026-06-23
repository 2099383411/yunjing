"""智能扫描策略引擎
根据目标类型和感知结果，自动选择最优扫描策略"""
import re
from typing import Optional

# ── 扫描策略定义 ─────────────────────────────────────────
SCAN_STRATEGIES = {
    "full": {
        "label": "全面渗透",
        "phases": ["asset_discovery", "port_scan", "vuln_scan", "web_scan", "exploitation"],
        "nmap_args": "-sS -sV -O -p- -T4",
        "description": "全端口扫描+服务识别+OS检测+漏洞扫描+利用验证",
    },
    "quick": {
        "label": "快速侦察",
        "phases": ["asset_discovery", "port_scan"],
        "nmap_args": "-sS -sV -p 1-10000 -T4",
        "description": "前10000端口快速扫描+服务识别",
    },
    "web": {
        "label": "Web 专项",
        "phases": ["web_fingerprint", "web_scan", "dir_scan"],
        "nmap_args": "-sS -sV -p 80,443,8080,8443 -T4",
        "description": "Web端口专项扫描+指纹识别+Nikto+目录扫描",
    },
    "api": {
        "label": "API 专项",
        "phases": ["web_fingerprint", "web_scan"],
        "nmap_args": "-sS -sV -p 80,443,3000,5000,8000,8080,8443,9000 -T4",
        "description": "API常见端口扫描+Web扫描",
    },
    "internal": {
        "label": "内网渗透",
        "phases": ["asset_discovery", "port_scan", "vuln_scan", "exploitation", "post_exploit"],
        "nmap_args": "-sS -sV -O -p- -T3",
        "description": "全端口+OS检测+漏洞扫描+利用+后渗透",
    },
    "stealth": {
        "label": "隐蔽扫描",
        "phases": ["asset_discovery", "port_scan"],
        "nmap_args": "-sS -sV -p 1-1000 -T2 --max-retries=1",
        "description": "低速隐蔽扫描（前1000端口，适合有WAF环境）",
    },
    "ad": {
        "label": "AD 域控测试",
        "phases": ["port_scan", "vuln_scan", "exploitation"],
        "nmap_args": "-sS -sV -p 53,88,135,139,389,445,636,3268,3269,3389 -T4",
        "description": "AD域常见端口扫描+漏洞利用",
    },
}


# ── 目标类型推断 ─────────────────────────────────────────
def detect_target_type(target: str) -> str:
    """推断目标类型"""
    # IP 地址
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        return "ip"
    # CIDR 网段
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', target):
        return "network"
    # URL
    if target.startswith("http"):
        return "url"
    # 域名
    if "." in target and " " not in target:
        return "domain"
    return "unknown"


# ── 感知洞察 → 策略优化 ─────────────────────────────────
def optimize_strategy(target_type: str, perception: dict | None = None, target: str = "") -> dict:
    """根据目标类型 + 感知结果，选择并定制扫描策略"""
    # 默认策略
    if target_type == "network":
        base_strategy = "internal"
    elif target_type == "url":
        base_strategy = "web"
    elif target_type == "ip":
        base_strategy = "full"
    else:
        base_strategy = "full"
    
    strategy = dict(SCAN_STRATEGIES.get(base_strategy, SCAN_STRATEGIES["full"]))
    strategy["name"] = base_strategy
    strategy["target_type"] = target_type
    
    # 如果有感知结果，进一步优化
    if perception:
        techs = perception.get("technologies", [])
        subdomains = perception.get("subdomains", [])
        
        # 检测到 Web 服务器 → 增加 Web 扫描阶段
        has_web_server = any(
            t.get("category") in ("web_server", "cms") 
            for t in techs
        )
        if has_web_server:
            if "web_fingerprint" not in strategy.get("phases", []):
                strategy["phases"].insert(1, "web_fingerprint")
            if "web_scan" not in strategy.get("phases", []):
                strategy["phases"].append("web_scan")
            strategy["description"] += " (Web优化)"
        
        # 检测到子域名 → 增加 OSINT 情报收集
        if subdomains and "osint_gather" not in strategy.get("phases", []):
            strategy["phases"].insert(0, "osint_gather")
            strategy["description"] += " (多域名)"
        
        # 内网 IP → 内网策略
        if target_type == "ip":
            first_octet = target.split(".")[0] if target else "0"
            if first_octet in ("10", "172", "192"):
                strategy = dict(SCAN_STRATEGIES["internal"])
                strategy["name"] = "internal"
    
    return strategy


# ── 策略排序 ─────────────────────────────────────────────
def prioritize_phases(strategy: dict) -> list[str]:
    """对阶段进行优先级排序"""
    priority_order = [
        "osint_gather",
        "asset_discovery",
        "port_scan",
        "web_fingerprint",
        "service_detect",
        "vuln_scan",
        "web_scan",
        "dir_scan",
        "exploitation",
        "post_exploit",
    ]
    
    phases = strategy.get("phases", [])
    return sorted(phases, key=lambda p: priority_order.index(p) if p in priority_order else 999)


def analyze_ports(port_data: list[dict]) -> dict:
    """分析端口扫描结果，给出攻击面建议"""
    result = {
        "total_open": 0,
        "web_ports": [],
        "db_ports": [],
        "admin_ports": [],
        "vpn_ports": [],
        "services": [],
        "attack_surface": "low",
    }
    
    web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 9443}
    db_ports = {3306, 5432, 5433, 6379, 27017, 9200, 5601, 8444}
    admin_ports = {22, 3389, 5900, 5901, 23, 21, 1433, 1521}
    vpn_ports = {1194, 51820, 1723, 500, 4500}
    
    for p in port_data:
        port_num = p.get("port", 0)
        service = p.get("service", "")
        result["total_open"] += 1
        result["services"].append(f"{port_num}/{service}" if service else str(port_num))
        
        if port_num in web_ports:
            result["web_ports"].append(port_num)
        if port_num in db_ports:
            result["db_ports"].append(port_num)
        if port_num in admin_ports:
            result["admin_ports"].append(port_num)
        if port_num in vpn_ports:
            result["vpn_ports"].append(port_num)
    
    # 攻击面评估
    risk_score = 0
    if result["db_ports"]:
        risk_score += 2
    if result["admin_ports"]:
        risk_score += 2
    if result["web_ports"]:
        risk_score += 1
    if result["vpn_ports"]:
        risk_score += 1
    if result["total_open"] > 10:
        risk_score += 1
    
    if risk_score >= 4:
        result["attack_surface"] = "high"
    elif risk_score >= 2:
        result["attack_surface"] = "medium"
    
    return result
