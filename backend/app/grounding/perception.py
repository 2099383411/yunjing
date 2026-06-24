"""感知层 — 被动信息收集与资产发现
使用 httpx (已安装) 替代 aiohttp"""
import asyncio
import re
import json
from typing import Optional
from urllib.parse import urlparse, urljoin

import ipaddress


def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


async def perceive_target(target: str) -> dict:
    """对目标执行被动信息收集与资产发现
    
    Args:
        target: 目标 IP、域名或 URL
        
    Returns:
        包含 technologies、subdomains、domain 等信息的字典
    """
    result = {
        "target": target,
        "domain": "",
        "technologies": [],
        "subdomains": [],
        "open_ports": [],
        "web_services": [],
        "error": None,
    }
    
    try:
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path or target
        domain = domain.split(":")[0].strip()
        result["domain"] = domain
        
        # 使用 smart_scanner 的 detect_target_type
        from app.grounding.smart_scanner import detect_target_type
        target_type = detect_target_type(target)
        result["target_type"] = target_type
        
        # 如果是 IP，检测是否为内网
        if _is_private_ip(domain):
            result["is_private"] = True
        
        return result
    except Exception as e:
        result["error"] = str(e)
        return result
