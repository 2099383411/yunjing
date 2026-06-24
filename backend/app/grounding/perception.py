<<<<<<< HEAD
"""感知层 v2 — 被动信息收集与资产发现
=======
"""感知层 — 被动信息收集与资产发现
>>>>>>> server/master
使用 httpx (已安装) 替代 aiohttp"""
import asyncio
import re
import json
from typing import Optional
from urllib.parse import urlparse, urljoin

import ipaddress

<<<<<<< HEAD
def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


import ipaddress
=======
>>>>>>> server/master

def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

<<<<<<< HEAD
import httpx

# ── CRT.sh 证书透明度日志查询 ────────────────────────────
CRT_SH_TIMEOUT = 10

async def crt_sh_subdomains(domain: str, limit: int = 100) -> list[dict]:
    """通过 CRT.sh 查询子域名（被动，零触碰目标）"""
    url = f"https://crt.sh/?q=%25.{domain}&output=json&excluded=expired"
    try:
        async with httpx.AsyncClient(verify=False, timeout=CRT_SH_TIMEOUT) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code not in (200, 301, 302):
                # CRT.sh 返回 502 时回退到备选方案
                return await _alienvault_subdomains(domain, limit)
            data = resp.json()
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError):
        return await _certspotter_subdomains(domain, limit)
    except Exception:
        return await _certspotter_subdomains(domain, limit)

    seen = set()
    results = []
    for entry in data[:limit]:
        name = entry.get("name_value", "")
        for sub in name.split("\n"):
            sub = sub.strip().lower()
            if sub.endswith(f".{domain}") and sub not in seen and sub != domain:
                seen.add(sub)
                results.append({
                    "subdomain": sub,
                    "issuer": entry.get("issuer_name", "")[:60],
                    "not_after": entry.get("not_after", ""),
                    "source": "crt.sh",
                })
    return results


# ── CertSpotter 子域名查询（备选） ────────────────────
async def _certspotter_subdomains(domain: str, limit: int = 100) -> list[dict]:
    """通过 CertSpotter 证书透明度日志查询子域名（备选，无需 API Key）"""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&after="
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return await _hackertarget_subdomains(domain, limit)
            data = resp.json()
    except Exception:
        return await _hackertarget_subdomains(domain, limit)

    seen = set()
    results = []
    for entry in data[:limit]:
        for name in entry.get("dns_names", []):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(f".{domain}") and name not in seen and name != domain:
                seen.add(name)
                results.append({
                    "subdomain": name,
                    "not_after": entry.get("not_after", "")[:10],
                    "source": "certspotter",
                })
    return results


# ── HackerTarget 子域名查询（最终备选） ────────────────
async def _hackertarget_subdomains(domain: str, limit: int = 100) -> list[dict]:
    """通过 HackerTarget 查询子域名（无需 API Key）"""
    # Using DNS lookup via hackertarget
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code != 200:
                return []
            lines = resp.text.strip().split("\n")
    except Exception:
        return []

    seen = set()
    results = []
    for line in lines[:limit]:
        parts = line.split(",")
        if len(parts) >= 1:
            name = parts[0].strip().lower()
            if name.endswith(f".{domain}") and name not in seen and name != domain:
                seen.add(name)
                ip = parts[1].strip() if len(parts) > 1 else ""
                results.append({
                    "subdomain": name,
                    "ip": ip,
                    "source": "hackertarget",
                })
    return results


# ── 技术栈识别（基于 HTTP 响应头 + 页面特征） ──────────
async def tech_fingerprint(url: str) -> list[dict]:
    """通过 HTTP 响应头和页面内容识别技术栈"""
    techs = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "text/html,*/*"})
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text

            # Server header
            if "server" in headers:
                techs.append({"name": headers["server"], "category": "web_server", "source": "header"})

            # X-Powered-By
            if "x-powered-by" in headers:
                techs.append({"name": headers["x-powered-by"], "category": "framework", "source": "header"})

            # Set-Cookie patterns
            cookies = headers.get("set-cookie", "")
            cookie_techs = {
                "PHPSESSID": "PHP", "JSESSIONID": "Java/JSP",
                "ASP.NET": "ASP.NET", "connect.sid": "Express",
                "laravel_session": "Laravel", "ci_session": "CodeIgniter",
                "symfony": "Symfony", "wordpress_test": "WordPress",
                "wp-": "WordPress", "drupal": "Drupal",
            }
            for ck, tech_name in cookie_techs.items():
                if ck.lower() in cookies.lower():
                    techs.append({"name": tech_name, "category": "cms", "source": "cookie"})

            # HTML meta generator
            gen_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.I)
            if gen_match:
                techs.append({"name": gen_match.group(1), "category": "cms", "source": "meta"})

            # Common CMS paths
            cms_paths = {
                "/wp-content/": "WordPress", "/wp-admin/": "WordPress",
                "/administrator/": "Joomla", "/wp-includes/": "WordPress",
                "/sites/default/": "Drupal",
            }
            for path, cms_name in cms_paths.items():
                if path in body:
                    techs.append({"name": cms_name, "category": "cms", "source": "path"})

            # X-Frame-Options / CSP
            if "x-frame-options" in headers:
                techs.append({"name": f"X-Frame-Options: {headers['x-frame-options']}", "category": "security_header", "source": "header"})
            if "content-security-policy" in headers:
                csp = headers["content-security-policy"][:80]
                techs.append({"name": f"CSP present", "category": "security_header", "source": "header"})

    except httpx.ConnectError:
        pass  # 目标不可达
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for t in techs:
        key = f"{t['name']}|{t['category']}"
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


# ── JS 端点提取 ──────────────────────────────────────────
JS_PATTERNS = [
    r'/api/[^\s"\'<>]+',
    r'/v[0-9]+/[^\s"\'<>]+',
    r'https?://[^\s"\'<>]+\.(?:json|xml|do|action|wsdl)',
    r'["\'](/[^\s"\'<>]{3,}\.(?:php|jsp|aspx|do|action|json|wsdl))',
]

async def js_endpoint_extract(url: str) -> list[dict]:
    """从页面 JS 文件中提取 API 端点和敏感路径"""
    endpoints = []
    js_urls = []

    try:
        async with httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            body = resp.text
            base_url = str(resp.url)

            # Find <script src="...">
            js_matches = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', body, re.I)
            for js_path in js_matches[:10]:
                js_url = urljoin(base_url, js_path)
                js_urls.append(js_url)

            # Inline endpoints in HTML
            all_text = body
            for pattern in JS_PATTERNS:
                for match in re.finditer(pattern, all_text):
                    ep = match.group(1) if match.lastindex else match.group(0)
                    ep = ep.strip('"\'')
                    if len(ep) > 3 and not ep.startswith('//') and ' ' not in ep and not ep.startswith('http'):
                        endpoints.append({
                            "endpoint": ep,
                            "type": "inline_html",
                            "confidence": "medium"
                        })

        # Fetch JS files
        for js_url in js_urls[:5]:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as js_client:
                    js_resp = await js_client.get(js_url, headers={"User-Agent": "Mozilla/5.0"})
                    if js_resp.status_code == 200:
                        js_body = js_resp.text
                        for pattern in JS_PATTERNS:
                            for match in re.finditer(pattern, js_body):
                                ep = match.group(1) if match.lastindex else match.group(0)
                                ep = ep.strip('"\'')
                                if len(ep) > 3 and not ep.startswith('//') and ' ' not in ep:
                                    endpoints.append({
                                        "endpoint": ep,
                                        "source_url": js_url,
                                        "type": "js_file",
                                        "confidence": "high"
                                    })
            except Exception:
                continue

    except (httpx.ConnectError, httpx.TimeoutException):
        pass
    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for ep in endpoints:
        if ep["endpoint"] not in seen:
            seen.add(ep["endpoint"])
            unique.append(ep)
    return unique


# ── 综合感知分析 ─────────────────────────────────────────
async def perceive_target(target: str) -> dict:
    # Short-circuit for private/internal IPs
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    if _is_private_ip(host):
        return {
            "target": target,
            "type": "private_ip",
            "technologies": [],
            "subdomains": [],
            "note": "Private/internal IP - skipping external passive recon"
        }
    # Short-circuit for private/internal IPs
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    if _is_private_ip(host):
        return {
            "target": target,
            "type": "private_ip",
            "technologies": [],
            "subdomains": [],
            "note": "Private/internal IP - skipping external passive recon"
        }
    """对目标执行完整的感知分析（零触碰）"""
    # 解析域名
    domain = None
    if target.startswith("http"):
        parsed = urlparse(target)
        domain = parsed.netloc.split(":")[0]
    elif "." in target and not target.startswith("http") and " " not in target:
        domain = target

    result = {
        "target": target,
        "domain": domain,
        "subdomains": [],
        "technologies": [],
        "endpoints": [],
        "summary": ""
    }

    # 确定目标 URL
    url = target if target.startswith("http") else f"https://{target}"

    # 并发执行感知任务
    tasks = [tech_fingerprint(url), js_endpoint_extract(url)]
    if domain:
        tasks.insert(0, crt_sh_subdomains(domain))

    completed = await asyncio.gather(*tasks, return_exceptions=True)

    idx = 0
    if domain:
        result["subdomains"] = completed[0] if not isinstance(completed[0], Exception) else []
        idx = 1

    result["technologies"] = completed[idx] if not isinstance(completed[idx], Exception) else []
    result["endpoints"] = completed[idx + 1] if not isinstance(completed[idx + 1], Exception) else []

    # Build summary
    parts = []
    if result["subdomains"]:
        parts.append(f"发现 {len(result['subdomains'])} 个子域名")
    if result["technologies"]:
        parts.append(f"识别 {len(result['technologies'])} 项技术")
    if result["endpoints"]:
        parts.append(f"提取 {len(result['endpoints'])} 个端点")
    result["summary"] = "，".join(parts) if parts else "未获取到有用的感知信息（目标可能不可达或无有用信源）"

    return result
=======

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
>>>>>>> server/master
