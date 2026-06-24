"""目标解析模块 — 从自然语言中提取渗透测试目标
对话层核心组件：理解用户意图并提取 IP/域名/URL/目标描述"""
import re
from typing import Optional, TypedDict

class ParsedTarget(TypedDict, total=False):
    target: str          # 提取的目标值
    target_type: str     # ip/domain/url/network/unknown
    description: str     # 原始描述
    confidence: float    # 置信度 0~1


IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
CIDR_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)/(?:[12]\d|3[0-2]|[1-9])\b'
)
DOMAIN_PATTERN = re.compile(
    r'(?<![a-zA-Z0-9-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9-])'
)
URL_PATTERN = re.compile(
    r'https?://[^\s/$.?#].[^\s]*'
)

# 触发词：表明用户要扫描/测试某个目标
TRIGGER_PHRASES = [
    r'扫[描一].*?(?:下|一下|这个|那个|一下这个)',
    r'测[试试].*?(?:下|一下|这个|那个|一下这个)',
    r'检测.*?(?:下|一下|这个|那个)',
    r'看看.*?(?:这个|那个|下|一下)',
    r'帮我.*?(?:看[看看]|检[检测测查]|扫[描描]|测[试试])',
    r'对[ ].*?(?:进行|执行|做)',
    r'target[ :：,，]*',
    r'目标[ ：,:，]*',
]


def extract_target(text: str) -> Optional[ParsedTarget]:
    """从自然语言中提取渗透测试目标"""
    text = text.strip()
    if not text:
        return None

    # 1. 直接命中 URL
    url_match = URL_PATTERN.findall(text)
    if url_match:
        url = url_match[0].rstrip('/.,;:!?)"\' ')
        return ParsedTarget(
            target=url,
            target_type="url",
            description=text,
            confidence=0.95
        )

    # 2. 直接命中 CIDR
    cidr_match = CIDR_PATTERN.findall(text)
    if cidr_match:
        return ParsedTarget(
            target=cidr_match[0],
            target_type="network",
            description=text,
            confidence=0.95
        )

    # 3. 直接命中 IP
    ip_match = IP_PATTERN.findall(text)
    if ip_match:
        return ParsedTarget(
            target=ip_match[0],
            target_type="ip",
            description=text,
            confidence=0.9
        )

    # 4. 直接命中域名
    domain_match = DOMAIN_PATTERN.findall(text)
    if domain_match:
        domain = domain_match[0].lower().lstrip('.')
        return ParsedTarget(
            target=domain,
            target_type="domain",
            description=text,
            confidence=0.85
        )

    # 5. 触发词+上下文提取
    for phrase in TRIGGER_PHRASES:
        match = re.search(phrase, text, re.IGNORECASE)
        if match:
            # 提取触发词后面的内容
            after = text[match.end():].strip().lstrip(':：,， ')
            if not after:
                before = text[:match.start()].strip().rstrip(':：,， ')
                if before:
                    after = before
            if after:
                # 递归解析后面的内容
                sub = extract_target(after)
                if sub:
                    sub["confidence"] = max(sub["confidence"] - 0.1, 0.5)
                    return sub
            return ParsedTarget(
                target=text,
                target_type="unknown",
                description=text,
                confidence=0.4
            )

    # 6. 常见的渗透测试意图
    intent_keywords = ["scan", "test", "audit", "pentest", "渗透",
                       "扫描", "检测", "测试", "评估", "安全"]
    if any(kw in text.lower() for kw in intent_keywords):
        # 可能是目标描述，置信度较低
        return ParsedTarget(
            target=text[:120],
            target_type="unknown",
            description=text,
            confidence=0.3
        )

    return None


def format_target_summary(pt: ParsedTarget) -> str:
    """格式化目标摘要信息"""
    type_labels = {
        "ip": "IP 地址",
        "domain": "域名",
        "url": "URL",
        "network": "网段",
        "unknown": "目标描述",
    }
    label = type_labels.get(pt["target_type"], pt["target_type"])
    return f"[{label}] {pt['target']} (置信度: {pt['confidence']:.0%})"
