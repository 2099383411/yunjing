"""云镜推理引擎 — 知识库接口

从本地知识库文档提取攻击面规则，为假设生成器提供种子数据。
当前实现：14 种攻击模式的硬编码规则 + 动态加载接口。
"""
from __future__ import annotations
import os
import json
import glob
import logging
from typing import Optional

from .models import AttackHypothesis, HypothesisStatus

logger = logging.getLogger(__name__)


class AttackPatternRule:
    """攻击模式种子规则"""
    
    def __init__(self, name: str, pattern_id: str, principle: str,
                 surface_path: str, port_triggers: list[int],
                 service_triggers: list[str], env_hints: list[str],
                 base_confidence: float, impact: str, effort: str,
                 verification_method: str):
        self.name = name
        self.pattern_id = pattern_id
        self.principle = principle
        self.surface_path = surface_path
        self.port_triggers = port_triggers
        self.service_triggers = service_triggers
        self.env_hints = env_hints
        self.base_confidence = base_confidence
        self.impact = impact
        self.effort = effort
        self.verification_method = verification_method


class KnowledgeBaseEngine:
    """知识库引擎 — 管理攻击模式种子与动态加载"""

    # ============================================================
    # 14 种通用攻击模式种子
    # ============================================================
    SEED_PATTERNS: dict[str, AttackPatternRule] = {}

    @classmethod
    def initialize(cls):
        """初始化攻击模式种子库"""
        patterns = [
            AttackPatternRule(
                name="Web 注入与 XSS",
                pattern_id="web-injection",
                principle="HTTP 协议未对用户输入做充分验证，注入攻击模型适用于所有 Web 应用",
                surface_path="web-security/02-xss-and-injection-security.md",
                port_triggers=[80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
                service_triggers=["http", "https", "nginx", "apache", "iis"],
                env_hints=["web"],
                base_confidence=0.6,
                impact="high",
                effort="medium",
                verification_method="nuclei / sqlmap / 手动 payload 注入",
            ),
            AttackPatternRule(
                name="SSH 弱口令/Key 复用",
                pattern_id="ssh-breach",
                principle="SSH 协议支持密码和公钥认证，密码可被暴力破解，公钥可被窃取复用",
                surface_path="protocols/05-ssh-protocol-security.md",
                port_triggers=[22, 2222],
                service_triggers=["ssh", "openssh"],
                env_hints=["ssh"],
                base_confidence=0.5,
                impact="critical",
                effort="medium",
                verification_method="hydra 暴力破解 / 尝试已知私钥",
            ),
            AttackPatternRule(
                name="Redis 未授权访问",
                pattern_id="redis-noauth",
                principle="Redis 协议无认证层的信任假设，默认配置允许任意连接",
                surface_path="network/01-network-stack-security.md",
                port_triggers=[6379, 6380],
                service_triggers=["redis", "redis-server"],
                env_hints=["container"],
                base_confidence=0.7,
                impact="high",
                effort="low",
                verification_method="redis-cli ping / info 测试",
            ),
            AttackPatternRule(
                name="数据库弱口令",
                pattern_id="db-weak-cred",
                principle="数据库服务依赖密码认证，默认配置或弱密码可被利用",
                surface_path="crypto/05-cryptography-security.md",
                port_triggers=[3306, 5432, 3307, 1521, 1433],
                service_triggers=["mysql", "postgresql", "oracle", "mssql"],
                env_hints=[],
                base_confidence=0.5,
                impact="critical",
                effort="low",
                verification_method="psql / mysql -h 尝试默认凭据",
            ),
            AttackPatternRule(
                name="SMB 匿名访问",
                pattern_id="smb-anonymous",
                principle="SMB 协议支持匿名 IPC$ 连接，默认配置可能暴露共享",
                surface_path="protocols/06-smb-protocol-security.md",
                port_triggers=[139, 445],
                service_triggers=["smb", "microsoft-ds"],
                env_hints=["windows"],
                base_confidence=0.4,
                impact="high",
                effort="low",
                verification_method="smbclient -L //target -N 测试匿名访问",
            ),
            AttackPatternRule(
                name="Everything HTTP 文件系统泄露",
                pattern_id="everything-http",
                principle="文件索引工具默认绑定 0.0.0.0 且无认证，局域网任意访问",
                surface_path="web-security/05-everything-http-security.md",
                port_triggers=[13577],
                service_triggers=["everything"],
                env_hints=["windows"],
                base_confidence=0.8,
                impact="critical",
                effort="low",
                verification_method="curl http://target:13577/ 验证 HTTP 响应",
            ),
            AttackPatternRule(
                name="Docker 容器逃逸",
                pattern_id="container-escape",
                principle="容器隔离依赖内核命名空间，docker.sock 挂载或特权模式可绕过",
                surface_path="network/03-docker-container-security.md",
                port_triggers=[],
                service_triggers=[],
                env_hints=["container"],
                base_confidence=0.4,
                impact="critical",
                effort="medium",
                verification_method="检查 /var/run/docker.sock 和 capabilities",
            ),
            AttackPatternRule(
                name="ZTNA 控制平面攻击",
                pattern_id="ztna-attack",
                principle="ZTNA 控制平面 API 若未正确保护，可被枚举和利用",
                surface_path="network/04-ztna-zero-trust-security.md",
                port_triggers=[8080, 9090, 80],
                service_triggers=["ztna", "headscale", "authentik"],
                env_hints=[],
                base_confidence=0.5,
                impact="critical",
                effort="low",
                verification_method="curl http://target:port/api/ 测试 API",
            ),
            AttackPatternRule(
                name="浏览器密码库泄露",
                pattern_id="browser-password",
                principle="Chrome/Edge 密码用 DPAPI + AES-GCM 加密，同用户可解密",
                surface_path="web-security/04-browser-password-security.md",
                port_triggers=[],
                service_triggers=[],
                env_hints=["windows"],
                base_confidence=0.6,
                impact="critical",
                effort="medium",
                verification_method="读取 Local State + Login Data 解密",
            ),
            AttackPatternRule(
                name="KeePass 密码库离线破解",
                pattern_id="keepass-crack",
                principle="KeePass KDBX 文件使用 Argon2d/AES-KDF 加密，可离线暴力破解",
                surface_path="crypto/06-password-storage-security.md",
                port_triggers=[],
                service_triggers=[],
                env_hints=[],
                base_confidence=0.5,
                impact="critical",
                effort="high",
                verification_method="keepass2john + hashcat 暴力破解",
            ),
            AttackPatternRule(
                name="密码复用横向移动",
                pattern_id="cred-reuse",
                principle="企业内部密码复用普遍存在，一处泄露可突破多台系统",
                surface_path="level2-case-fusion.md",
                port_triggers=[],
                service_triggers=[],
                env_hints=[],
                base_confidence=0.7,
                impact="critical",
                effort="low",
                verification_method="尝试已获取凭据登录其他服务",
            ),
            AttackPatternRule(
                name="防火墙管理接口攻击",
                pattern_id="fw-management",
                principle="防火墙管理接口通常有默认凭据，或可通过 SSL 证书识别设备型号",
                surface_path="network/05-nsg-firewall-security.md",
                port_triggers=[443, 8443, 9090, 10000],
                service_triggers=["nsg", "firewall", "pfsense", "opnsense"],
                env_hints=[],
                base_confidence=0.4,
                impact="high",
                effort="medium",
                verification_method="尝试 admin/admin 等默认凭据",
            ),
            AttackPatternRule(
                name="向日葵远程桌面突破",
                pattern_id="sunlogin-breach",
                principle="向日葵远程控制软件 Token 存储在本地配置文件，可被窃取并复用",
                surface_path="level2-case-fusion.md",
                port_triggers=[],
                service_triggers=["sunlogin", "向日葵"],
                env_hints=[],
                base_confidence=0.5,
                impact="high",
                effort="low",
                verification_method="读取 Sunlogin 配置文件提取 Token",
            ),
            AttackPatternRule(
                name="FinalShell SSH 配置泄露",
                pattern_id="finalshell-config",
                principle="FinalShell SSH 客户端配置以明文存储连接信息和密码",
                surface_path="level2-case-fusion.md",
                port_triggers=[],
                service_triggers=[],
                env_hints=[],
                base_confidence=0.5,
                impact="high",
                effort="low",
                verification_method="读取 FinalShell 配置文件提取 SSH 连接",
            ),
        ]

        cls.SEED_PATTERNS = {p.pattern_id: p for p in patterns}
        logger.info(f"[知识库] 初始化完成: {len(cls.SEED_PATTERNS)} 个攻击模式种子")

    @classmethod
    def get_pattern_by_port(cls, port: int) -> list[AttackPatternRule]:
        """按端口匹配攻击模式"""
        return [p for p in cls.SEED_PATTERNS.values() if port in p.port_triggers]

    @classmethod
    def get_pattern_by_service(cls, service: str) -> list[AttackPatternRule]:
        """按服务名匹配攻击模式"""
        svc_lower = service.lower()
        return [
            p for p in cls.SEED_PATTERNS.values()
            if any(trigger in svc_lower for trigger in p.service_triggers)
        ]

    @classmethod
    def get_all_patterns(cls) -> list[AttackPatternRule]:
        """获取所有攻击模式"""
        return list(cls.SEED_PATTERNS.values())

    @classmethod
    def get_pattern_by_id(cls, pattern_id: str) -> Optional[AttackPatternRule]:
        """按 ID 获取攻击模式"""
        return cls.SEED_PATTERNS.get(pattern_id)

    @classmethod
    def get_by_env_hint(cls, env_hint: str) -> list[AttackPatternRule]:
        """按部署环境获取攻击模式"""
        return [
            p for p in cls.SEED_PATTERNS.values()
            if env_hint in p.env_hints
        ]

    @classmethod
    def get_ports_pattern_map(cls) -> dict[int, list[str]]:
        """返回端口→模式ID映射表（用于快速查找）"""
        mapping: dict[int, list[str]] = {}
        for pid, pattern in cls.SEED_PATTERNS.items():
            for port in pattern.port_triggers:
                if port not in mapping:
                    mapping[port] = []
                mapping[port].append(pid)
        return mapping


# 模块加载时自动初始化
KnowledgeBaseEngine.initialize()
