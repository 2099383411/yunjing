"""云镜推理引擎 — 假设生成器

从感知结果和知识库规则生成攻击假设。
当前实现规则引擎 + LLM 混合模式：
1. 规则引擎（Phase 1）：基于 14 种攻击模式的硬编码规则
2. LLM 生成（Phase 2）：根据感知结果动态推断新假设

集成:
- LearningEngine: 调整置信度和排序权重
- LLM Generator: 补充规则覆盖不到的假设
"""
from __future__ import annotations
import uuid
import asyncio
import logging
from typing import Optional

from .models import (
    TargetPerception, AttackHypothesis, HypothesisStatus,
    PortInfo, WebInfo, CredentialInfo,
)

logger = logging.getLogger(__name__)


class HypothesisGenerator:
    """假设生成器"""

    def __init__(self, llm_generator: Optional[callable] = None,
                 learning_engine: Optional[callable] = None):
        """
        Args:
            llm_generator: async callable(perception) -> list[AttackHypothesis]
            learning_engine: LearningEngine 实例（用于置信度调整）
        """
        self._llm_generator = llm_generator
        self._learning_engine = learning_engine

    def generate(self, perception: TargetPerception,
                 target_type: str = "common") -> list[AttackHypothesis]:
        """从感知结果生成攻击假设

        Args:
            perception: 目标感知结果
            target_type: 目标环境类型（用于自学习调整）

        Returns:
            排序后的攻击假设列表
        """
        hypotheses = []

        # Phase 1: 规则引擎
        hypotheses.extend(self._rule_based_generation(perception))
        logger.info(f"[假设生成] 规则生成 {len(hypotheses)} 个")

        # Phase 2: LLM 生成（异步回调，用 asyncio.run 包装）
        if self._llm_generator:
            try:
                llm_hypotheses = asyncio.run(self._llm_generator(perception))
                if llm_hypotheses:
                    logger.info(f"[假设生成] LLM 补充 {len(llm_hypotheses)} 个")
                    hypotheses.extend(llm_hypotheses)
            except Exception as e:
                logger.warning(f"[假设生成] LLM 生成失败（不影响规则引擎）: {e}")

        # Phase 3: 自学习置信度调整
        if self._learning_engine:
            for h in hypotheses:
                adjusted = self._learning_engine.get_adjusted_confidence(h, target_type)
                if adjusted != h.source_confidence:
                    logger.debug(
                        f"[自学习] 置信度调整: {h.name} "
                        f"{h.source_confidence:.3f} → {adjusted:.3f}"
                    )
                    h.source_confidence = adjusted

        # 去重（按名称去重）
        seen = set()
        unique = []
        for h in hypotheses:
            key = h.name.lower().strip()
            if key not in seen:
                seen.add(key)
                unique.append(h)

        logger.info(f"[假设生成] 最终 {len(unique)} 个假设 "
                    f"(规则{len(hypotheses)-len(unique) if self._llm_generator else 0}+LLM+去重)")
        return unique

    def _rule_based_generation(self, p: TargetPerception) -> list[AttackHypothesis]:
        """基于 14 种攻击模式的规则引擎"""
        hypotheses = []
        port_set = {info.port for info in p.open_ports}
        services = {info.service.lower() for info in p.open_ports}
        found_creds = bool(p.discovered_credentials)
        found_files = bool(p.accessible_files)

        # -------------------------------------------------------
        # Web 服务漏洞
        # -------------------------------------------------------
        if 80 in port_set or 443 in port_set or any(s in services for s in ["http", "https"]):
            h = self._make_hypothesis(
                name="Web 应用漏洞探测",
                desc="目标开放 HTTP/HTTPS 服务，可能存在 SQL 注入、XSS、命令注入等常见 Web 漏洞",
                principle="HTTP 协议未对用户输入做充分验证，注入攻击模型适用于所有 Web 应用",
                attack_surface="web-security/02-xss-and-injection-security.md",
                pattern_id="web-injection",
                confidence=0.6,
                impact="high",
                effort="medium",
                env_hint="web",
                verification="nuclei / sqlmap / curl 测试注入点",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # SSH 暴力破解 / Key 复用
        # -------------------------------------------------------
        if 22 in port_set:
            h = self._make_hypothesis(
                name="SSH 弱口令/Key 复用",
                desc="SSH 服务开放，存在弱口令暴力破解或已知私钥复用的可能性",
                principle="SSH 协议支持密码和公钥认证，密码可被暴力破解，公钥可被窃取复用",
                attack_surface="protocols/05-ssh-protocol-security.md",
                pattern_id="ssh-breach",
                confidence=0.5,
                impact="critical",
                effort="low" if found_creds else "medium",
                env_hint="ssh",
                verification="hydra 暴力破解 / 尝试已知私钥登录",
            )
            if found_creds:
                h.depends_on = ["cred-discovered"]
            hypotheses.append(h)

        # -------------------------------------------------------
        # Redis 未授权访问
        # -------------------------------------------------------
        if 6379 in port_set:
            h = self._make_hypothesis(
                name="Redis 未授权访问",
                desc="Redis 默认无密码，可能导致数据泄露或远程命令执行",
                principle="Redis 协议无认证层的信任假设，默认配置允许任意连接",
                attack_surface="network/01-network-stack-security.md",
                pattern_id="redis-noauth",
                confidence=0.7,
                impact="high",
                effort="low",
                env_hint="container" if self._is_container(p) else "physical",
                verification="redis-cli ping / info 命令测试",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # MySQL / PostgreSQL 弱口令
        # -------------------------------------------------------
        for port in [3306, 5432, 3307]:
            if port in port_set:
                svc = {3306: "MySQL", 5432: "PostgreSQL", 3307: "MySQL"}[port]
                h = self._make_hypothesis(
                    name=f"{svc} 弱口令/默认凭据",
                    desc=f"{svc} 数据库端口开放，存在默认凭据或弱口令风险",
                    principle="数据库服务依赖密码认证，默认配置或弱密码可被利用",
                    attack_surface="crypto/05-cryptography-security.md",
                    pattern_id="db-weak-cred",
                    confidence=0.5,
                    impact="critical",
                    effort="low",
                    verification=f"psql / mysql -h 尝试默认凭据连接",
                )
                hypotheses.append(h)

        # -------------------------------------------------------
        # SMB 匿名访问 / 信息泄露
        # -------------------------------------------------------
        if 445 in port_set or 139 in port_set:
            h = self._make_hypothesis(
                name="SMB 匿名访问 / 信息泄露",
                desc="SMB 服务可能允许匿名访问，导致文件系统泄露",
                principle="SMB 协议支持匿名 IPC$ 连接，默认配置可能暴露共享",
                attack_surface="protocols/06-smb-protocol-security.md",
                pattern_id="smb-anonymous",
                confidence=0.4,
                impact="high",
                effort="low",
                verification="smbclient -L //target -N 测试匿名访问",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # Everything HTTP 文件系统泄露
        # -------------------------------------------------------
        if 13577 in port_set:
            h = self._make_hypothesis(
                name="Everything HTTP 文件系统泄露",
                desc="Everything HTTP 服务默认无认证，可浏览完整文件系统",
                principle="文件索引工具默认绑定 0.0.0.0 且无认证，局域网任意访问",
                attack_surface="web-security/05-everything-http-security.md",
                pattern_id="everything-http",
                confidence=0.8,
                impact="critical",
                effort="low",
                env_hint="windows",
                verification="curl http://target:13577/ 验证 HTTP 响应",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # 容器逃逸
        # -------------------------------------------------------
        if self._is_container(p):
            h = self._make_hypothesis(
                name="Docker 容器逃逸",
                desc="目标运行在容器中，检查 docker.sock 或特权模式可逃逸到宿主机",
                principle="容器隔离依赖内核命名空间，docker.sock 挂载或特权模式可绕过",
                attack_surface="network/03-docker-container-security.md",
                pattern_id="container-escape",
                confidence=0.4,
                impact="critical",
                effort="medium",
                env_hint="container",
                verification="检查 /var/run/docker.sock 和 capabilities",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # ZTNA / Headscale 控制平面攻击
        # -------------------------------------------------------
        if any("ztna" in s or "headscale" in s for s in services):
            h = self._make_hypothesis(
                name="ZTNA 控制平面攻击",
                desc="发现 ZTNA 控制平面服务，可能存在 API 未授权或预认证 Key 泄露",
                principle="ZTNA 控制平面 API 若未正确保护，可被枚举和利用",
                attack_surface="network/04-ztna-zero-trust-security.md",
                pattern_id="ztna-attack",
                confidence=0.5,
                impact="critical",
                effort="low",
                verification="curl http://target:8080/api/v1/node 测试 API",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # 浏览器密码泄露（如果可读文件系统）
        # -------------------------------------------------------
        if found_files:
            h = self._make_hypothesis(
                name="浏览器密码库泄露",
                desc="可从文件系统中读取浏览器 Local State 和 Login Data，提取所有保存密码",
                principle="Chrome/Edge 密码用 DPAPI + AES-GCM 加密，同用户可解密",
                attack_surface="web-security/04-browser-password-security.md",
                pattern_id="browser-password",
                confidence=0.6,
                impact="critical",
                effort="medium",
                env_hint="windows",
                verification="读取 %LOCALAPPDATA%/.../Local State + Login Data",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # KeePass 密码库
        # -------------------------------------------------------
        if found_files:
            h = self._make_hypothesis(
                name="KeePass 密码库离线破解",
                desc="发现 .kdbx 文件，可通过 keepass2john + hashcat 离线破解",
                principle="KeePass KDBX 文件使用 Argon2d/AES-KDF 加密，可离线暴力破解",
                attack_surface="crypto/06-password-storage-security.md",
                pattern_id="keepass-crack",
                confidence=0.5,
                impact="critical",
                effort="high",
                verification="keepass2john + hashcat 离线破解",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # 已发现凭据 → 密码复用
        # -------------------------------------------------------
        if found_creds:
            h = self._make_hypothesis(
                name="密码复用横向移动",
                desc="已获取的凭据可能在多台机器或服务间复用，尝试横向移动",
                principle="企业内部密码复用普遍存在，一处泄露可突破多台系统",
                attack_surface="level2-case-fusion.md",
                pattern_id="cred-reuse",
                confidence=0.7,
                impact="critical",
                effort="low",
                verification=f"尝试凭据 {[c.host for c in p.discovered_credentials[:3]]}",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # Firewall / NSG 管理接口
        # -------------------------------------------------------
        if any("nsg" in s or "firewall" in s for s in services):
            h = self._make_hypothesis(
                name="防火墙管理接口攻击",
                desc="发现防火墙管理接口，存在默认凭据或配置泄露风险",
                principle="防火墙管理接口通常有默认凭据，或可通过 SSL 证书识别设备型号",
                attack_surface="network/05-nsg-firewall-security.md",
                pattern_id="fw-management",
                confidence=0.4,
                impact="high",
                effort="medium",
                verification="尝试 admin/admin 等默认凭据登录",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # 向日葵远程桌面突破
        # -------------------------------------------------------
        if found_files:
            h = self._make_hypothesis(
                name="向日葵远程桌面 Token 泄露",
                desc="向日葵远程管理软件可能在本地存储 Token，可用于无密码远程登录",
                principle="向日葵远程控制软件 Token 存储在本地配置文件，可被窃取并复用",
                attack_surface="level2-case-fusion.md",
                pattern_id="sunlogin-breach",
                confidence=0.5,
                impact="high",
                effort="low",
                verification="读取 Sunlogin 配置文件提取 Token",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # FinalShell SSH 配置泄露
        # -------------------------------------------------------
        if found_files:
            h = self._make_hypothesis(
                name="FinalShell SSH 配置泄露",
                desc="FinalShell SSH 客户端配置以明文存储连接信息和密码",
                principle="FinalShell SSH 客户端配置以明文存储连接信息和密码",
                attack_surface="level2-case-fusion.md",
                pattern_id="finalshell-config",
                confidence=0.5,
                impact="high",
                effort="low",
                verification="读取 FinalShell 配置文件提取 SSH 连接",
            )
            hypotheses.append(h)

        # -------------------------------------------------------
        # 为每个假设生成唯一 ID
        # -------------------------------------------------------
        for h in hypotheses:
            if not h.id:
                h.id = f"H-{uuid.uuid4().hex[:6]}"

        return hypotheses

    def _make_hypothesis(
        self,
        name: str,
        desc: str,
        principle: str,
        attack_surface: str,
        pattern_id: str,
        confidence: float,
        impact: str,
        effort: str,
        env_hint: str = "",
        verification: str = "",
    ) -> AttackHypothesis:
        """创建攻击假设的辅助方法"""
        return AttackHypothesis(
            id=f"H-{uuid.uuid4().hex[:6]}",
            name=name,
            description=desc,
            pattern_id=pattern_id,
            source_principle=principle,
            source_attack_surface=attack_surface,
            source_confidence=confidence,
            priority_score=0.0,
            impact=impact,
            effort=effort,
            env_hint=env_hint,
            verification_method=verification,
            status=HypothesisStatus.PENDING,
        )

    @staticmethod
    def _is_container(p: TargetPerception) -> bool:
        """从感知结果判断是否运行在容器中"""
        # 容器特征：主机名短随机、非标准内核版本等
        hostname = p.hostname.lower()
        if any(x in hostname for x in ["dvwa", "worker", "container", "docker"]):
            return True
        # 可通过 os_info 进一步判断
        return False
