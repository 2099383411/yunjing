"""云镜推理引擎 — 基于知识库的动态假设生成器

替代旧的 14 条硬编码规则。核心逻辑：

1. 收到感知结果（端口、服务、环境）
2. 查询知识库获取相关章节和攻击面条目
3. 从攻击面条目中的「推导逻辑」自动构造攻击假设
4. LLM 补充验证策略
5. 自学习调整置信度

关键区别：
  旧版: 端口 6379 → 硬编码 "Redis 未授权访问"（只匹配不推理）
  新版: 端口 6379 → 查知识库 → 获取原理 + 推导链 → 生成多条假设
"""
from __future__ import annotations
import uuid
import asyncio
import logging
from typing import Optional
from collections import defaultdict

from .models import (
    TargetPerception, AttackHypothesis, HypothesisStatus,
    PortInfo, WebInfo, CredentialInfo,
)
from .kb_query import get_kb_index, KnowledgeBaseIndex, KnowledgeQueryResult, AttackSurfaceEntry

logger = logging.getLogger(__name__)


class KBHypothesisGenerator:
    """基于知识库的假设生成器"""

    def __init__(self, kb_index: Optional[KnowledgeBaseIndex] = None,
                 llm_generator: Optional[callable] = None,
                 learning_engine: Optional[object] = None):
        """
        Args:
            kb_index: 知识库索引实例（不传则用全局默认）
            llm_generator: async callable(perception) → list[AttackHypothesis]
            learning_engine: LearningEngine 实例
        """
        self._kb = kb_index or get_kb_index()
        self._llm_generator = llm_generator
        self._learning_engine = learning_engine

    def generate(self, perception: TargetPerception,
                 target_type: str = "common") -> list[AttackHypothesis]:
        """从感知结果动态生成攻击假设

        Args:
            perception: 目标感知结果
            target_type: 目标环境类型

        Returns:
            排序后的攻击假设列表
        """
        hypotheses = []

        # Phase 1: 知识库驱动生成
        kb_hypotheses = self._kb_driven_generation(perception)
        hypotheses.extend(kb_hypotheses)
        logger.info(f"[KB生成器] 知识库生成 {len(kb_hypotheses)} 个假设")

        # Phase 2: ★★★ 案例推理（案例库优先）★★★
        if self._learning_engine:
            case_boosted = self._apply_case_based_reasoning(hypotheses, perception)
            if case_boosted:
                logger.info(f"[KB生成器] 案例推理命中 {case_boosted} 个假设（优先级提升）")

        # Phase 3: LLM 补充
        if self._llm_generator:
            try:
                llm_hypotheses = asyncio.run(self._llm_generator(perception))
                if llm_hypotheses:
                    logger.info(f"[KB生成器] LLM 补充 {len(llm_hypotheses)} 个假设")
                    # 案例推理同样作用于 LLM 生成的假设
                    if self._learning_engine:
                        self._apply_case_based_reasoning(llm_hypotheses, perception)
                    hypotheses.extend(llm_hypotheses)
            except Exception as e:
                logger.warning(f"[KB生成器] LLM 生成失败（不影响知识库假设）: {e}")

        # Phase 4: 自学习置信度调整
        if self._learning_engine:
            for h in hypotheses:
                adjusted = self._learning_engine.get_adjusted_confidence(h, target_type)
                if adjusted != h.source_confidence:
                    h.source_confidence = adjusted

        # 去重
        hypotheses = self._deduplicate(hypotheses)

        logger.info(f"[KB生成器] 最终 {len(hypotheses)} 个假设")
        return hypotheses

    # ============================================================
    # 核心：知识库驱动生成
    # ============================================================

    def _kb_driven_generation(self, p: TargetPerception) -> list[AttackHypothesis]:
        """从知识库查询生成攻击假设"""
        hypotheses = []

        # 1. 收集查询上下文
        port_set = {info.port for info in p.open_ports}
        services = {info.service.lower() for info in p.open_ports}
        env = self._infer_environment(p)
        has_creds = bool(p.discovered_credentials)
        has_files = bool(p.accessible_files)

        # 2. 对每个开放端口查知识库
        for port in port_set:
            result = self._kb.query_by_port(port)
            if result.total_matches == 0:
                # 端口在知识库里找不到，用服务名查
                service = next(
                    (info.service for info in p.open_ports if info.port == port),
                    ""
                )
                if service:
                    result = self._kb.query_by_service(service)

            # 从攻击面条目生成假设
            for entry in result.attack_surface_entries:
                h = self._entry_to_hypothesis(entry, port, p)
                if h:
                    hypotheses.append(h)

            # 兜底：如果知识库查询命中了章节但没有攻击面条目，
            # 从章节中提取关键信息生成通用假设
            if not result.attack_surface_entries and result.sections:
                fallback_h = self._fallback_from_sections(result, port, p)
                if fallback_h:
                    hypotheses.extend(fallback_h)

        # 3. 按环境查通用攻击面
        if env:
            env_result = self._kb.query_by_env(env)
            for entry in env_result.attack_surface_entries:
                # 避免与端口级假设重复
                already_have = any(
                    entry.attack_direction in h.name or h.name in entry.attack_direction
                    for h in hypotheses
                )
                if not already_have:
                    h = self._entry_to_hypothesis(entry, 0, p)
                    if h:
                        hypotheses.append(h)

        # 4. 凭据相关
        if has_creds or has_files:
            cred_result = self._kb.query(["credential", "password", "keepass", "key"])
            for entry in cred_result.attack_surface_entries:
                h = self._entry_to_hypothesis(entry, 0, p, override_confidence=0.6)
                if h:
                    hypotheses.append(h)

        # 5. 设置唯一 ID
        for h in hypotheses:
            if not h.id:
                h.id = f"H-{uuid.uuid4().hex[:6]}"

        return hypotheses

    def _fallback_from_sections(
        self, result: KnowledgeQueryResult, port: int,
        p: TargetPerception
    ) -> list[AttackHypothesis]:
        """当知识库没有攻击面条目时，从匹配章节生成通用假设"""
        fallback_h = []
        seen_methods = set()

        # 整理端口-服务映射
        service_map = {info.port: info.service for info in p.open_ports}

        for section in result.sections:
            content_lower = section.content.lower()
            title_lower = section.title.lower()

            # 提取可信的攻击相关句子
            attack_indicators = []
            for line in section.content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # 检测攻击相关模式
                if any(kw in line.lower() for kw in [
                    "攻击", "突破", "绕过", "逃逸", "注入", "劫持",
                    "泄露", "破解", "exploit", "pwn", "rce", "shell",
                    "敏感", "密码", "root", "admin", "未授权",
                    "入侵", "渗透", "横向", "提权", "后门"
                ]):
                    if len(line) > 10 and line not in attack_indicators:
                        # 去重短文本
                        short = line[:40]
                        if short not in seen_methods:
                            attack_indicators.append(line)
                            seen_methods.add(short)

            if not attack_indicators:
                continue

            # 从章节生成假设
            service = service_map.get(port, "")
            h = AttackHypothesis(
                id=f"H-{uuid.uuid4().hex[:6]}",
                name=section.title if len(section.title) <= 40 else section.title[:40],
                description=f"端口 {port} ({service}) 相关章节: {section.title}\n"
                           f"关键线索: {'; '.join(attack_indicators[:3])}",
                pattern_id=f"kb-derived-port-{port}",
                source_principle="; ".join(attack_indicators[:2]),
                source_attack_surface=f"knowledge:{section.title}",
                source_confidence=0.4,  # 比攻击面条目低（待验证）
                impact="medium",
                effort="medium",
                verification_method=f"根据端口 {port} 信息进行针对性测试",
                status=HypothesisStatus.PENDING,
            )
            fallback_h.append(h)

        return fallback_h

    # ============================================================
    # 攻击面条目 → 假设转换
    # ============================================================

    def _entry_to_hypothesis(
        self, entry: AttackSurfaceEntry, port: int,
        perception: TargetPerception,
        override_confidence: Optional[float] = None,
    ) -> Optional[AttackHypothesis]:
        """将攻击面条目转换为攻击假设"""
        name = entry.attack_direction.strip()
        if not name or len(name) < 3:
            return None

        # 清理名称（去掉 Markdown 标记）
        clean_name = name.replace("**", "").replace("*", "").strip()
        if len(clean_name) > 50:
            clean_name = clean_name[:50]

        # 置信度：端口有明确匹配时更高
        confidence = override_confidence or 0.5
        if port in (22, 6379, 3306, 13577, 445, 139):
            confidence = min(confidence + 0.2, 0.9)

        # 影响程度：从技术名推断
        impact = self._infer_impact(entry.actual_technique + entry.attack_direction)
        effort = self._infer_effort(entry.derivation_logic)

        # 环境适配
        env_hint = ""
        if any(kw in entry.attack_direction.lower() for kw in ["容器", "docker", "container"]):
            env_hint = "container"
        elif any(kw in entry.attack_direction.lower() for kw in ["windows", "ntfs"]):
            env_hint = "windows"

        return AttackHypothesis(
            id=f"H-{uuid.uuid4().hex[:6]}",
            name=clean_name,
            description=(
                f"原理: {entry.derivation_logic}\n"
                f"攻击技术: {entry.actual_technique}\n"
                f"来源: {entry.doc_path}"
            ),
            pattern_id=self._infer_pattern_id(entry),
            source_principle=entry.derivation_logic,
            source_attack_surface=entry.doc_path,
            source_confidence=confidence,
            impact=impact,
            effort=effort,
            env_hint=env_hint,
            verification_method=self._verification_for_entry(entry),
            status=HypothesisStatus.PENDING,
        )

    def _infer_pattern_id(self, entry: AttackSurfaceEntry) -> str:
        """从攻击面条目推断模式ID"""
        text = (entry.attack_direction + entry.derivation_logic).lower()
        for kw, pid in [
            ("web", "web-injection"), ("注入", "web-injection"),
            ("xss", "web-injection"), ("sql", "web-injection"),
            ("ssh", "ssh-breach"), ("redis", "redis-noauth"),
            ("mysql", "db-weak-cred"), ("postgres", "db-weak-cred"),
            ("smb", "smb-anonymous"), ("everything", "everything-http"),
            ("容器", "container-escape"), ("docker", "container-escape"),
            ("ztna", "ztna-attack"), ("密码", "cred-reuse"),
            ("证书", "ssl-tls"), ("cve", "known-vuln"),
        ]:
            if kw in text:
                return pid
        return "kb-derived"

    def _infer_impact(self, text: str) -> str:
        """推断影响程度"""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["rce", "代码执行", "远程控制", "提权",
                                            "root", "admin", "逃逸", "全控",
                                            "认证绕过", "敏感信息"]):
            return "critical"
        if any(kw in text_lower for kw in ["ssrf", "文件读取", "xss", "csrf",
                                            "信息泄露", "dos", "拒绝服务"]):
            return "high"
        if any(kw in text_lower for kw in ["信息收集", "探针", "枚举", "版本识别"]):
            return "low"
        return "medium"

    def _infer_effort(self, text: str) -> str:
        """推断验证难度"""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ["猜解", "暴力", "破解", "逆向", "汇编"]):
            return "high"
        if any(kw in text_lower for kw in ["探测", "检查", "读取", "查看"]):
            return "low"
        if any(kw in text_lower for kw in ["利用", "劫持", "注入", "溢出"]):
            return "medium"
        return "medium"

    def _verification_for_entry(self, entry: AttackSurfaceEntry) -> str:
        """为攻击面条目生成验证方法"""
        derive = entry.derivation_logic.lower()
        technique = entry.actual_technique.lower()

        if "curl" in technique or "http" in technique:
            return f"curl/sqlmap/nuclei 验证 {entry.attack_direction}"
        if "nmap" in technique:
            return f"nmap 脚本验证 {entry.attack_direction}"
        if "ssh" in derive or "ssh" in technique:
            return f"hydra/ssh 验证 {entry.attack_direction}"
        return f"手动验证: {entry.derivation_logic[:100]}"

    # ============================================================
    # 辅助方法
    # ============================================================

    @staticmethod
    def _infer_environment(p: TargetPerception) -> str:
        """从感知结果推断目标环境"""
        hostname = p.hostname.lower()
        if any(x in hostname for x in ["dvwa", "worker", "container", "docker"]):
            return "container"
        if p.os_info and "windows" in p.os_info.lower():
            return "windows"
        if p.os_info and "linux" in p.os_info.lower():
            return "linux"
        return ""

    @staticmethod
    def _deduplicate(hypotheses: list[AttackHypothesis]) -> list[AttackHypothesis]:
        """按名称去重"""
        seen = set()
        result = []
        for h in hypotheses:
            key = h.name.lower().strip()[:30]
            if key not in seen:
                seen.add(key)
                result.append(h)
            else:
                # 如果已有同名的，保留置信度更高的
                for existing in result:
                    if existing.name.lower().strip()[:30] == key:
                        if h.source_confidence > existing.source_confidence:
                            existing.source_confidence = h.source_confidence
                        break
        return result

    # ============================================================
    # ★★★ 案例推理优先（v0.2 新增）★★★
    # ============================================================

    def _apply_case_based_reasoning(
        self, hypotheses: list, perception
    ) -> int:
        """从案例库检索相似案例，提升已验证模式的优先级

        核心思想：
        遇到新目标时，先问问自己——"我以前打过类似的目标吗？上次什么方法管用了？"
        如果案例库说"上次的 Windows 10 是通过 SSH key 打穿的"，
        那当前目标的 SSH key 假设就值得排到前面。

        Returns:
            int: 被提升的假设数量
        """
        if not self._learning_engine:
            return 0

        # 1. 构建目标特征
        target_features = self._build_target_features(perception)
        if not target_features.get("ports") and not target_features.get("services"):
            return 0

        # 2. 查案例库
        similar_chains = self._learning_engine.search_similar_chains(
            target_features, top_k=3
        )
        if not similar_chains:
            return 0

        # 3. 统计成功模式
        success_patterns = {}
        for chain in similar_chains:
            for step in chain.get("steps", []):
                pid = step.get("pattern_id", "")
                success = step.get("success", False)
                if pid:
                    if pid not in success_patterns:
                        success_patterns[pid] = {"count": 0, "total": 0}
                    success_patterns[pid]["total"] += 1
                    if success:
                        success_patterns[pid]["count"] += 1

        if not success_patterns:
            return 0

        # 4. 计算每个模式在相似案例中的成功率
        pattern_scores = {}
        for pid, stats in success_patterns.items():
            if stats["total"] >= 1:
                pattern_scores[pid] = stats["count"] / stats["total"]

        # 5. 提升假设优先级
        boosted = 0
        for h in hypotheses:
            h_pid = h.pattern_id or ""
            if h_pid in pattern_scores:
                boost = pattern_scores[h_pid] * 0.15
                old_conf = h.source_confidence
                h.source_confidence = min(1.0, h.source_confidence + boost)
                if h.source_confidence != old_conf:
                    boosted += 1

        # 6. 案例命中的模式排前面
        hypotheses.sort(
            key=lambda h: (
                pattern_scores.get(h.pattern_id or "", 0),
                h.source_confidence
            ),
            reverse=True
        )

        return boosted

    @staticmethod
    def _build_target_features(perception) -> dict:
        """从感知结果构建目标特征字典，用于案例检索"""
        features = {
            "ports": [info.port for info in perception.open_ports],
            "services": list({
                info.service.lower()
                for info in perception.open_ports
                if info.service
            }),
            "os": perception.os_info or "",
            "tags": [],
        }

        ports = set(features["ports"])
        if {80, 443, 8080}.intersection(ports) and {22}.intersection(ports):
            features["tags"].append("web+ssh")
        if {22}.intersection(ports) and {3306, 5432, 6379}.intersection(ports):
            features["tags"].append("db-server")
        if {135, 139, 445, 3389}.intersection(ports):
            features["tags"].append("windows")
        if {6379, 5672, 9200}.intersection(ports):
            features["tags"].append("middleware")

        services = set(features["services"])
        if "http" in services or "https" in services:
            features["tags"].append("web-service")
        if "mysql" in services or "postgresql" in services or "redis" in services:
            features["tags"].append("database")

        return features
