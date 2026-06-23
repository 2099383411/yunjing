"""云镜推理引擎

基于四层推理链（感知→假设→验证→路径）的渗透测试推理框架。
与现有 DAG 扫描引擎并行运行，提供基于底层原理推导的脆弱性发现能力。

核心能力：
1. **知识库驱动** → 动态查询 43+ 份文档，从攻击面推导逻辑自动构造假设
2. **LLM 生成** → 动态推断非常规假设（补充非知识库覆盖范围）
3. **自学习** → 验证结果回流，动态调整置信度
4. **状态机** → 四层推理链树形流转

使用方式：
```python
from engine import ReasoningEngine

# 快速启动（含 LLM + 自学习）
engine = ReasoningEngine("192.168.1.1", enable_llm=True, enable_learning=True)

# 注入扫描结果
result = engine.run_full_pipeline(nmap_findings=[...])

# 查看 Top 假设
for h in result["hypotheses"]:
    print(f"{h['name']} (评分={h['score']})")
```

架构：
- perception.py      → 感知层：扫描结果结构化
- kb_hypothesis.py   → 假设层：知识库驱动的攻击假设生成（替代旧的 hypothesis.py 14条硬编码）
- state_machine.py   → 状态管理：四层推理链状态机
- knowledge.py       → 知识库：攻击模式种子规则（作为补充）
- kb_query.py        → 知识库查询引擎：支持动态文档查询
- models.py          → 数据模型定义
- llm_generator.py   → LLM 动态假设生成
- learning.py        → 自学习引擎
- verification.py    → 验证执行器

设计原则：
1. 模型无关：不绑定任何 LLM，可用任意模型驱动
2. 知识库驱动：不从硬编码规则匹配，而从 329 个攻击面条目推导
3. 证据驱动：所有假设必须有知识库支撑或 LLM 推导链
4. 分层推理：从原理出发逐层推导，不依赖预设模板
5. 自进化：每次验证都回流调整，越来越聪明
"""
from __future__ import annotations
import os
import json
import logging
from typing import Optional, Any

from .models import (
    EngineState, TargetPerception, AttackHypothesis, AttackPath,
    ScanPhase, HypothesisStatus, PathStatus, TrustLevel,
    PortInfo, WebInfo, FileInfo, CredentialInfo,
    VerificationStep, AttackPathNode, AttackChainStep, AttackChain,
)
from .perception import PerceptionLayer
from .kb_hypothesis import KBHypothesisGenerator  # ← 替代旧的 HypothesisGenerator
from .state_machine import ReasoningStateMachine
from .knowledge import KnowledgeBaseEngine, AttackPatternRule
from .verification import VerificationExecutor
from .hypothesis_scanner import HypothesisScanner
from .learning import LearningEngine

logger = logging.getLogger(__name__)


class ReasoningEngine:
    """推理引擎入口类"""

    def __init__(
        self,
        target: str,
        enable_llm: bool = True,
        enable_learning: bool = True,
        learning_storage: str = "",
        llm_adapter: Optional[object] = None,
    ):
        """
        Args:
            target: 目标 IP/Domain
            enable_llm: 是否启用 LLM 假设生成
            enable_learning: 是否启用自学习引擎
            learning_storage: 学习数据存储路径
            llm_adapter: LLMAdapter 实例（不传则自动创建）
        """
        self.target = target
        self._state_machine = ReasoningStateMachine(target)
        self._perception_layer = PerceptionLayer()
        self._learning_engine: Optional[LearningEngine] = None
        self._llm_generator_func: Optional[callable] = None

        # 初始化自学习
        if enable_learning:
            self._learning_engine = LearningEngine(
                storage_path=learning_storage or os.path.join(
                    os.path.dirname(__file__), "learning_data.json"
                )
            )
            logger.info(f"[引擎] 自学习已启用: {self._learning_engine.get_summary()}")

        # 初始化 LLM 生成器
        if enable_llm:
            try:
                from .llm_generator import create_llm_generator
                self._llm_generator_func = create_llm_generator(adapter=llm_adapter)
                logger.info("[引擎] LLM 假设生成器已启用")
            except Exception as e:
                logger.warning(f"[引擎] LLM 生成器初始化失败（不影响知识库引擎）: {e}")

        # 初始化 KB 驱动的假设生成器（替代旧硬编码规则）
        from .kb_query import get_kb_index
        kb_index = get_kb_index()
        self._hypothesis_generator = KBHypothesisGenerator(
            kb_index=kb_index,
            llm_generator=self._llm_generator_func,
            learning_engine=self._learning_engine,
        )
        logger.info(f"[引擎] KB驱动假设生成器已就绪 "
                    f"(知识库: {kb_index.get_stats()['documents']} 文档, "
                    f"{kb_index.get_stats()['attack_surface_entries']} 攻击面条目)")

        # RAG 向量检索状态
        try:
            from .vector_store import RAGEngine
            rag = RAGEngine()
            logger.info(f"[引擎] 向量RAG已就绪 (知识库: {rag.count('knowledge')} 向量, 经验库: {rag.count('experience')} 向量)")
        except Exception:
            logger.info("[引擎] 向量RAG未启用")

        # 初始化验证执行器
        self._verification_executor = VerificationExecutor()
        self._state_machine._verification_executor = self._verification_executor

        # 初始化假设驱动扫描桥接器
        self._hypothesis_scanner = HypothesisScanner(
            learning_engine=self._learning_engine,
        )
    # ============================================================
    #  假设驱动扫描 (Phase 1 桥接)
    # ============================================================

    def start(self) -> dict:
        """启动完整推理流程"""
        logger.info(f"[引擎] 启动推理: target={self.target}")
        return self._state_machine.get_summary()

    def run_full_pipeline(
        self,
        nmap_findings: Optional[list[dict]] = None,
        nuclei_findings: Optional[list[dict]] = None,
        gobuster_findings: Optional[list[dict]] = None,
        http_results: Optional[list[dict]] = None,
        credentials: Optional[list[CredentialInfo]] = None,
        custom_findings: Optional[list[TargetPerception]] = None,
        target_type: str = "common",
    ) -> dict:
        """运行完整推理管线

        Args:
            nmap_findings: nmap 扫描结果列表
            nuclei_findings: nuclei 扫描结果列表
            gobuster_findings: gobuster 扫描结果列表
            http_results: HTTP 探测结果列表
            credentials: 发现的凭据列表
            custom_findings: 自定义感知结果
            target_type: 目标环境类型（用于自学习）

        Returns:
            引擎最终状态摘要
        """
        # Layer 1: 感知
        perceptions = []

        if nmap_findings:
            perceptions.append(
                self._perception_layer.from_nmap_scan(self.target, nmap_findings)
            )
        if nuclei_findings:
            perceptions.append(
                self._perception_layer.from_nuclei_scan(self.target, nuclei_findings)
            )
        if gobuster_findings:
            perceptions.append(
                self._perception_layer.from_gobuster_scan(self.target, gobuster_findings)
            )
        if http_results:
            for r in http_results:
                port = r.get("port", 80)
                perceptions.append(
                    self._perception_layer.from_curls_http_check(self.target, port, r)
                )
        if credentials:
            perceptions.append(
                self._perception_layer.from_credentials(credentials)
            )
        if custom_findings:
            perceptions.extend(custom_findings)

        # 合并所有感知结果
        merged = (self._perception_layer.merge(perceptions)
                  if perceptions
                  else TargetPerception(target=self.target))

        # 注入感知结果
        perception_summary = self._state_machine.ingest_perception(merged)

        # Layer 2: 假设生成（含规则+LLM+自学习调整）
        hypotheses = self._state_machine.generate_hypotheses(
            generator=self._hypothesis_generator,
            target_type=target_type,
        )

        return {
            "perception": perception_summary,
            "hypotheses": [
                {
                    "id": h.id,
                    "name": h.name,
                    "description": h.description,
                    "score": h.priority_score,
                    "confidence": h.source_confidence,
                    "status": h.status.value,
                    "impact": h.impact,
                    "effort": h.effort,
                    "principle": h.source_principle[:100],
                }
                for h in hypotheses
            ],
            "state": self._state_machine.get_summary(),
        }

    # ============================================================
    # 验证 → 自学习反馈循环
    # ============================================================
    # ============================================================
    # ============================================================
    #  假设驱动扫描 (Phase 1 桥接)
    # ============================================================

    # ============================================================
    #  假设驱动扫描 (Phase 1 桥接)
    # ============================================================

    def scan_hypotheses(self, target: str = "", max_concurrent: int = 3) -> list[dict]:
        """将已生成的攻击假设提交到 Worker 执行扫描

        在 run_full_pipeline 之后调用，自动取当前所有假设发送到 Worker。

        Args:
            target: 扫描目标（默认 self.target）
            max_concurrent: 最大并行扫描数

        Returns:
            扫描任务调度结果列表
        """
        if not hasattr(self, "_hypothesis_scanner"):
            logger.warning("[扫描桥接] HypothesisScanner 未初始化")
            return []

        state = self._state_machine.state
        hypotheses = state.hypotheses
        if not hypotheses:
            logger.warning("[扫描桥接] 无假设可扫描")
            return []

        scan_target = target or self.target
        logger.info("[扫描桥接] 调度 %d 个假设 -> %s", len(hypotheses), scan_target)

        return self._hypothesis_scanner.execute_hypotheses(
            hypotheses=hypotheses,
            target=scan_target,
            max_concurrent=max_concurrent,
        )

    def feed_back_scan_result(self, hypothesis_id: str,
                              scan_success: bool,
                              findings: list[dict] = None) -> dict:
        """将扫描结果反馈给引擎，更新置信度

        Args:
            hypothesis_id: 假设ID
            scan_success: 扫描是否成功完成
            findings: 发现的漏洞列表

        Returns:
            置信度调整信息
        """
        findings = findings or []

        state = self._state_machine.state
        hypotheses = state.hypotheses
        hypothesis = next((h for h in hypotheses if h.id == hypothesis_id), None)
        if not hypothesis:
            logger.warning("[扫描回灌] 未找到假设: %s", hypothesis_id)
            return {"error": "Hypothesis not found: " + hypothesis_id}

        return self._hypothesis_scanner.feed_back(
            hypothesis=hypothesis,
            scan_success=scan_success,
            findings=findings,
        )


    def verify_and_learn(self, hypothesis_id: str, result: bool,
                         evidence: str = "", target_type: str = "common") -> float:
        """验证假设并回流到自学习引擎

        Args:
            hypothesis_id: 假设 ID
            result: 验证是否成功
            evidence: 证据描述
            target_type: 目标环境类型

        Returns:
            更新后的置信度
        """
        new_confidence = self._state_machine.update_hypothesis_confidence(
            hypothesis_id, result, evidence
        )

        # 回流到自学习引擎
        if self._learning_engine:
            for h in self._state_machine.state.hypotheses:
                if h.id == hypothesis_id:
                    self._learning_engine.record_result(h, result, target_type)
                    break

        return new_confidence

    def run_auto_verify(self, target_type: str = "common") -> int:
        """自动验证所有 PENDING 假设并回流学习"""
        count = 0
        while True:
            h = self._state_machine.next_hypothesis_to_test()
            if not h:
                break

            if self._verification_executor:
                success, evidence = self._verification_executor.execute(
                    h, self._state_machine.state.perception
                )
                self.verify_and_learn(h.id, success, evidence, target_type)
                count += 1

        # 验证完成后组合攻击路径
        if self._state_machine.state.confirmed_hypotheses:
            self._state_machine._transition(
                ScanPhase.VERIFICATION, ScanPhase.PATH_COMBINE
            )
            self._state_machine.compose_attack_paths()

        return count

    # ============================================================
    # 自学习查询
    # ============================================================

    def get_learning_summary(self) -> dict:
        """获取自学习摘要"""
        if not self._learning_engine:
            return {"enabled": False, "message": "自学习未启用"}
        return {
            "enabled": True,
            "summary": self._learning_engine.get_summary(),
        }

    def get_hot_patterns(self, target_type: str = "common", top_k: int = 5) -> list:
        """获取当前环境下最有效的攻击模式"""
        if not self._learning_engine:
            return []
        return self._learning_engine.get_env_hot_patterns(target_type, top_k)

    def get_cold_patterns(self, target_type: str = "common") -> list:
        """获取低效攻击模式"""
        if not self._learning_engine:
            return []
        return self._learning_engine.get_cold_patterns(target_type)

    # ============================================================
    # 单步控制
    # ============================================================

    def feed_scan_results(self, results: list[dict], source: str = "nmap") -> dict:
        """注入扫描结果（手动控制模式）"""
        if source == "nmap":
            p = self._perception_layer.from_nmap_scan(self.target, results)
        elif source == "nuclei":
            p = self._perception_layer.from_nuclei_scan(self.target, results)
        else:
            p = TargetPerception(target=self.target)
            p.raw_findings = results

        logger.info(f"[引擎] 注入扫描结果: source={source}, "
                    f"找={len(results)} 条")
        return self._state_machine.ingest_perception(p)

    def add_hypothesis(self, hypothesis: AttackHypothesis):
        """手动添加假设"""
        self._state_machine.state.hypotheses.append(hypothesis)
        if hypothesis.status == HypothesisStatus.PENDING:
            self._state_machine.state.active_hypotheses.append(hypothesis)

    def verify_next(self) -> Optional[dict]:
        """获取下一个待验证的假设"""
        h = self._state_machine.next_hypothesis_to_test()
        if not h:
            return None
        return {
            "id": h.id,
            "name": h.name,
            "method": h.verification_method,
            "description": h.description,
        }

    def confirm_hypothesis(self, hypothesis_id: str, evidence: str = "") -> float:
        """手动确认假设"""
        return self.verify_and_learn(hypothesis_id, True, evidence)

    def reject_hypothesis(self, hypothesis_id: str, reason: str = "") -> float:
        """手动否定假设"""
        return self.verify_and_learn(hypothesis_id, False, reason)

    def compose_paths(self) -> list[AttackPath]:
        """组合攻击路径"""
        return self._state_machine.compose_attack_paths()

    # ============================================================
    # 状态查询
    # ============================================================

    def get_state(self) -> EngineState:
        """获取完整引擎状态"""
        return self._state_machine.state

    def report(self) -> dict:
        """生成推理报告摘要"""
        state = self._state_machine.state
        report_data = {
            "target": state.target,
            "phase": state.current_phase.value,
            "port_count": len(state.perception.open_ports) if state.perception else 0,
            "hypotheses": {
                "total": len(state.hypotheses),
                "confirmed": len(state.confirmed_hypotheses),
                "active": len(state.active_hypotheses),
                "pending": len([h for h in state.hypotheses if h.status == HypothesisStatus.PENDING]),
                "refuted": len([h for h in state.hypotheses if h.status == HypothesisStatus.REFUTED]),
            },
            "attack_paths": [
                {
                    "id": p.id,
                    "name": p.name,
                    "score": p.total_score,
                    "nodes": len(p.nodes),
                    "status": p.status.value,
                }
                for p in state.attack_paths
            ],
        }

        # 追加自学习摘要
        if self._learning_engine:
            report_data["learning"] = self._learning_engine.get_summary()

        return report_data

    # ============================================================
    # ★★★ v0.2 新增：案例库管理 ★★★
    # ============================================================

    def record_chain(self, chain_id: str, title: str,
                     target: dict, steps: list[dict],
                     chain_type: str = "unknown",
                     tags: Optional[list[str]] = None) -> dict:
        """记录完整攻击链到案例库

        Args:
            chain_id: 唯一标识
            title: 标题
            target: 目标特征 {ip, os, ports, services}
            steps: 步骤列表 [{step_id, name, pattern_id, success, evidence, target_type, parent_step_id}]
            chain_type: 链类型
            tags: 标签列表

        Returns:
            记录结果摘要
        """
        if not self._learning_engine:
            logger.warning("[引擎] 自学习未启用，无法记录案例")
            return {"error": "learning disabled"}

        return self._learning_engine.record_attack_chain(
            chain_id=chain_id,
            title=title,
            target=target,
            steps=steps,
            chain_type=chain_type,
            tags=tags or [],
            source="engine"
        )

    def search_case(self, target_features: dict,
                    top_k: int = 5) -> list[dict]:
        """检索相似历史案例

        Args:
            target_features: 目标特征 {ports, services, os, tags}
            top_k: 返回条数

        Returns:
            匹配案例列表
        """
        if not self._learning_engine:
            return []
        return self._learning_engine.search_similar_chains(target_features, top_k)

    def get_case(self, chain_id: str) -> Optional[dict]:
        """获取单个案例详情"""
        if not self._learning_engine:
            return None
        return self._learning_engine.get_case(chain_id)

    def list_chains(self, chain_type: Optional[str] = None,
                    tag: Optional[str] = None,
                    limit: int = 20) -> list[dict]:
        """列出案例库"""
        if not self._learning_engine:
            return []
        return self._learning_engine.list_chains(chain_type, tag, limit)

    def get_chain_templates(self, min_occurrences: int = 2) -> list[dict]:
        """获取通用攻击链模板"""
        if not self._learning_engine:
            return []
        return self._learning_engine.get_chain_templates(min_occurrences)

    def get_transfer_rate(self, pattern_id: str,
                          from_env: str, to_env: str) -> Optional[float]:
        """查询跨环境迁移率"""
        if not self._learning_engine:
            return None
        return self._learning_engine.get_transfer_rate(pattern_id, from_env, to_env)
