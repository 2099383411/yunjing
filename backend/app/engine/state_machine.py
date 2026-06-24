"""云镜推理引擎 — 四层推理链状态机

基于 v0.2 设计的树形状态机，实现从感知到攻击路径组合的完整推理流程。

状态转换图：
```
PERCEPTION → HYPOTHESIS → VERIFICATION → PATH_COMBINE
    │            │             │              │
    ▼            ▼             ▼              ▼
 扫描目标    生成假设     循环:测试→确认   串联攻击路径
 格式化结果   排序假设     或 测试→否定    计算总置信度
             选择top-K    更新置信度      生成报告
                 │             │
                 ▼             ▼
             前置条件检查  暴露点交叉关联
             环境感知适配  置信度传播
"""
from __future__ import annotations
import logging
from typing import Optional

from .models import (
    EngineState, TargetPerception, AttackHypothesis, HypothesisStatus,
    ScanPhase, AttackPath, AttackPathNode, VerificationStep, PathStatus,
)

logger = logging.getLogger(__name__)


class ReasoningStateMachine:
    """四层推理链状态机"""

    def __init__(self, target: str):
        self.state = EngineState(target=target)
        self._hypothesis_generator = None   # 由外部注入
        self._verification_executor = None  # 由外部注入
        logger.info(f"[引擎] 初始化推理状态机: target={target}")

    # ============================================================
    # Phase 1: 感知层 — 接收扫描结果并结构化
    # ============================================================

    def ingest_perception(self, perception: TargetPerception) -> dict:
        """注入感知结果，触发假设生成"""
        self.state.perception = perception
        self._transition(ScanPhase.PERCEPTION, ScanPhase.HYPOTHESIS)
        
        # 从感知结果提取关键摘要
        summary = {
            "target": perception.target,
            "open_ports": len(perception.open_ports),
            "web_services": len(perception.web_services),
            "creds_found": len(perception.discovered_credentials),
            "files_found": len(perception.accessible_files),
        }
        logger.info(f"[引擎][感知] 完成: {summary}")
        return summary

    # ============================================================
    # Phase 2: 假设层 — 生成并排序攻击假设
    # ============================================================

    def generate_hypotheses(self, generator=None, target_type: str = "common") -> list[AttackHypothesis]:
        """生成攻击假设（支持外部注入生成器）

        Args:
            generator: HypothesisGenerator 实例
            target_type: 目标环境类型，用于自学习调整

        Returns:
            Top-K 待验证假设
        """
        if generator:
            self._hypothesis_generator = generator

        if not self.state.perception:
            raise RuntimeError("感知层尚未完成，无法生成假设")

        perception = self.state.perception
        hypotheses = []

        if self._hypothesis_generator:
            hypotheses = self._hypothesis_generator.generate(perception, target_type)

        # 存储并排序
        self.state.hypotheses = self._sort_hypotheses(hypotheses)
        self.state.active_hypotheses = [
            h for h in self.state.hypotheses
            if h.status == HypothesisStatus.PENDING
        ]
        
        # 按优先级取 Top-K
        top_k = min(10, len(self.state.active_hypotheses))
        top_hypotheses = self.state.active_hypotheses[:top_k]

        logger.info(
            f"[引擎][假设] 生成 {len(hypotheses)} 个假设, "
            f"激活 {len(self.state.active_hypotheses)} 个, "
            f"Top-{top_k} 待验证"
        )
        return top_hypotheses

    def _sort_hypotheses(self, hypotheses: list[AttackHypothesis]) -> list[AttackHypothesis]:
        """按优先级排序假设

        排序公式 S(H) = w₁×C₀ + w₂×I + w₃×D(H) - w₄×E(H) + w₅×U(H)
        当前使用硬编码权重，后期由自学习调整
        """
        weights = {
            "confidence": 0.25,     # 初始置信度
            "impact": 0.30,         # 影响程度
            "dependency": 0.15,     # 前置依赖收益
            "effort": 0.20,         # 努力程度（负向权重）
            "env_fit": 0.10,        # 环境适配因子
        }

        impact_map = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        effort_map = {"low": 1.0, "medium": 0.6, "high": 0.3}

        for h in hypotheses:
            score = (
                weights["confidence"] * h.source_confidence +
                weights["impact"] * impact_map.get(h.impact, 0.5) +
                weights["dependency"] * min(len(h.unlocks) * 0.1, 0.5) -
                weights["effort"] * (1.0 - effort_map.get(h.effort, 0.6)) +
                weights["env_fit"] * (0.5 if h.env_hint else 0.3)
            )
            h.priority_score = round(score, 3)

        return sorted(hypotheses, key=lambda h: h.priority_score, reverse=True)

    # ============================================================
    # Phase 3: 验证层 — 逐一验证假设
    # ============================================================

    def next_hypothesis_to_test(self) -> Optional[AttackHypothesis]:
        """获取下一个待验证的假设"""
        for h in self.state.active_hypotheses:
            if h.status == HypothesisStatus.PENDING:
                # 检查前置依赖
                if h.depends_on:
                    deps_met = all(
                        any(
                            ch.id == dep_id and ch.status == HypothesisStatus.CONFIRMED
                            for ch in self.state.confirmed_hypotheses
                        )
                        for dep_id in h.depends_on
                    )
                    if not deps_met:
                        h.status = HypothesisStatus.PENDING
                        continue
                h.status = HypothesisStatus.TESTING
                return h
        return None

    def update_hypothesis_confidence(
        self, hypothesis_id: str, result: bool, evidence: str = ""
    ) -> float:
        """更新假设置信度（使用指数移动平均）

        C(H, n+1) = C(H, n) + α × (R - C(H, n))
        α = 0.3 (前10次快速学习)
        """
        for h in self.state.hypotheses:
            if h.id == hypothesis_id:
                # 学习率（当前固定为快速学习阶段）
                alpha = 0.3
                
                # 结果映射
                r = 1.0 if result else 0.0
                
                # 更新置信度
                old_c = h.source_confidence
                new_c = old_c + alpha * (r - old_c)
                h.source_confidence = round(new_c, 4)
                h.verification_result = evidence
                
                # 状态更新
                if result:
                    h.status = HypothesisStatus.CONFIRMED
                    self.state.confirmed_hypotheses.append(h)
                else:
                    h.status = HypothesisStatus.REFUTED

                logger.info(
                    f"[引擎][验证] H[{hypothesis_id}] "
                    f"{'✅ 确认' if result else '❌ 否定'} "
                    f"置信度 {old_c:.3f} → {new_c:.3f}"
                )
                return new_c
        return 0.0

    def run_verification_cycle(self) -> int:
        """运行一个完整的验证循环（验证所有可能的假设）"""
        verified_count = 0
        while True:
            h = self.next_hypothesis_to_test()
            if not h:
                break

            if self._verification_executor:
                result, evidence = self._verification_executor.execute(h)
                self.update_hypothesis_confidence(h.id, result, evidence)
                verified_count += 1

        # 验证完成后进入路径组合阶段
        if self.state.confirmed_hypotheses:
            self._transition(ScanPhase.VERIFICATION, ScanPhase.PATH_COMBINE)

        return verified_count

    # ============================================================
    # Phase 4: 攻击路径组合
    # ============================================================

    def compose_attack_paths(self) -> list[AttackPath]:
        """从已确认的假设构建攻击路径"""
        confirmed = self.state.confirmed_hypotheses
        paths = []

        if not confirmed:
            logger.info("[引擎][路径] 无已确认假设，跳过路径组合")
            return paths

        # 按依赖关系构建路径
        # 简单实现: 按依赖→解锁关系串联
        ordered = sorted(confirmed, key=lambda h: h.priority_score, reverse=True)

        current_path = AttackPath(
            id="path-1",
            name=f"主攻击链 (target={self.state.target})",
        )

        for h in ordered:
            node = AttackPathNode(
                asset=self.state.target,
                hypothesis_id=h.id,
                action=h.verification_method,
                result=h.verification_result,
                confidence=h.source_confidence,
            )
            current_path.nodes.append(node)

        # 计算路径总得分
        if current_path.nodes:
            current_path.total_score = round(
                sum(n.confidence for n in current_path.nodes) / len(current_path.nodes),
                3
            )
            current_path.summary = self._generate_path_summary(current_path)

        paths.append(current_path)
        self.state.attack_paths = paths

        logger.info(
            f"[引擎][路径] 构建 {len(paths)} 条攻击路径, "
            f"得分 {current_path.total_score:.3f}"
        )
        return paths

    def _generate_path_summary(self, path: AttackPath) -> str:
        """生成攻击路径的文字摘要"""
        lines = []
        for i, node in enumerate(path.nodes, 1):
            lines.append(f"  {i}. {node.action} → {'✅' if node.confidence > 0.5 else '⚠️'} (置信度: {node.confidence:.2f})")
        return "\n".join(lines)

    # ============================================================
    # 状态管理
    # ============================================================

    def _transition(self, from_phase: ScanPhase, to_phase: ScanPhase):
        """阶段转换"""
        self.state.phase_history.append(self.state.current_phase)
        self.state.current_phase = to_phase
        logger.info(f"[引擎][状态] {from_phase.value} → {to_phase.value}")

    def reset(self):
        """重置状态机"""
        self.state = EngineState(target=self.state.target)
        logger.info("[引擎] 状态机已重置")

    def get_summary(self) -> dict:
        """获取引擎状态摘要"""
        return self.state.summary()
