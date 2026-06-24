"""
云镜推理引擎 — 假设驱动扫描桥接器 v0.1

生命线：AttackHypothesis -> 具体扫描动作 -> Worker 执行 -> 结果回灌

设计哲学：
  - 每个假设都试图被验证，不是盲目扫，是带着推理去验证
  - 高置信度的假设扫快点（quick），低置信度的扫全点（full）
  - 结果回灌是灵魂——验证了的假设 confidence++，被打脸的 confidence--
"""
from __future__ import annotations
import json
import os
import logging
import uuid
from typing import Optional
from celery import Celery

from .models import AttackHypothesis, HypothesisStatus

logger = logging.getLogger(__name__)

# Celery 客户端 — 发任务到 Worker
CELERY_BROKER = os.environ.get("REDIS_URL", "redis://redis:6379/1")
celery_app = Celery("yunjing", broker=CELERY_BROKER)
EXECUTE_SCAN_TASK = "tasks.scan_tasks.execute_scan"

# --- 假设 -> 扫描工具映射表 -----------------------------------
# 格式: (关键词列表) -> {tool, phase, cmd_template, description}
HYPOTHESIS_SCAN_MAP = [
    # -- Web 类 --
    {
        "keywords": ["web", "注入", "xss", "csrf", "rce", "upload", "ssrf",
                     "cors", "api", "目录遍历", "lfi", "rfi"],
        "scan_type": "web",
        "phase": "web_vuln",
        "description": "Web 应用漏洞扫描",
    },
    # -- SSH 类 --
    {
        "keywords": ["ssh", "弱密码", "弱口令", "默认口令", "默认密码",
                     "brute force", "暴力破解"],
        "scan_type": "exploit",
        "phase": "bruteforce",
        "description": "SSH 暴力破解/弱口令检测",
    },
    # -- 数据库类 --
    {
        "keywords": ["mysql", "postgresql", "redis", "mongo", "database",
                     "数据库", "sql注入", "sql injection"],
        "scan_type": "exploit",
        "phase": "db_scan",
        "description": "数据库服务安全检测",
    },
    # -- SMB 类 --
    {
        "keywords": ["smb", "samba", "cifs", "netbios", "wins"],
        "scan_type": "exploit",
        "phase": "smb_scan",
        "description": "SMB 协议安全检测",
    },
    # -- 认证绕过类 --
    {
        "keywords": ["认证绕过", "auth bypass", "jwt", "oauth", "session",
                     "2fa", "otp"],
        "scan_type": "web",
        "phase": "auth_bypass",
        "description": "认证绕过漏洞检测",
    },
    # -- 容器逃逸类 --
    {
        "keywords": ["容器逃逸", "container escape", "docker escape",
                     "特权容器", "privileged"],
        "scan_type": "exploit",
        "phase": "container_escape",
        "description": "容器逃逸漏洞检测",
    },
    # -- 信息泄露类 --
    {
        "keywords": ["信息泄露", "信息收集", "敏感信息", "暴露",
                     "everything", "file disclosure", "目录泄露"],
        "scan_type": "quick",
        "phase": "info_leak",
        "description": "敏感信息泄露检测",
    },
    # -- 防火墙/云组类 --
    {
        "keywords": ["防火墙", "firewall", "nsg", "云组", "acl",
                     "port暴露", "端口暴露", "端口开放"],
        "scan_type": "quick",
        "phase": "port_scan",
        "description": "端口暴露与网络安全组检测",
    },
    # -- 密码复用类 --
    {
        "keywords": ["密码复用", "密码重用", "cred reuse", "password reuse",
                     "lateral", "横向移动"],
        "scan_type": "exploit",
        "phase": "lateral",
        "description": "密码复用/横向移动检测",
    },
    # -- 浏览器密码导出类 --
    {
        "keywords": ["浏览器密码", "browser password", "chrome password",
                     "凭证导出", "凭据导出"],
        "scan_type": "exploit",
        "phase": "credential_dump",
        "description": "浏览器凭证导出检测",
    },
    # -- 默认兜底 --
    {
        "keywords": [],
        "scan_type": "full",
        "phase": "full",
        "description": "全面扫描",
    },
]

class HypothesisScanner:
    """假设驱动扫描桥接器"""

    def __init__(self, storage_path: str = "", learning_engine=None):
        self._storage_path = storage_path
        self._learning = learning_engine

    # ========================================================
    #  假设 -> 扫描映射
    # ========================================================

    def map_hypothesis(self, hypothesis: AttackHypothesis) -> dict:
        """将单个假设映射为扫描配置"""
        name_lower = hypothesis.name.lower()
        desc_lower = hypothesis.description.lower()
        verification_lower = hypothesis.verification_method.lower()
        combined = f"{name_lower} {desc_lower} {verification_lower}"

        for rule in HYPOTHESIS_SCAN_MAP:
            if not rule["keywords"]:
                continue  # skip the default catch-all
            if any(kw in combined for kw in rule["keywords"]):
                return {
                    "scan_type": rule["scan_type"],
                    "phase": rule["phase"],
                    "description": rule["description"],
                    "priority": hypothesis.priority_score,
                    "effort": hypothesis.effort,
                }

        # Fallback to default
        default = HYPOTHESIS_SCAN_MAP[-1]
        return {
            "scan_type": default["scan_type"],
            "phase": default["phase"],
            "description": default["description"],
            "priority": hypothesis.priority_score,
            "effort": hypothesis.effort,
        }

    def map_hypotheses(self, hypotheses: list[AttackHypothesis]) -> list[dict]:
        """批量映射假设 -> 扫描配置"""
        return [self.map_hypothesis(h) for h in hypotheses]

    # ========================================================
    #  假设执行
    # ========================================================

    def execute_hypothesis(self, hypothesis: AttackHypothesis,
                           target: str,
                           conversation_id: str = "") -> str:
        """执行单个假设：创建扫描任务，发送到 Worker

        Returns:
            task_id: Celery 任务 ID
        """
        scan_config = self.map_hypothesis(hypothesis)
        task_id = f"hyp-{uuid.uuid4().hex[:12]}"

        logger.info(
            f"[假设扫描] {hypothesis.name} -> {scan_config['scan_type']}/"
            f"{scan_config['phase']}, target={target}, task_id={task_id}"
        )

        # 发到 Worker
        celery_app.send_task(
            EXECUTE_SCAN_TASK,
            args=[task_id, target, scan_config["scan_type"]],
            queue="scan",
        )

        return task_id

    def execute_hypotheses(self, hypotheses: list[AttackHypothesis],
                           target: str,
                           conversation_id: str = "",
                           max_concurrent: int = 3) -> list[dict]:
        """批量按优先级执行假设

        排序策略：
        1. 按 priority_score 降序
        2. 依赖关系：depends_on 不冲突就并行
        3. 高置信度的优先

        Returns:
            [{hypothesis_id, task_id, scan_type, phase, status}]
        """
        # 排序
        sorted_h = sorted(hypotheses,
                         key=lambda h: h.priority_score,
                         reverse=True)

        results = []
        # 按置信度分级
        high_prio = []
        normal_prio = []

        for h in sorted_h:
            if h.priority_score >= 0.7:
                high_prio.append(h)
            else:
                normal_prio.append(h)

        # 优先执行高置信度假设
        for h_list, tier in [(high_prio, "high"), (normal_prio, "normal")]:
            for i, h in enumerate(h_list):
                if i >= max_concurrent:
                    break
                task_id = self.execute_hypothesis(h, target, conversation_id)
                h.status = HypothesisStatus.TESTING
                results.append({
                    "hypothesis_id": h.id,
                    "hypothesis_name": h.name,
                    "task_id": task_id,
                    "scan_type": self.map_hypothesis(h)["scan_type"],
                    "phase": self.map_hypothesis(h)["phase"],
                    "priority_score": h.priority_score,
                    "tier": tier,
                })

        logger.info(
            f"[假设扫描] 已调度 {len(results)}/{len(hypotheses)} 个假设"
            f" (high={len(high_prio)}, normal={len(normal_prio)})"
        )
        return results

    # ========================================================
    #  结果回灌
    # ========================================================

    def feed_back(self, hypothesis: AttackHypothesis,
                  scan_success: bool,
                  findings: list[dict] = None) -> dict:
        """扫描结果回灌

        规则：
        - 发现漏洞 -> 置信度 += 0.2（封顶 0.95）
        - 没发现漏洞 -> 置信度 -= 0.1（保底 0.05）
        - 漏洞数量多 -> 额外 +0.05
        - 高危漏洞 -> 额外 +0.05
        """
        findings = findings or []
        adjustment = {"delta": 0.0, "reason": ""}

        vuln_count = len(findings)
        has_critical = any(f.get("severity", "") in ("critical", "high")
                          for f in findings)

        if scan_success and vuln_count > 0:
            delta = 0.2
            reasons = ["发现漏洞"]
            if vuln_count >= 3:
                delta += 0.05
                reasons.append("多个漏洞")
            if has_critical:
                delta += 0.05
                reasons.append("高危漏洞")
            hypothesis.source_confidence = min(
                0.95, hypothesis.source_confidence + delta
            )
            adjustment = {"delta": delta, "reason": " + ".join(reasons)}
        elif scan_success:
            delta = -0.1
            hypothesis.source_confidence = max(
                0.05, hypothesis.source_confidence + delta
            )
            adjustment = {"delta": delta, "reason": "扫描完成未发现漏洞"}

        hypothesis.status = (HypothesisStatus.CONFIRMED
                            if hypothesis.source_confidence >= 0.5
                            else HypothesisStatus.REFUTED)

        # 持久化到 learning_data.json
        if self._learning:
            self._learning.record_result(
                hypothesis=hypothesis,
                success=(hypothesis.status == HypothesisStatus.CONFIRMED),
                target_type=hypothesis.source_attack_surface.split(":")[0].split("/")[0] if hypothesis.source_attack_surface else "unknown",
            )
            # 同时记录详细经验（LLM RAG 可用）
            target_info = {
                "type": hypothesis.source_attack_surface.split("/")[0] if hypothesis.source_attack_surface else "unknown",
                "name": hypothesis.source_attack_surface or ""
            }
            signals = []
            if hypothesis.source_attack_surface:
                signals.append({"type": "target", "value": hypothesis.source_attack_surface,
                               "reason": f"自动扫描目标: {hypothesis.source_attack_surface}"})
            verification_info = {
                "method": hypothesis.verification_method or "自动扫描",
                "payload": "",
                "expected": "",
                "actual": f"发现 {len(findings)} 个结果",
                "confirmed": scan_success and vuln_count > 0
            }
            exploitation = []
            for f_item in findings:
                exploitation.append({
                    "action": f_item.get("title", "未知"),
                    "result": f_item.get("severity", "info"),
                    "success": True
                })
            self._learning.record_experience(
                hypothesis={
                    "name": hypothesis.name or hypothesis.pattern_id or "unknown",
                    "pattern_id": hypothesis.pattern_id or (hypothesis.source_attack_surface.split("/")[-1].replace(".md","") if hypothesis.source_attack_surface else "unknown"),
                    "target": hypothesis.source_attack_surface or "",
                    "confidence": hypothesis.source_confidence
                },
                target=target_info,
                reasoning_path=[f"自动扫描 -> {hypothesis.name} -> {'成功' if scan_success and vuln_count > 0 else '未发现'}"],
                verification=verification_info,
                signals=signals,
                exploitation=exploitation,
                success=scan_success and vuln_count > 0,
                duration=0.0
            )

        return {
            "hypothesis_id": hypothesis.id,
            "confidence_before": hypothesis.source_confidence - adjustment["delta"],
            "confidence_after": hypothesis.source_confidence,
            "adjustment": adjustment,
            "status": hypothesis.status.value,
        }
