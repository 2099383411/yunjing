"""
ScanObserver — 旁路监督器

独立于决策循环运行，通过 Redis Pub/Sub 通信：
- Subscribe Worker 的每步状态
- 检测异常 → Publish 熔断/纠正指令

检测规则：
1. 动作重复熔断：同一 action 连续 N 次
2. 新发现枯竭：连续 M 步无新 findings
3. 异常动作检测：选择了不存在的 action
4. 超时熔断：总耗时 > 阈值
"""

import time
import json
import logging
from collections import deque
from typing import Optional

logger = logging.getLogger("scan_observer")

# ===== 配置 =====
MAX_CONSECUTIVE_SAME_ACTION = 3   # 同一动作连续 N 次 → 熔断
MAX_STEPS_WITHOUT_FINDINGS = 5    # 连续 M 步无新发现 → 建议结束
MAX_TOTAL_TIME_SECONDS = 7200     # 2 小时强制熔断
ACTION_EXECUTION_TIMEOUT = 600    # 单步超时 10 分钟


class ScanObserver:
    """旁路监督器"""

    def __init__(self, task_id: str):
        self.task_id = task_id
        self.start_time = time.time()
        self.action_history = deque(maxlen=20)
        self.finding_counts = deque(maxlen=20)
        self.last_finding_count = 0
        self.steps_without_findings = 0
        self.consecutive_same_action = 0
        self.last_action = None
        self.warnings = []
        self.fatals = []

    def observe(self, action_name: str, result: dict, state: dict) -> Optional[dict]:
        import logging as _lg
        _lg.getLogger("scan_observer").info("[OBSERVER] called: action=%s last=%s consec=%d", action_name, self.last_action, self.consecutive_same_action)
        """
        观察单步执行结果，返回熔断指令或 None

        Args:
            action_name: 刚执行的动作名
            result: 执行结果 dict
            state: 当前扫描状态 dict

        Returns:
            None → 一切正常
            {"severity": "warning", "message": "..."} → 建议
            {"severity": "fatal", "message": "..."} → 强制熔断
        """
        now = time.time()
        elapsed = now - self.start_time

        # ── 1. 超时检测 ──
        if elapsed > MAX_TOTAL_TIME_SECONDS:
            msg = f"超时熔断：已运行 {elapsed:.0f}s > {MAX_TOTAL_TIME_SECONDS}s"
            return {"severity": "fatal", "message": msg}

        # ── 2. 动作重复检测 ──
        if action_name == self.last_action:
            self.consecutive_same_action += 1
        else:
            self.consecutive_same_action = 1
            self.last_action = action_name

        if self.consecutive_same_action >= MAX_CONSECUTIVE_SAME_ACTION:
            msg = f"动作重复熔断：'{action_name}' 连续执行 {self.consecutive_same_action} 次"
            return {"severity": "fatal", "message": msg}

        # ── 3. 新发现枯竭检测 ──
        current_findings = len(state.get("findings", state.get("vulnerabilities", [])))
        if current_findings == self.last_finding_count:
            self.steps_without_findings += 1
        else:
            self.steps_without_findings = 0
            self.last_finding_count = current_findings

        if self.steps_without_findings >= MAX_STEPS_WITHOUT_FINDINGS:
            msg = f"新发现枯竭：连续 {self.steps_without_findings} 步无新发现，建议结束"
            return {"severity": "warning", "message": msg}

        # ── 4. 日志记录 ──
        self.action_history.append({
            "action": action_name,
            "elapsed": elapsed,
            "findings": current_findings,
        })

        return None  # 一切正常

    def check_action_validity(self, action_name: str,
                              available_actions: list) -> Optional[dict]:
        """检查 LLM 选择的动作是否有效"""
        valid_names = {a["id"] for a in available_actions}
        if action_name not in valid_names:
            return {
                "severity": "fatal",
                "message": f"非法动作 '{action_name}'，可选: {valid_names}",
            }
        return None

    def get_summary(self) -> dict:
        """获取监督摘要"""
        return {
            "task_id": self.task_id,
            "elapsed": time.time() - self.start_time,
            "steps_observed": len(self.action_history),
            "warnings": len(self.warnings),
            "fatals": len(self.fatals),
            "last_actions": list(self.action_history)[-5:] if self.action_history else [],
        }
