"""
攻击状态管理器 (Attack State Manager)
======================================
管理渗透过程中"已知什么、拥有什么、尝试过什么"的状态。

核心数据结构：
  - DiscoveredAssets:   已发现的IP/域名/端口/服务
  - CapturedCredentials: 已获取的凭据/session/cookie
  - SuccessfulExploits:  成功的突破点
  - FailedAttempts:      失败的尝试（防重复）
  - AttackPath:          攻击链路径记录

参考: VulnClaw target_state/store.py + agent/context.py
"""

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Asset:
    """发现的资产"""
    ip: str = ""
    hostname: str = ""
    ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    os_info: str = ""
    notes: str = ""


@dataclass
class Credential:
    """获取的凭据"""
    target: str = ""
    username: str = ""
    password: str = ""
    source: str = ""          # 怎么拿到的 (brute/leak/misconfig)
    confidence: float = 0.5   # 0-1
    verified: bool = False
    notes: str = ""


@dataclass
class Exploit:
    """成功的漏洞利用"""
    target: str = ""
    vuln_type: str = ""       # SQL注入 / 文件上传 / RCE
    tool_used: str = ""
    detail: str = ""
    outcome: str = ""          # 拿到shell / 读取文件 / 提取数据
    cve: str = ""
    severity: str = "medium"
    timestamp: float = 0.0


@dataclass
class FailedAttempt:
    """失败的尝试"""
    target: str = ""
    action: str = ""           # 试图做什么
    reason: str = ""           # 为什么失败
    timestamp: float = 0.0


@dataclass
class AttackStep:
    """攻击链中的一步"""
    step_id: int = 0
    action: str = ""           # nmap扫描 / sqlmap注入 / 上传shell
    target: str = ""
    tool: str = ""
    params: dict = field(default_factory=dict)
    result_summary: str = ""
    findings: list = field(default_factory=list)
    reasoning: str = ""        # LLM决策理由
    timestamp: float = 0.0
    success: bool = False


class AttackState:
    """
    攻击状态 — 整个渗透过程中的状态中枢
    
    用法:
        state = AttackState(target="192.168.1.100")
        state.add_asset(Asset(ip="192.168.1.100", ports=[80, 443]))
        state.add_credential(Credential(target="192.168.1.100", username="admin", password="admin"))
        state.add_step(AttackStep(action="nmap_scan", target="192.168.1.100", success=True))
        summary = state.summarize()  # → LLM能读懂的当前状态描述
    """
    
    def __init__(self, target: str = "", task_id: str = "", max_history: int = 50):
        self.target = target
        self.task_id = task_id
        self.start_time = time.time()
        self.max_history = max_history
        
        # 核心状态
        self.assets: list[Asset] = []
        self.credentials: list[Credential] = []
        self.exploits: list[Exploit] = []
        self.failed_attempts: list[FailedAttempt] = []
        self.attack_chain: list[AttackStep] = []
        
        # 进度标记
        self.current_phase: str = "init"
        self.consecutive_stale_rounds: int = 0  # 连续无新发现的轮数
        self.last_new_finding_time: float = time.time()
        self.overall_progress: float = 0.0
    
    # ─── 添加状态 ───────────────────────────────────────
    
    def add_asset(self, asset: Asset):
        """添加或更新资产"""
        existing = [a for a in self.assets if a.ip == asset.ip]
        if existing:
            idx = self.assets.index(existing[0])
            existing_a = existing[0]
            # 合并端口
            existing_a.ports = list(set(existing_a.ports + asset.ports))
            # 合并服务
            existing_services = {s.get("port", s.get("name", "")): s for s in existing_a.services}
            for s in asset.services:
                key = s.get("port", s.get("name", ""))
                existing_services[key] = s
            existing_a.services = list(existing_services.values())
            if asset.os_info:
                existing_a.os_info = asset.os_info
            existing_a.notes = asset.notes or existing_a.notes
            self.assets[idx] = existing_a
        else:
            self.assets.append(asset)
        self._on_new_finding()
    
    def add_credential(self, cred: Credential):
        """添加凭据"""
        # 去重
        for c in self.credentials:
            if c.target == cred.target and c.username == cred.username:
                return
        cred.timestamp = time.time()
        self.credentials.append(cred)
        self._on_new_finding()
    
    def add_exploit(self, exploit: Exploit):
        """记录成功利用"""
        exploit.timestamp = time.time()
        self.exploits.append(exploit)
        self._on_new_finding()
    
    def add_failed_attempt(self, action: str, target: str, reason: str):
        """记录失败尝试"""
        self.failed_attempts.append(FailedAttempt(
            target=target, action=action, reason=reason, timestamp=time.time()
        ))
    
    def add_step(self, step: AttackStep):
        """添加攻击步骤"""
        step.timestamp = time.time()
        self.attack_chain.append(step)
        if len(self.attack_chain) > self.max_history:
            self.attack_chain = self.attack_chain[-self.max_history:]
    
    def _on_new_finding(self):
        """发现新东西时重置连续无新发现计数器"""
        self.consecutive_stale_rounds = 0
        self.last_new_finding_time = time.time()
    
    def mark_no_new_finding(self):
        """一轮没有新发现时调用"""
        self.consecutive_stale_rounds += 1
    
    def is_stale(self, threshold: int = 5) -> bool:
        """检查是否陷入死循环（参考VulnClaw stale_rounds_threshold）"""
        return self.consecutive_stale_rounds >= threshold
    
    def time_since_last_finding(self) -> float:
        return time.time() - self.last_new_finding_time
    
    # ─── 状态序列化 ─────────────────────────────────────
    
    def summarize(self) -> str:
        """生成当前状态的文本摘要 — 给LLM看的"""
        parts = []
        parts.append(f"## 当前状态 (目标: {self.target})")
        parts.append(f"阶段: {self.current_phase} | 已用时间: {int(time.time() - self.start_time)}s")
        parts.append(f"连续无新发现: {self.consecutive_stale_rounds}/{self.max_history} 轮")
        parts.append(f"整体进度: {self.overall_progress:.0%}")
        
        # 资产
        if self.assets:
            parts.append(f"\n### 已发现资产 ({len(self.assets)}个)")
            for a in self.assets:
                ports = ",".join(str(p) for p in a.ports[:10])
                services = "; ".join(
                    f"{s.get('port','')}/{s.get('service', s.get('name',''))} {s.get('version','')}" 
                    for s in a.services[:5]
                )
                parts.append(f"- {a.ip} [{ports}] {a.os_info}")
                if services:
                    parts.append(f"  服务: {services}")
        
        # 凭据
        if self.credentials:
            parts.append(f"\n### 已获取凭据 ({len(self.credentials)}个)")
            for c in self.credentials[-5:]:
                stars = "*" * len(c.password) if c.password else "(空)"
                parts.append(f"- {c.target} | {c.username}:{stars} [来源:{c.source}]")
        
        # 成功利用
        if self.exploits:
            parts.append(f"\n### 成功利用 ({len(self.exploits)}个)")
            for e in self.exploits[-5:]:
                parts.append(f"- {e.target} | {e.vuln_type} → {e.outcome}")
        
        # 失败尝试
        if self.failed_attempts:
            parts.append(f"\n### 失败尝试 ({len(self.failed_attempts)}个)")
            for f in self.failed_attempts[-5:]:
                parts.append(f"- {f.target} | {f.action}: {f.reason}")
        
        # 攻击链
        if self.attack_chain:
            parts.append(f"\n### 攻击链 ({len(self.attack_chain)}步)")
            for s in self.attack_chain[-10:]:
                mark = "✅" if s.success else "❌"
                parts.append(f"- {mark} {s.action} → {s.result_summary[:80]}")
        
        return "\n".join(parts)
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "task_id": self.task_id,
            "current_phase": self.current_phase,
            "consecutive_stale_rounds": self.consecutive_stale_rounds,
            "assets": len(self.assets),
            "credentials": len(self.credentials),
            "exploits": len(self.exploits),
            "failed_attempts": len(self.failed_attempts),
            "attack_chain_steps": len(self.attack_chain),
            "overall_progress": self.overall_progress,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
