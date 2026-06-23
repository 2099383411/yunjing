"""云镜推理引擎 — 数据模型

推理引擎的核心数据模型，定义目标感知、假设生成、攻击路径、
状态机的标准数据结构。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ============================================================
# 枚举类型
# ============================================================

class ScanPhase(Enum):
    """推理链的四个阶段"""
    PERCEPTION = "perception"       # Layer 1: 目标感知
    HYPOTHESIS = "hypothesis"       # Layer 2: 信任假设
    VERIFICATION = "verification"   # Layer 3: 攻击方向验证
    PATH_COMBINE = "path_combine"   # Layer 4: 攻击路径组合


class HypothesisStatus(Enum):
    """假设状态"""
    PENDING = "pending"           # 待验证
    TESTING = "testing"           # 验证中
    CONFIRMED = "confirmed"       # 已确认
    REFUTED = "refuted"           # 已否定
    PARTIAL = "partial"           # 部分确认


class PathStatus(Enum):
    """攻击路径状态"""
    ACTIVE = "active"             # 活跃路径
    BLOCKED = "blocked"           # 被阻断
    COMPLETED = "completed"       # 已完成
    ABANDONED = "abandoned"       # 已放弃


class TrustLevel(Enum):
    """信源可靠性等级"""
    CONFIRMED = 1.0               # 直接确认（如SSH登录成功）
    HIGH = 0.8                    # 高度可信（如明文读取）
    MEDIUM = 0.5                  # 中等可信（如扫描发现）
    LOW = 0.2                     # 低可信（如推测）
    SPECULATIVE = 0.05            # 推测（任意猜测）


# ============================================================
# 感知层模型 (Layer 1)
# ============================================================

@dataclass
class PortInfo:
    """端口信息"""
    port: int
    protocol: str = "tcp"         # tcp / udp
    service: str = ""             # 服务名称 (如 http, ssh, redis)
    service_version: str = ""     # 服务版本
    state: str = "open"           # open / filtered / closed
    banner: str = ""              # 服务Banner
    confidence: float = 0.5       # 识别置信度


@dataclass
class WebInfo:
    """Web 服务信息"""
    url: str
    title: str = ""               # HTML Title
    server: str = ""              # Server header
    status_code: int = 0
    technologies: list[str] = field(default_factory=list)  # 技术栈
    security_headers: dict = field(default_factory=dict)   # 安全头
    cookies: list[dict] = field(default_factory=list)       # Cookie 信息
    forms: list[dict] = field(default_factory=list)        # 表单端点


@dataclass
class FileInfo:
    """文件系统信息"""
    path: str
    accessible: bool = False
    content_hint: str = ""        # 内容类型描述
    size: int = 0


@dataclass
class CredentialInfo:
    """已发现的凭据"""
    source: str                   # 来源 (如 "kdbx", "browser", "config")
    username: str = ""
    password: str = ""
    host: str = ""                # 关联主机
    service_type: str = ""        # 服务类型
    confidence: float = 0.5


@dataclass
class TargetPerception:
    """目标感知结果（Layer 1 输出）"""
    target: str                   # 目标 IP/Domain
    hostname: str = ""
    os_info: str = ""
    open_ports: list[PortInfo] = field(default_factory=list)
    web_services: list[WebInfo] = field(default_factory=list)
    accessible_files: list[FileInfo] = field(default_factory=list)
    discovered_credentials: list[CredentialInfo] = field(default_factory=list)
    network_info: dict = field(default_factory=dict)        # 网络拓扑
    security_config: dict = field(default_factory=dict)     # 安全配置标记
    raw_findings: list[dict] = field(default_factory=list)  # 原始发现
    metadata: dict = field(default_factory=dict)


# ============================================================
# 假设层模型 (Layer 2)
# ============================================================

@dataclass
class AttackHypothesis:
    """攻击假设"""
    id: str = ""
    name: str = ""                # 假设名称
    description: str = ""         # 详细描述
    pattern_id: str = ""          # 关联的攻击模式ID（用于自学习）
    
    # 从哪里推导
    source_principle: str = ""    # 底层原理依据
    source_attack_surface: str = ""  # 攻击面依据
    source_confidence: float = 0.3    # 初始置信度
    
    # 优先级排序
    priority_score: float = 0.0   # 综合评分 S(H)
    impact: str = "medium"        # low/medium/high/critical
    effort: str = "medium"        # low/medium/high
    
    # 依赖关系
    depends_on: list[str] = field(default_factory=list)  # 前置假设ID
    unlocks: list[str] = field(default_factory=list)     # 解锁的后置假设
    
    # 验证状态
    status: HypothesisStatus = HypothesisStatus.PENDING
    verification_method: str = ""  # 验证方法描述
    verification_result: str = ""  # 验证结果详情
    
    # 环境感知
    env_hint: str = ""            # "container" / "vm" / "physical" / "windows"


@dataclass
class HypothesisGroup:
    """假设分组（按攻击面分类）"""
    category: str                 # 攻击面类别
    hypotheses: list[AttackHypothesis] = field(default_factory=list)
    average_confidence: float = 0.0


# ============================================================
# 验证层模型 (Layer 3)
# ============================================================

@dataclass
class VerificationStep:
    """验证步骤"""
    hypothesis_id: str
    tool: str                     # 使用的工具 (如 "nmap", "curl", "sqlmap")
    command: str                  # 执行的命令
    args: dict = field(default_factory=dict)  # 参数
    expected_result: str = ""
    actual_result: str = ""
    success: bool = False
    evidence: str = ""            # 证据
    confidence_update: float = 0.0  # 置信度更新值


# ============================================================
# 攻击路径模型 (Layer 4)
# ============================================================

@dataclass
class AttackPathNode:
    """攻击路径节点"""
    asset: str                    # 资产标识
    hypothesis_id: str = ""       # 关联假设
    action: str = ""              # 动作描述
    credential_used: str = ""     # 使用的凭据
    result: str = ""              # 结果
    confidence: float = 0.0


@dataclass
class AttackPath:
    """完整攻击路径"""
    id: str = ""
    name: str = ""
    nodes: list[AttackPathNode] = field(default_factory=list)
    total_score: float = 0.0
    status: PathStatus = PathStatus.ACTIVE
    summary: str = ""


# ============================================================
# 引擎状态
# ============================================================

@dataclass
class EngineState:
    """推理引擎完整状态"""
    target: str
    perception: Optional[TargetPerception] = None
    hypotheses: list[AttackHypothesis] = field(default_factory=list)
    active_hypotheses: list[AttackHypothesis] = field(default_factory=list)
    confirmed_hypotheses: list[AttackHypothesis] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    current_phase: ScanPhase = ScanPhase.PERCEPTION
    phase_history: list[ScanPhase] = field(default_factory=list)
    
    def summary(self) -> dict:
        """返回引擎状态的简要摘要"""
        return {
            "target": self.target,
            "current_phase": self.current_phase.value,
            "total_hypotheses": len(self.hypotheses),
            "confirmed": len([h for h in self.hypotheses if h.status == HypothesisStatus.CONFIRMED]),
            "refuted": len([h for h in self.hypotheses if h.status == HypothesisStatus.REFUTED]),
            "testing": len([h for h in self.hypotheses if h.status == HypothesisStatus.TESTING]),
            "attack_paths": len(self.attack_paths),
            "phase_history": [p.value for p in self.phase_history],
        }

# ============================================================
# 攻击链模型 (v0.2 新增)
# ============================================================

@dataclass
class AttackChainStep:
    """攻击链中的一步"""
    step_id: str                        # 步骤唯一标识
    name: str                           # 步骤名称 (如 "everything-http-discovery")
    description: str                    # 人类可读描述
    pattern_id: str                     # 攻击模式 ID (如 "everything-http")
    success: bool                       # 是否成功
    evidence: str                       # 关键证据描述
    target_addr: str                    # 当前步骤作用的目标地址
    target_type: str = "unknown"        # 目标环境类型 (linux/windows/container/ztna)
    parent_step_id: Optional[str] = None  # 依赖的上一步
    confidence: float = 0.5             # 该步骤的置信度
    metadata: dict = field(default_factory=dict)  # 额外信息


@dataclass
class AttackChain:
    """完整攻击链"""
    chain_id: str                       # 唯一标识
    title: str                          # 人类可读标题
    target_ip: str                      # 目标 IP
    target_os: str = ""                 # 目标操作系统
    target_ports: list[int] = field(default_factory=list)    # 目标开放端口
    target_services: list[str] = field(default_factory=list) # 目标服务
    chain_type: str = "unknown"         # 链类型 (如 "web->container->host")
    steps: list[AttackChainStep] = field(default_factory=list)  # 步骤列表
    source: str = "imported"           # 来源 (manual/engine/imported)
    tags: list[str] = field(default_factory=list)    # 标签
    created_at: float = 0.0             # 创建时间戳

    @property
    def total_steps(self) -> int:
        return len(self.steps)

    @property
    def success_steps(self) -> int:
        return sum(1 for s in self.steps if s.success)

    @property
    def overall_success(self) -> float:
        return self.success_steps / self.total_steps if self.total_steps > 0 else 0.0

    def to_dict(self) -> dict:
        """转为字典，用于 JSON 序列化"""
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "target": {
                "ip": self.target_ip,
                "os": self.target_os,
                "ports": self.target_ports,
                "services": self.target_services,
            },
            "steps": [
                {
                    "step_id": s.step_id,
                    "name": s.name,
                    "description": s.description,
                    "pattern_id": s.pattern_id,
                    "success": s.success,
                    "evidence": s.evidence,
                    "target_addr": s.target_addr,
                    "target_type": s.target_type,
                    "parent_step_id": s.parent_step_id,
                    "confidence": s.confidence,
                }
                for s in self.steps
            ],
            "chain_type": self.chain_type,
            "source": self.source,
            "tags": self.tags,
            "created_at": self.created_at or __import__("time").time(),
        }
