"""云镜推理引擎 — LLM 假设生成器

当规则引擎覆盖不到的领域，由 LLM 根据感知结果动态推断新假设。
与规则引擎的假设合并去重后，进入统一排序流程。

设计原则：
1. LLM 生成的是「补充假设」— 规则引擎优先，LLM 兜底
2. Prompt 包含完整感知上下文 + 已知攻击模式（避免重复）
3. 输出格式为结构化 JSON，由 HypothesisGenerator.llm_generator 回调
"""
from __future__ import annotations
import json
import logging
from typing import Optional

from .models import (
    TargetPerception, AttackHypothesis, HypothesisStatus,
)

logger = logging.getLogger(__name__)

# ============================================================
# Prompt 模板
# ============================================================

SYSTEM_PROMPT = """你是一个渗透测试推理专家。你的任务是根据目标感知数据，生成攻击假设。

## 规则
1. 只输出 JSON 数组，不要多余内容
2. 每条假设包含：name, description, principle, impact, effort, verification_method
3. impact: critical/high/medium/low
4. effort: low/medium/high
5. 基于底层原理推导，不要依赖已知 CVE 或 PoC
6. 避免与规则引擎已有的通用假设重复（Web注入、SSH爆破、Redis未授权、SMB、数据库弱口令等）
7. 重点发现「非常规」攻击面、组合攻击路径、配置疏忽

## 输出格式
```json
[
  {{
    "name": "假设简短名称",
    "description": "详细描述",
    "principle": "底层原理依据",
    "impact": "critical",
    "effort": "medium",
    "verification_method": "验证方法描述",
    "source_confidence": 0.5
  }}
]
```"""


def _build_user_prompt(perception: TargetPerception) -> str:
    """构建用户提示（包含感知数据）"""
    lines = ["## 目标感知数据", f"目标: {perception.target}"]
    if perception.hostname:
        lines.append(f"主机名: {perception.hostname}")
    if perception.os_info:
        lines.append(f"操作系统: {perception.os_info}")

    # 开放的端口
    if perception.open_ports:
        lines.append("\n### 开放端口")
        for info in perception.open_ports:
            svc = f"{info.service} {info.service_version}" if info.service_version else info.service
            lines.append(f"  - {info.port}/{info.protocol}: {svc} ({info.state})")
            if info.banner:
                lines.append(f"    Banner: {info.banner[:100]}")

    # Web 服务
    if perception.web_services:
        lines.append("\n### Web 服务")
        for w in perception.web_services:
            techs = ", ".join(w.technologies) if w.technologies else "未知"
            lines.append(f"  - {w.url} [{w.status_code}] {w.title}")
            lines.append(f"    技术栈: {techs}")

    # 文件系统
    if perception.accessible_files:
        lines.append("\n### 可访问文件")
        for f in perception.accessible_files:
            lines.append(f"  - {f.path} ({'可读' if f.accessible else '受限'})")

    # 凭据
    if perception.discovered_credentials:
        lines.append("\n### 已发现凭据")
        for c in perception.discovered_credentials:
            lines.append(f"  - {c.source}: {c.username}@{c.host} ({c.service_type})")

    lines.append("\n请根据以上信息，推断最可能的非常规攻击假设（2-5个）。")
    return "\n".join(lines)


# ============================================================
# 解析器
# ============================================================

def _parse_llm_response(text: str) -> list[dict]:
    """解析 LLM 响应中的 JSON"""
    # 尝试提取 JSON 块
    try:
        # 查找 ```json ... ``` 或直接 JSON 数组
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]

        data = json.loads(text.strip())
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "hypotheses" in data:
            return data["hypotheses"]
        return [data]
    except (json.JSONDecodeError, IndexError, TypeError) as e:
        logger.warning(f"[LLM生成器] JSON 解析失败: {e}, 原始文本: {text[:200]}")
        return []


def _to_hypothesis(raw: dict) -> Optional[AttackHypothesis]:
    """将 LLM 输出转为 AttackHypothesis 对象"""
    try:
        name = raw.get("name", "").strip()
        if not name:
            return None

        # 从名称推断 pattern_id
        pattern_id = _infer_pattern_id_from_name(name)

        return AttackHypothesis(
            name=name,
            pattern_id=pattern_id,
            description=raw.get("description", ""),
            source_principle=raw.get("principle", ""),
            source_attack_surface="llm-generated",
            source_confidence=min(float(raw.get("source_confidence", 0.3)), 1.0),
            impact=raw.get("impact", "medium"),
            effort=raw.get("effort", "medium"),
            verification_method=raw.get("verification_method", ""),
            status=HypothesisStatus.PENDING,
        )
    except (ValueError, TypeError) as e:
        logger.warning(f"[LLM生成器] 假设解析失败: {e}, 原始: {raw}")
        return None


def _infer_pattern_id_from_name(name: str) -> str:
    """从假设名称推断 pattern_id"""
    name_lower = name.lower()
    mapping = [
        ("injection", "web-injection"), ("xss", "web-injection"),
        ("csrf", "web-injection"), ("web", "web-injection"),
        ("ssh", "ssh-breach"),
        ("redis", "redis-noauth"),
        ("mysql", "db-weak-cred"), ("postgres", "db-weak-cred"),
        ("database", "db-weak-cred"),
        ("smb", "smb-anonymous"),
        ("everything", "everything-http"),
        ("container", "container-escape"), ("docker", "container-escape"),
        ("ztna", "ztna-attack"), ("headscale", "ztna-attack"),
        ("browser", "browser-password"),
        ("keepass", "keepass-crack"), ("kdbx", "keepass-crack"),
        ("cred", "cred-reuse"), ("password", "cred-reuse"),
        ("firewall", "fw-management"), ("nsg", "fw-management"),
        ("sunlogin", "sunlogin-breach"), ("向日葵", "sunlogin-breach"),
        ("finalshell", "finalshell-config"),
        ("celery", "container-escape"), ("redis", "redis-noauth"),
        ("php", "web-injection"),
    ]
    for keyword, pid in mapping:
        if keyword in name_lower:
            return pid
    return "custom-llm"


# ============================================================
# LLM 生成器工厂
# ============================================================

def create_llm_generator(adapter=None):
    """创建 LLM 假设生成器回调函数

    Args:
        adapter: LLMAdapter 实例（不传则尝试自动创建）

    Returns:
        callable: async function(perception) -> list[AttackHypothesis]
    """
    async def llm_generator(perception: TargetPerception) -> list[AttackHypothesis]:
        """LLM 假设生成器"""
        try:
            # 延迟导入避免循环依赖
            if adapter is None:
                from app.llm.adapter import llm_adapter as _adapter
            else:
                _adapter = adapter

            # 构造 prompt
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(perception)},
            ]

            logger.info(f"[LLM生成器] 发送请求: target={perception.target}")
            response = await _adapter.chat(
                messages=messages,
                temperature=0.3,
                max_tokens=2000,
            )

            # 提取文本
            content = (response.get("choices", [{}])[0]
                       .get("message", {})
                       .get("content", ""))
            if not content:
                logger.warning("[LLM生成器] 响应为空")
                return []

            # 解析
            raw_list = _parse_llm_response(content)
            hypotheses = []
            for raw in raw_list:
                h = _to_hypothesis(raw)
                if h:
                    hypotheses.append(h)

            logger.info(f"[LLM生成器] 生成 {len(hypotheses)} 个假设")
            return hypotheses

        except Exception as e:
            logger.error(f"[LLM生成器] 异常: {e}", exc_info=True)
            return []

    return llm_generator
