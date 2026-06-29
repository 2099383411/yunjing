import os
"""
云镜 Agent — AI 智能体编排引擎 V2
技能感知 + 深度意图识别 + 动态 DAG 编排 + 红线安全规则
"""
import json
import os
import re
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from openai import AsyncOpenAI
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("yunjing-agent")

# ── 配置 ──────────────────────────────────────────────────
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.deepseek.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")

# ── FastAPI ───────────────────────────────────────────────
app = FastAPI(title="云镜 Agent — AI 智能体 V2", version="0.4.0")

# ── Basic Auth ────────────────────────────────────────────
_security = HTTPBasic()

async def verify_basic_auth(credentials: HTTPBasicCredentials = Depends(_security)):
    """简单的基本认证，用于保护 Agent API"""
    agent_username = os.getenv("AGENT_USER", "admin")
    agent_password = os.getenv("AGENT_PASSWORD", "yunjing123")
    if credentials.username != agent_username or credentials.password != agent_password:
        raise HTTPException(status_code=401, detail="Unauthorized",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials


# ── 技能知识库（启动时从后端加载） ──────────────────────
_skills_cache: list[dict] = []
_skills_system_prompt = ""


PHASE_LABELS = {
    "intelligence_gathering": "Phase 1 — 侦察与资产发现",
    "threat_modeling": "Phase 2 — 威胁建模",
    "vulnerability_analysis": "Phase 3 — 漏洞分析",
    "exploitation": "Phase 4 — 漏洞利用与攻击",
    "post_exploitation": "Phase 5 — 后渗透与横向移动",
    "reporting": "Phase 6 — 报告生成",
}

PHASE_TARGET_MAP = {
    "intelligence_gathering": ["single_ip", "cidr", "domain", "multi_ip", "internal_net"],
    "threat_modeling": ["single_ip", "cidr", "domain", "multi_ip", "internal_net"],
    "vulnerability_analysis": ["single_ip", "cidr", "domain", "web", "api", "internal_net"],
    "exploitation": ["single_ip", "cidr", "domain", "web", "api", "internal_net"],
    "post_exploitation": ["single_ip", "internal_net"],
    "reporting": ["*"],
}

PRIORITY = [
    "intelligence_gathering",
    "threat_modeling",
    "vulnerability_analysis",
    "exploitation",
    "post_exploitation",
    "reporting",
]


def _build_phase_priority():
    """动态构建 PTES 方法论阶段说明"""
    phases = []
    # Group skills by phase
    by_phase = {}
    for s in _skills_cache:
        p = s.get("phase", "")
        if p and p != "all" and p != "reference" and p != "environment":
            by_phase.setdefault(p, []).append(s)

    for pid in PRIORITY:
        label = PHASE_LABELS.get(pid, pid)
        skills = by_phase.get(pid, [])
        skill_names = ", ".join(s["name"] for s in skills if s.get("enabled"))
        lines = []
        if pid == "intelligence_gathering":
            lines.append("资产发现/存活探测/端口枚举/指纹识别/子域名枚举")
        elif pid == "threat_modeling":
            lines.append("目标画像分析/攻击路径推荐/暴露面建模")
        elif pid == "vulnerability_analysis":
            lines.append("漏洞扫描/配置检查/弱口令检测/SSL检查/代码审计/API测试")
        elif pid == "exploitation":
            lines.append("Web漏洞利用/API攻击/认证绕过/AD攻击/SQL注入/XSS")
        elif pid == "post_exploitation":
            lines.append("C2通信/权限维持/数据提取/内网横向")
        elif pid == "reporting":
            lines.append("漏洞汇总/攻击链路/暴露面清单/等保对标/修复建议")
        if skill_names:
            lines.append(f"可用技能: {skill_names}")
        phases.append((label, lines))
    return phases


def _build_red_line_rules() -> str:
    """红线规则 — Agent 安全行为准则"""
    return """## ⛔ 红线规则 — 安全行为准则（必须遵守）

在安全检测全过程中，你作为 AI 智能体必须遵守以下红线规则：

### 1. 不破坏原则
- **绝对不允许执行会导致目标系统崩溃、业务中断、数据损坏的操作**
- 怀疑某个操作可能导致不稳定时，**跳过该操作**，在报告备注注明

### 2. 漏洞利用红线
当你判断一个漏洞可以「利用」时，先做风险评估：
- ✅ **安全利用**：SQL 注入（读取数据而不删除/写入）、目录遍历（读取而不修改）、弱口令登录（验证即可）
- ⚠️ **谨慎利用**：RCE 执行命令（仅执行无害命令如 `whoami`、`id`、`pwd`）、文件上传（上传无害测试文件并删除）
- ❌ **禁止利用**：DDOS、格式化硬盘、删除数据、修改系统配置、重启服务、写入恶意文件、提权到 root、安装后门
- 📝 **记录代替执行**：对 ❌ 级别的漏洞，在报告中记录「此漏洞可导致 XXXX，但实际测试可能导致系统不稳定，建议人工确认」

### 3. 扫描规则
- 速率限制：每秒不超过 50 个请求
- 全端口扫描只扫描 1-10000 端口（不扫全部 65535）
- 弱口令检测仅尝试 Top 20 常见密码（不爆破库）
- 对生产环境默认使用被动模式（仅侦察，不做主动攻击）

### 4. 授权确认
- 如果用户未提供任何目标 IP/域名，要求用户提供
- 如果目标包含外网 IP，提示用户确认授权范围
- 所有高危操作（漏洞利用阶段）需在计划中标注 risk_level

### 5. 熔断机制
- 如果检测到目标响应变慢或异常，自动降速
- 如果用户通过 Web UI 触发「一键熔断」，立即停止所有任务"""


def _build_intent_rules() -> str:
    """意图理解规则"""
    return """## 🎯 意图理解与目标分析规则

你收到用户消息后，必须分析以下维度：

### 1. 目标类型识别
分析用户提到的目标来判断：

| 输入示例 | 目标类型 |
|---------|---------|
| "192.168.1.165" | single_ip |
| "192.168.1.0/24" 或 "192.168.1.1-254" | cidr |
| "example.com" | domain |
| "192.168.1.10, 192.168.1.20" 或 "10台服务器" | multi_ip |
| "api.example.com" 或 "给我测测API" | api |
| "帮我看看内网" 或 "资产发现" | internal_net |

### 2. 扫描深度识别
根据用户措辞判断深度：

| 用户说 | 深度 |
|-------|------|
| "快速检查一下"、"简单扫扫"、"看看有啥端口" | quick_check |
| "全面扫描"、"安全检测"、"帮我检查安全" | standard |
| "深度渗透"、"完整攻击"、"我要看看能不能打进去" | full_penetration |

### 3. 特殊需求提取
- "要报告" → requirements: ["report"]
- "等保"、"护网" → requirements: ["compliance_report"]
- "漏洞利用"、"帮我打进去" → requirements: ["exploitation"]
- "弱口令"、"爆破" → requirements: ["brute_force"]
- "Web"、"网站"、"页面" → requirements: ["web_scan"]
- "API"、"接口" → requirements: ["api_scan"]

### 4. 排除项识别
- "不要扫 443"、"排除 xxx" → exclusions
- "只扫80和443"、"只测Web" → scope_limits

### 5. 多目标处理
- 用户说 "10台服务器"、"一批机器" → 转换为多目标模式
- 用户说 IP 段 → 自动解构为目标列表"""


def _build_skill_selection_rules() -> str:
    """动态构建技能选择规则"""
    lines = ["## 🧠 技能选择与编排规则", ""]
    lines.append("### 基本原则")
    lines.append("1. **最少技能原则**：能用 1 个技能解决的问题不用 3 个")
    lines.append("2. **依赖优先原则**：端口扫描 → 服务识别 → 漏洞扫描 → 漏洞利用")
    lines.append("3. **类型匹配原则**：根据目标类型选择对应技能")
    lines.append("4. **阶段匹配原则**：根据当前 PTES 阶段选择对应 phase 标签的技能")
    lines.append("")

    # Group enabled skills by target type
    type_map = {}
    for s in _skills_cache:
        if not s.get("enabled"):
            continue
        raw = s.get("target_types", "[]")
        if isinstance(raw, str):
            try:
                types = json.loads(raw)
            except json.JSONDecodeError:
                types = ["*"]
        else:
            types = raw
        for t in types:
            type_map.setdefault(t, []).append(s)

    target_labels = {
        "single_ip": "单 IP / 普通服务器",
        "cidr": "网段 / 多主机",
        "domain": "域名",
        "web": "Web 应用",
        "api": "API 接口",
        "internal_net": "内网环境",
        "cloud": "云环境",
        "code": "代码审计",
        "*": "通用（适用所有场景）",
    }

    for t, label in target_labels.items():
        skills = type_map.get(t, [])
        if not skills:
            continue
        lines.append(f"#### {label}")
        for s in skills:
            phase_tag = f"[{s.get('phase','?')}]" if s.get("phase") else ""
            lines.append(f"- {phase_tag} {s['name']}: {s.get('description','')[:80]}")
        lines.append("")

    # Phase → stage mapping
    lines.append("### 阶段 ID → 扫描阶段映射")
    phase_stage_map = {
        "intelligence_gathering": "asset_discovery → port_scan → web_fingerprint → osint_gather",
        "threat_modeling": "threat_model",
        "vulnerability_analysis": "service_detect → vuln_scan → web_scan → dir_scan",
        "exploitation": "exploitation",
        "post_exploitation": "post_exploit",
        "reporting": "report",
    }
    for pid, stages in phase_stage_map.items():
        label = PHASE_LABELS.get(pid, pid)
        lines.append(f"- **{label}**: {stages}")
    lines.append("")

    return "\n".join(lines)


def _recommend_skills(target_type: str, depth: str = "standard") -> list[str]:
    """根据目标类型和深度，动态推荐最优技能组合"""
    candidates = []
    for s in _skills_cache:
        if not s.get("enabled"):
            continue
        # Check target type match
        raw = s.get("target_types", "[]")
        if isinstance(raw, str):
            try:
                types = json.loads(raw)
            except json.JSONDecodeError:
                types = ["*"]
        else:
            types = raw
        if "*" not in types and target_type not in types:
            continue
        # Filter by depth
        if depth == "quick_check" and s.get("phase") in ("post_exploitation", "exploitation"):
            continue
        phase = s.get("phase", "")
        # Priority: same phase skills first
        candidates.append(s)

    # Sort: phase priority + enabled first
    def sort_key(s):
        try:
            p_idx = PRIORITY.index(s.get("phase", ""))
        except ValueError:
            p_idx = 99
        return (p_idx, s.get("sort_order", 99))

    candidates.sort(key=sort_key)

    # Select: pick a diverse set (at most one per phase for quick, more for deep)
    seen_phases = set()
    selected = []
    for s in candidates:
        p = s.get("phase", "")
        if depth == "quick_check" and p in seen_phases and p not in ("all", "reference"):
            continue
        seen_phases.add(p)
        selected.append(s["id"])
        if depth == "quick_check" and len(selected) >= 3:
            break

    if not selected:
        # Fallback: pick first 3 enabled
        selected = [s["id"] for s in _skills_cache if s.get("enabled")][:3]

    return selected


def _build_default_prompt(skills: list[dict]) -> str:
    """根据技能列表构建完整的 LLM 系统提示词"""
    if not skills:
        return """你是云镜·安全检测助手的 AI 智能体。协助用户进行渗透测试和安全检测。
当前技能列表尚未加载，请提示用户技能系统可能未就绪。"""

    enabled = [s for s in skills if s.get("enabled")]
    disabled = [s for s in skills if not s.get("enabled")]

    # 按分类分组技能
    categories = {}
    for s in skills:
        cat = s.get("category", "综合")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(s)

    lines = [
        "## 🔐 你的身份",
        "你是**云镜·安全检测助手**的 AI 智能体，一项企业级全自动 AI 渗透测试服务。",
        "你精通 {} 个专业安全技能，能根据用户的一句话需求，自主完成从资产发现到漏洞利用到报告生成的完整闭环。",
        "",
        "## 📋 核心能力",
        "- 理解自然语言安全需求 → 提取目标、深度、要求",
        "- 根据 18 个技能动态编排扫描计划（DAG 图形化编排）",
        "- 红线规则确保安全（不破坏目标系统）",
        "- 多目标一键扫描（支持 /24 网段、多 IP 列表）",
        "- 攻击证实与链路追踪（记录每一步）",
        "- 自动生成 4 格式报告（PDF/Word/HTML/Excel）",
        "",
        "## 🛠 技能体系（共 {{}} 个技能，{{}} 个已启用）".format(len(skills), len(enabled)),
        "以下是可用的安全检测技能。所有技能通过 Kali Linux 沙箱隔离运行。",
        "",
    ]

    # 按分类展示技能
    for cat_name, cat_skills in categories.items():
        lines.append(f"### {cat_name}")
        for s in cat_skills:
            sid = s.get('id', '?')
            status = "🟢" if s.get("enabled") else "🔴"
            lines.append(f"- {status} **{s['name']}** (id: `{sid}`): {s.get('description', '')[:120]}")
    lines.append("")

    # 意图理解规则
    lines.append(_build_intent_rules())
    lines.append("")

    # 技能选择规则
    lines.append(_build_skill_selection_rules())
    lines.append("")

    # 红线规则
    lines.append(_build_red_line_rules())
    lines.append("")

    # PTES 方法论
    lines.append("## 📚 PTES 渗透测试方法论阶段")
    for phase_name, details in _build_phase_priority():
        lines.append(f"### {phase_name}")
        for d in details:
            lines.append(f"- {d}")
    lines.append("")

    # 响应格式
    lines.append("""## 📤 响应格式

### 场景一：用户提出安全检测需求 → 返回扫描计划 JSON

```json
{
  "type": "scan_plan",
  "intent": {
    "summary": "用户意图简述",
    "target_type": "single_ip | cidr | domain | multi_ip | api | internal_net",
    "targets": ["目标1", "目标2"],
    "depth": "quick_check | standard | full_penetration",
    "requirements": ["report", "compliance_report", "exploitation"],
    "exclusions": [],
    "scope_limits": []
  },
  "plan": {
    "phases": [
      {
        "phase": "asset_discovery",
        "skills": ["skill_id1", "skill_id2"],
        "description": "阶段说明",
        "parallel": false,
        "depends_on": [],
        "condition": null,
        "risk_level": "safe"
      }
    ],
    "total_estimated": "预估时间"
  },
  "selected_skills": ["skill_id1", "skill_id2"],
  "reasoning": "选择这些技能的原因"
}
```

### 场景二：普通聊天（非检测需求）→ 自然语言回复

直接以自然语言回复用户。

### 场景三：用户明确要求渗透测试 → JSON 格式 + 附带简短中文说明

先发 JSON 计划，再发一段简短的自然语言说明。""")

    return "\n".join(lines)


# ── 请求模型 ──────────────────────────────────────────────
class ChatRequest(BaseModel):
    session_id: str
    message: str
    history: Optional[list[dict]] = []


class ChatResponse(BaseModel):
    type: str  # "scan_plan" | "chat"
    content: str
    plan: Optional[dict] = None


class ReloadResponse(BaseModel):
    message: str
    count: int
    enabled: int


# ── API ────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    logger.info("🚀 云镜 Agent V2 启动中...")
    await load_skills()


async def load_skills():
    """从后端 API 加载技能，构建 LLM 系统提示词"""
    global _skills_cache, _skills_system_prompt
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            for l_attempt in range(5):
                login_resp = await client.post(
                    f"{BACKEND_URL}/api/auth/login",
                    json={"username": "admin", "password": os.getenv("AGENT_BACKEND_PASSWORD", "yunjing123")},
                )
                if login_resp.status_code == 200:
                    break
                wait = 2 * (l_attempt + 1)
                logger.warning(f"Login failed ({login_resp.status_code}), retry {l_attempt+1}/5 in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)
            if login_resp.status_code != 200:
                logger.warning(f"Login failed after 5 retries")
                _skills_system_prompt = _build_default_prompt([])
                return

            token_data = login_resp.json()
            token = token_data.get("access_token", "")

            for sf_attempt in range(3):
                skills_resp = await client.get(
                    f"{BACKEND_URL}/api/skills/",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if skills_resp.status_code == 200:
                    break
                wait = 2 * (sf_attempt + 1)
                logger.warning(f"Skills fetch failed ({skills_resp.status_code}), retry {sf_attempt+1}/3 in {wait}s...")
                import asyncio
                await asyncio.sleep(wait)
            if skills_resp.status_code != 200:
                logger.warning(f"Skills fetch failed after 3 retries")
                _skills_system_prompt = _build_default_prompt([])
                return

            data = skills_resp.json()
            skills = data.get("skills", [])
            _skills_cache = skills
            _skills_system_prompt = _build_default_prompt(skills)
            enabled = sum(1 for s in skills if s.get("enabled"))
            logger.info(f"✅ 加载 {len(skills)} 个技能（{enabled} 个启用）")
            logger.info(f"📏 System Prompt 长度: {len(_skills_system_prompt)} 字符")
    except Exception as e:
        logger.warning(f"技能加载失败: {e}")
        _skills_system_prompt = _build_default_prompt([])


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "agent",
        "version": "0.4.0",
        "skills_loaded": len(_skills_cache),
        "skills_enabled": sum(1 for s in _skills_cache if s.get("enabled")),
    }


@app.get("/skills")
async def get_skills(credentials=Depends(verify_basic_auth)):
    """返回当前缓存的技能列表"""
    return {"skills": _skills_cache}


@app.post("/skills/reload")
async def reload_skills(credentials=Depends(verify_basic_auth)):
    """手动触发技能重载"""
    await load_skills()
    return ReloadResponse(
        message=f"技能已重载，共 {len(_skills_cache)} 个",
        count=len(_skills_cache),
        enabled=sum(1 for s in _skills_cache if s.get("enabled")),
    )


@app.post("/chat")
async def chat(req: ChatRequest, credentials=Depends(verify_basic_auth)):
    """处理用户消息 — 技能感知的 AI 对话"""
    if not LLM_API_KEY:
        raise HTTPException(status_code=500, detail="LLM_API_KEY 未配置")

    messages = [{"role": "system", "content": _skills_system_prompt}]

    for h in (req.history or [])[-8:]:
        role = h.get("role", "user")
        content = h.get("content", "")
        messages.append({"role": role, "content": content})

    messages.append({"role": "user", "content": req.message})

    try:
        client = AsyncOpenAI(api_key=LLM_API_KEY, base_url=LLM_API_BASE)
        response = await client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            temperature=0.1,
            max_tokens=3000,
            extra_body={"max_completion_tokens": 3000},
        )

        content = response.choices[0].message.content or ""
        reasoning = getattr(response.choices[0].message, "reasoning_content", "") or ""

        # 尝试解析 JSON 扫描计划
        plan = _try_parse_json(content)

        if plan and "plan" in plan:
            # 完整扫描计划
            intent = plan.get("intent", {})
            plan_detail = plan.get("plan", {})
            skill_ids = plan.get("selected_skills", [])

            summary = intent.get("summary", "安全检测")
            targets = intent.get("targets", [req.message])
            depth = intent.get("depth", "standard")
            phases = plan_detail.get("phases", [])

            return ChatResponse(
                type="scan_plan",
                content=f"🎯 已识别检测需求：{summary}\n📡 目标：{', '.join(targets)}\n📊 深度：{depth}\n🧩 阶段数：{len(phases)}个\n🛠 技能：{', '.join(skill_ids)}",
                plan=plan,
            )
        elif plan and "selected_skills" in plan:
            # 简单扫描计划（旧版兼容）
            return ChatResponse(
                type="scan_plan",
                content=f"已识别检测需求：{plan.get('intent', '安全检测')}",
                plan=plan,
            )
        else:
            return ChatResponse(type="chat", content=content, plan=None)

    except Exception as e:
        logger.error(f"LLM 调用失败: {e}")
        raise HTTPException(status_code=500, detail=f"AI 推理失败: {e}")


def _try_parse_json(text: str) -> Optional[dict]:
    """尝试从 LLM 响应中提取 JSON"""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # 尝试找到第一个 { 到最后一个 }
    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        try:
            return json.loads(text[first:last+1])
        except json.JSONDecodeError:
            pass

    return None
