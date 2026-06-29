"""对话 API 辅助函数"""
from app.api.skills import BUILTIN_SKILLS


def _tool_summary(tool_calls):
    """Generate a friendly summary when LLM only calls tools without text"""
    if not tool_calls:
        return " "
    names = [tc.get("function", {}).get("name", "?") for tc in tool_calls[:3]]
    name_labels = {"start_scan": "启动渗透扫描", "get_task_status": "查询任务状态",
                   "get_task_vulnerabilities": "获取漏洞列表", "analyze_results": "AI 分析结果",
                   "get_tools_status": "检查工具状态"}
    labels = [name_labels.get(n, n) for n in names]
    return "🔧 正在执行: " + ", ".join(labels) + "..."


def _build_skills_section():
    layers = {"perception": "感知层", "deduction": "推演层", "execution": "执行层"}
    lines = [f"共 {len(BUILTIN_SKILLS)} 个已注册技能："]
    for lk, ll in layers.items():
        skills = [s for s in BUILTIN_SKILLS if s.get('layer') == lk]
        if skills:
            lines.append(f"  【{ll}】")
            for s in skills:
                lines.append(f"    - {s['id']} — {s['name']}")
    return '\n'.join(lines)


_SKILLS_PH = "##_SKILLS_SECTION##"


SYSTEM_PROMPT = """你叫云镜，是一名企业级AI渗透测试专家。你不是工具调度员，你是真正的渗透分析师。

## 你的核心能力
1. **启动扫描** — 调用 start_scan 执行自动化渗透测试
2. **分析结果** — 扫描完成后，你必须分析发现、给出专业判断和下一步建议
3. **知识驱动** — 所有分析必须基于知识库和经验库的检索结果，不得凭空猜测
4. **策略制定** — 基于扫描发现，制定下一轮攻击方向

## 工作流程
1. **收到目标** → 检索经验库 → 启动 start_scan 全面检测
2. **扫描进行中** → 不轮询，直接告诉用户"扫描已启动，任务ID：xxx"
3. **扫描完成** → 必须执行以下分析：
   a. 获取漏洞列表 (get_task_vulnerabilities)
   b. 调用 analyze_results 获取 AI 分析
   c. 基于知识库和经验库，补充你的专业判断
   d. 输出分析总结 + 下一步攻击建议
4. **用户跟进** → 用户选择攻击方向后，启动第二轮深度扫描

## 分析输出格式（扫描完成后必须使用）
🔍 **扫描总结**
- 目标特征：（端口、服务、技术栈）
- 关键发现：（列出最重要的3-5条）

💡 **专业分析**
- 基于知识库[来源]：解释为什么这个发现是危险的
- 基于经验库[来源]：之前类似场景的利用成功率

🎯 **下一步建议**
1. [具体攻击方向] — 理由：[引用知识库/经验库]
2. [具体攻击方向] — 理由：[引用知识库/经验库]

## 避免幻觉的硬规则
- ❌ 禁止说"根据经验..."——必须说"根据知识库[文档名]"或"根据经验库[第N次扫描]"
- ❌ 禁止编造不存在的 CVE 编号
- ❌ 禁止在没有工具输出的情况下声称"发现漏洞"
- ✅ 分析必须引用具体来源（知识库文档名或经验库记录）
- ✅ 不确定时明确说"需要进一步验证"
- ✅ 引用工具输出时使用原文

## 沟通风格
中文，专业精炼，引用来源。每个分析点必须有依据。
不要问用户"可以开始吗"——直接启动检测。
用户消息意味着"立即行动"，不是"询问意见"。"""


def _build_rag_context(target_info: str) -> str:
    """根据目标信息查询 RAG 经验库，构建 LLM 上下文"""
    try:
        import httpx
        # 调用 RAG 搜索
        resp = httpx.post(
            "http://yunjing-backend:8000/api/engine/experience/search",
            json={"query": target_info, "top_k": 3},
            timeout=10,
        )
        if resp.status_code != 200:
            return ""

        data = resp.json()
        exp_list = data.get("results", [])
        if not exp_list:
            return ""

        lines = ["\n[📚 经验库参考 — 基于目标的攻击建议]\n系统已自动查询经验库，以下是与目标最相关的攻击经验："]
        for i, exp in enumerate(exp_list[:3], 1):
            title = exp.get("title", "?")
            score = exp.get("score", 0)
            target_type = exp.get("target_type", "")
            verification = exp.get("verification_steps", "")[:200]
            tools = exp.get("tools", [])
            tools_str = ", ".join(tools[:5]) if tools else "标准工具"
            lines.append(f"  {i}. [{title}] (相关度: {score:.2f})")
            if target_type:
                lines.append(f"     适用场景: {target_type}")
            lines.append(f"     建议方案: {verification}")
            lines.append(f"     推荐工具: {tools_str}")
        return "\n".join(lines)
    except Exception as e:
        return ""
