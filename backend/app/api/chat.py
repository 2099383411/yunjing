"""对话 API：持久化会话 + LLM Function Calling"""
import json, uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
import asyncio, json
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc, delete
from app.database import AsyncSessionLocal
from app.models.conversation import Conversation, Message
from app.models.user import User
from app.api.deps import optional_user
from app.llm.adapter import llm_adapter
from app.services.scan_tools import TOOLS, execute_tool_call
from app.grounding.reasoning_capture import capture_reasoning
from app.grounding.target_parser import extract_target, format_target_summary
from app.api.skills import BUILTIN_SKILLS

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

_SKILLS_PH = "##_SKILLS_SECTION_##"

from app.config import settings
from app.models.setting import SystemSetting

router = APIRouter()

# ═══════════════════════════════════════════════════════════
#  新 SYSTEM_PROMPT — 对话式渗透
# ═══════════════════════════════════════════════════════════

SYSTEM_PROMPT = """你叫云镜，是一名企业级渗透测试专家。你采用「自主渗透 + 全透明」模式工作。

## 工作流程
1. **收到目标** → 立即查询经验库获取相关攻击方案
2. **启动检测** → 调用 start_scan 启动全面安全检测（全端口扫描→服务识别→漏洞检测→渗透测试）
3. **全程透明** → 每完成一个阶段向用户汇报（不轮询进度）
4. **分析汇报** → 每阶段汇报格式：🔍 正在做什么 → ✅ 发现了什么 → 💡 专业解读
5. **完成收尾** → 全部完成后输出渗透测试报告摘要

## 核心准则
- **自主但不盲目** — 自动执行检测，但每阶段结果都要向用户汇报
- **全透明** — 用户能看到所有进度和发现
- **可打断** — 用户任何消息都会打断当前流程，等待新指令
- **智能决策** — 根据目标特征自动调整渗透方向
- **经验驱动** — 充分利用系统提供的经验库建议，不瞎试

## 工具说明
- **start_scan(target, description?)** → 启动全面安全检测（创建任务后立即返回）
- **get_task_status(task_id)** → 查任务状态（调用一次即可，不要轮询）
- **get_task_vulnerabilities(task_id)** → 获取扫描结果的漏洞列表
- **get_tools_status()** → 查工具状态（启动前查一次即可）

## 重要规则
- **不轮询任务状态**。调用 `get_task_status` 一次后直接告诉用户"扫描进行中"，然后停止调用工具
- **启动即回报**。调用 `start_scan` 拿到 task_id 后，回复"扫描已启动，任务ID：xxx" 并结束当前对话
- **每个对话最多调用 2 次工具**（查状态 → 启动扫描），之后必须给出文字回复

## 沟通风格
中文，专业精炼。每个阶段用 🔍✅💡 三要素汇报。
不要问用户“可以开始吗”——直接启动检测并汇报。
"""
# ═══════════════════════════════════════════════════════════
#  RAG 上下文构建
# ═══════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════
#  API Endpoints
# ═══════════════════════════════════════════════════════════

@router.get("/conversations")
async def list_conversations(user: User = Depends(optional_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(Conversation).order_by(desc(Conversation.updated_at)).limit(50)
        )
        convs = result.scalars().all()
        out = []
        for c in convs:
            cnt = await sess.execute(select(Message).where(Message.conversation_id == c.id))
            msgs = cnt.scalars().all()
            out.append({
                "id": c.id, "title": c.title, "message_count": len(msgs),
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "updated_at": c.updated_at.isoformat() if c.updated_at else "",
            })
    return out


@router.post("/conversations")
async def create_conversation(data: dict, user: User = Depends(optional_user)):
    title = data.get("title", "新对话")
    async with AsyncSessionLocal() as sess:
        conv = Conversation(id=str(uuid.uuid4()), user_id=user.id if user else None, title=title)
        sess.add(conv)
        await sess.commit()
        await sess.refresh(conv)
    return {"id": conv.id, "title": conv.title}


@router.get("/conversations/{conv_id}/messages")
async def get_messages(conv_id: str, user: User = Depends(optional_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(
            select(Message).where(Message.conversation_id == conv_id).order_by(Message.created_at)
        )
        msgs = result.scalars().all()
        return [{
            "id": m.id, "role": m.role, "content": m.content,
            "tool_calls": m.tool_calls,
            "created_at": m.created_at.isoformat() if m.created_at else "",
        } for m in msgs]


@router.delete("/conversations/{conv_id}")
async def delete_conversation(conv_id: str, user: User = Depends(optional_user)):
    async with AsyncSessionLocal() as sess:
        await sess.execute(delete(Message).where(Message.conversation_id == conv_id))
        await sess.execute(delete(Conversation).where(Conversation.id == conv_id))
        await sess.commit()
    return {"ok": True}


@router.post("/conversations/{conv_id}/chat")
async def chat(conv_id: str, data: dict, user: User = Depends(optional_user)):
    """对话式渗透 — 每次消息都是一次交互"""
    text = data.get("text", "")
    stream = data.get("stream", True)
    history = data.get("history", None)

    if not text:
        raise HTTPException(status_code=400, detail="text is required")

    # ── 构建消息上下文 ──
    async with AsyncSessionLocal() as sess:
        if history is None:
            result = await sess.execute(
                select(Message).where(Message.conversation_id == conv_id).order_by(Message.created_at)
            )
            history = result.scalars().all()

        # 初始 system prompt（含技能列表）
        system_content = SYSTEM_PROMPT.replace(_SKILLS_PH, _build_skills_section())

        messages = [{"role": "system", "content": system_content}]

        # ── RAG 上下文注入 ──
        # 如果是新目标，查 RAG 经验库获取相关攻击经验
        target_info = ""
        parsed = extract_target(text)
        if parsed:
            target_info = format_target_summary(parsed)
            # 注入目标信息
            target_display = f"[TARGET] {target_info}"
            messages.append({"role": "system", "content": target_display})

            # 查询 RAG 经验库
            rag_context = _build_rag_context(target_info)
            if rag_context:
                messages.append({"role": "system", "content": rag_context})

        # 历史消息

        # 历史消息
        for m in history:
            msg = {"role": m.role, "content": m.content}
            if m.tool_calls:
                msg["tool_calls"] = m.tool_calls
            if m.tool_call_id:
                msg["tool_call_id"] = m.tool_call_id
            messages.append(msg)

        # 当前用户消息
        # 如果已有目标信息在 system 消息中，不再重复注入 [TARGET]
        messages.append({"role": "user", "content": text})
        # 保存用户消息到 DB
        try:
            async with AsyncSessionLocal() as _save_sess:
                _save_sess.add(Message(id=str(uuid.uuid4()), conversation_id=conv_id, role="user", content=text))
                await _save_sess.commit()
        except Exception:
            pass

        # Check API key
        key_result = await sess.execute(
            select(SystemSetting).where(SystemSetting.key == "llm_api_key")
        )
        key_row = key_result.scalar_one_or_none()
        has_api_key = bool(key_row and key_row.value)

        # Update conversation title if first message
        conv = await sess.get(Conversation, conv_id)
        msg_count = len([m for m in history if m.role == "user"])
        if conv and msg_count == 0:
            conv.title = text[:50] + ("..." if len(text) > 50 else "")
            conv.updated_at = datetime.utcnow()

        await sess.commit()

    if not has_api_key and not settings.LLM_API_KEY:
        reply = "欢迎使用云镜安全检测助手！请先在设置页面配置 LLM API Key。"
        async with AsyncSessionLocal() as sess:
            asst_msg = Message(id=str(uuid.uuid4()), conversation_id=conv_id, role="assistant", content=reply)
            sess.add(asst_msg)
            conv2 = await sess.get(Conversation, conv_id)
            if conv2:
                conv2.updated_at = datetime.utcnow()
            await sess.commit()

        async def no_key_gen():
            yield f"data: {json.dumps({'token': reply, 'done': True})}\n\n"
        return StreamingResponse(no_key_gen(), media_type="text/event-stream")

    async def event_stream():
        try:
            full_content = ""
            reasoning_content = None
            tool_calls_data = None
            done_reason = None

            # Use streaming from LLM
            async for chunk_dict in llm_adapter.chat_stream(messages=messages, tools=TOOLS):
                choices = chunk_dict.get("choices", [])
                if not choices:
                    continue
                choice = choices[0]
                delta = choice.get("delta", {})
                finish = choice.get("finish_reason")

                if delta.get("reasoning_content"):
                    if delta["reasoning_content"]:
                        rc = delta["reasoning_content"]
                        reasoning_content = (reasoning_content or "") + rc
                        yield f"data: {json.dumps({'type': 'reasoning', 'content': rc})}\n\n"
                    continue

                if delta.get("tool_calls"):
                    tool_calls_data = tool_calls_data or []
                    for tc in delta["tool_calls"]:
                        idx = tc.get("index", 0)
                        if idx is not None and idx < len(tool_calls_data):
                            existing = tool_calls_data[idx]
                            if tc.get("id"):
                                existing["id"] = tc["id"]
                            if tc.get("function"):
                                if tc["function"].get("name"):
                                    existing["function"]["name"] = tc["function"]["name"]
                                if tc["function"].get("arguments"):
                                    existing["function"]["arguments"] += tc["function"]["arguments"]
                        else:
                            tool_calls_data.append({
                                "id": tc.get("id"),
                                "type": "function",
                                "function": {
                                    "name": tc.get("function", {}).get("name", ""),
                                    "arguments": tc.get("function", {}).get("arguments", ""),
                                }
                            })

                content = delta.get("content", "")
                if content:
                    full_content += content
                    yield f"data: {json.dumps({'token': content, 'done': False})}\n\n"

                if finish == "tool_calls":
                    done_reason = "tool_calls"
                    results = []
                    for tc in (tool_calls_data or []):
                        tc_name = tc["function"]["name"]
                        try:
                            tc_args = json.loads(tc["function"]["arguments"])
                        except:
                            tc_args = {}
                        yield f"data: {json.dumps({'type': 'tool_call', 'name': tc_name, 'arguments': tc_args})}\n\n"
                        # Capture reasoning
                        try:
                            from app.database import AsyncSessionLocal as ASL_S
                            async with ASL_S() as gsess:
                                await capture_reasoning(
                                    db=gsess, task_id=f"chat-{conv_id}",
                                    turn_id=len([m for m in messages if m["role"] in ("assistant","tool")]) // 2 + 1,
                                    llm_decision=f"调用 {tc_name}",
                                    llm_reasoning=reasoning_content or "流式推理",
                                    evidence_type="推理",
                                    tool=tc_name, target=str(tc_args)[:200],
                                    status="running", confidence_before=0.5,
                                )
                        except Exception:
                            pass
                        tc_result = await execute_tool_call({
                            "id": tc["id"],
                            "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]}
                        })
                        yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name, 'result': tc_result})}\n\n"
                        results.append({"tool_call_id": tc["id"], "content": tc_result})
                        # Capture tool result
                        try:
                            from app.database import AsyncSessionLocal as ASL_S2
                            async with ASL_S2() as gsess2:
                                await capture_reasoning(
                                    db=gsess2, task_id=f"chat-{conv_id}",
                                    turn_id=len([m for m in messages if m["role"] in ("assistant","tool")]) // 2 + 1,
                                    llm_decision=f"工具 {tc_name} 执行完成",
                                    evidence_type="执行",
                                    tool=tc_name,
                                    result_summary=(tc_result or "")[:200],
                                    status="success" if tc_result else "failed",
                                    confidence_after=0.7 if tc_result else 0.3,
                                )
                        except Exception:
                            pass

                    asst_dict = {
                        "role": "assistant",
                        "content": (full_content or "") or " ",
                        "tool_calls": tool_calls_data,
                    }
                    if reasoning_content:
                        asst_dict["reasoning_content"] = reasoning_content
                    messages.append(asst_dict)
                    for r in results:
                        messages.append({"role": "tool", "tool_call_id": r["tool_call_id"], "content": r["content"]})
                    # 保存第一轮 assistant+tool 消息到 DB
                    try:
                        async with AsyncSessionLocal() as _save_sess:
                            _save_sess.add(Message(id=str(uuid.uuid4()), conversation_id=conv_id,
                                role="assistant", content=(full_content or "") or " ", tool_calls=tool_calls_data))
                            for _r in results:
                                _save_sess.add(Message(id=str(uuid.uuid4()), conversation_id=conv_id,
                                    role="tool", content=_r["content"], tool_call_id=_r["tool_call_id"]))
                            await _save_sess.commit()
                    except Exception:
                        pass


                    # ⭐ WebSocket 实时接收扫描进度 ⭐
                    if tool_calls_data and any(tc.get("function",{}).get("name")=="start_scan" for tc in tool_calls_data):
                        try:
                            task_id = json.loads(tc_result).get("task_id", "")
                            if task_id:
                                scan_completed = False
                                vuln_findings_collected = []
                                try:
                                    import websockets
                                    ws_url = f"ws://localhost:8000/api/ws/scan/{task_id}"
                                    async with websockets.connect(ws_url, ping_interval=None, close_timeout=5) as ws:
                                        while not scan_completed:
                                            try:
                                                msg = await asyncio.wait_for(ws.recv(), timeout=120)
                                            except asyncio.TimeoutError:
                                                yield f"data: {json.dumps({'token': '! 扫描超时，请手动查询进度\\n', 'done': False})}\\n\\n"
                                                break
                                            try:
                                                evt = json.loads(msg) if isinstance(msg, str) else json.loads(msg)
                                            except (json.JSONDecodeError, TypeError):
                                                continue
                                            evt_type = evt.get("type", "")
                                            evt_data = evt.get("data", {})
                                            if evt_type == "phase":
                                                phase = evt_data.get("phase", "?")
                                                pstatus = evt_data.get("status", "")
                                                prog = evt_data.get("progress", 0)
                                                phase_label = {
                                                    "asset_discovery": "🔍 资产发现",
                                                    "osint": "🔎 情报收集",
                                                    "port_scan": "📡 端口扫描",
                                                    "service_detect": "⚙️ 服务识别",
                                                    "vuln_scan": "⚡ 漏洞扫描",
                                                    "web_scan": "🌐 Web扫描",
                                                    "dir_scan": "📁 目录扫描",
                                                    "web_fuzz": "💥 Web模糊测试",
                                                    "api_scan": "🏷 API检测",
                                                    "auth_test": "🔑 认证测试",
                                                    "exploit": "⚡ 漏洞利用",
                                                    "post_exploit": "🎯 后渗透",
                                                    "ad_enum": "👥 AD枚举",
                                                    "krb_scan": "🔒 Kerberos检测",
                                                }.get(phase, phase)
                                                if pstatus == "running":
                                                    p_bar = "▓" * min(prog // 5, 20) + "░" * max(20 - min(prog // 5, 20), 0)
                                                    p_msg = f"{phase_label}: ▶ 执行中 {p_bar} {prog}%\\n"
                                                elif pstatus == "done":
                                                    detail = evt_data.get("data", {})
                                                    detail_str = ""
                                                    if isinstance(detail, dict):
                                                        for k, v in detail.items():
                                                            if v and isinstance(v, (int, str)):
                                                                detail_str += f" {k}={v}"
                                                    p_msg = f"{phase_label}: ✅ 完成{detail_str}  ({prog}%)\\n"
                                                else:
                                                    p_msg = f"{phase_label}: {pstatus} ({prog}%)\\n"
                                                yield f"data: {json.dumps({'token': p_msg, 'done': False})}\\n\\n"
                                            elif evt_type == "vuln_findings":
                                                findings = evt_data.get("findings") or []
                                                vuln_findings_collected.extend(findings)
                                                yield f"data: {json.dumps({'token': f'⚠️ 发现 {len(findings)} 个漏洞\\n', 'done': False})}\\n\\n"
                                            elif evt_type == "dag_inject":
                                                inj_phase = evt_data.get("phase", "")
                                                inj_reason = evt_data.get("reason", "")
                                                yield f"data: {json.dumps({'token': f'📥 动态注入阶段 [{inj_phase}] → {inj_reason}\\n', 'done': False})}\\n\\n"
                                            elif evt_type == "status":
                                                s = evt_data.get("status", "")
                                                prog = evt_data.get("progress", 0)
                                                if s == "RUNNING":
                                                    yield f"data: {json.dumps({'token': '🚀 扫描引擎启动\\n', 'done': False})}\\n\\n"
                                                elif s in ("COMPLETED", "FAILED", "CANCELLED"):
                                                    scan_completed = True
                                                    s_label = {"COMPLETED": "✅ 完成", "FAILED": "❌ 失败", "CANCELLED": "⏹ 取消"}
                                                    yield f"data: {json.dumps({'token': f'🏁 扫描{s_label.get(s, s)} (进度 {prog}%)\\n', 'done': False})}\\n\\n"
                                                    if s == "COMPLETED":
                                                        v_result = await execute_tool_call({
                                                            "id": f"vuln_{task_id}",
                                                            "function": {"name": "get_task_vulnerabilities", "arguments": json.dumps({"task_id": task_id})}
                                                        })
                                                        messages.append({
                                                            "role": "tool",
                                                            "tool_call_id": f"auto_vuln_{task_id}",
                                                            "content": f"[扫描完成] 发现漏洞:\\n{v_result}"
                                                        })
                                                        try:
                                                            v_data = json.loads(v_result) if isinstance(v_result, str) else {}
                                                            import httpx
                                                            httpx.post(
                                                                "http://localhost:8000/api/engine/scan-callback",
                                                                json={
                                                                    "task_id": task_id, "target": "",
                                                                    "scan_type": "auto", "status": "completed",
                                                                    "findings": v_data.get("vulnerabilities", vuln_findings_collected),
                                                                },
                                                                timeout=5,
                                                            )
                                                        except Exception:
                                                            pass
                                                    break
                                except ImportError:
                                    for pi in range(12):
                                        await asyncio.sleep(5)
                                        p_result = await execute_tool_call({
                                            "id": f"poll_{pi}",
                                            "function": {"name": "get_task_progress", "arguments": json.dumps({"task_id": task_id})}
                                        })
                                        p_data = json.loads(p_result) if isinstance(p_result, str) else {}
                                        p_status = p_data.get("status", "")
                                        p_prog = p_data.get("progress", 0)
                                        p_msg = f"▓ 进度 {p_prog}% | {p_status}\n"
                                        yield f"data: {json.dumps({'token': p_msg, 'done': False})}\n\n"
                                        if p_status in ("COMPLETED", "FAILED", "CANCELLED"):
                                            if p_status == "COMPLETED":
                                                v_result = await execute_tool_call({
                                                    "id": f"vuln_{task_id}",
                                                    "function": {"name": "get_task_vulnerabilities", "arguments": json.dumps({"task_id": task_id})}
                                                })
                                                messages.append({
                                                    "role": "tool",
                                                    "tool_call_id": f"auto_vuln_{task_id}",
                                                    "content": f"[扫描完成] 发现漏洞:\n{v_result}"
                                                })
                                            break
                                except Exception as ws_err:
                                    yield f"data: {json.dumps({'token': f'! WebSocket连接失败({ws_err})，降级为HTTP轮询\\n', 'done': False})}\\n\\n"
                                    for pi in range(12):
                                        await asyncio.sleep(5)
                                        p_result = await execute_tool_call({
                                            "id": f"poll_{pi}",
                                            "function": {"name": "get_task_progress", "arguments": json.dumps({"task_id": task_id})}
                                        })
                                        p_data = json.loads(p_result) if isinstance(p_result, str) else {}
                                        p_status = p_data.get("status", "")
                                        p_prog = p_data.get("progress", 0)
                                        p_msg = f"▓ 进度 {p_prog}% | {p_status}\n"
                                        yield f"data: {json.dumps({'token': p_msg, 'done': False})}\n\n"
                                        if p_status in ("COMPLETED", "FAILED", "CANCELLED"):
                                            if p_status == "COMPLETED":
                                                v_result = await execute_tool_call({
                                                    "id": f"vuln_{task_id}",
                                                    "function": {"name": "get_task_vulnerabilities", "arguments": json.dumps({"task_id": task_id})}
                                                })
                                                messages.append({
                                                    "role": "tool",
                                                    "tool_call_id": f"auto_vuln_{task_id}",
                                                    "content": f"[扫描完成] 发现漏洞:\n{v_result}"
                                                })
                                            break
                        except Exception:
                            pass
                    # ══ 第二次 LLM 调用（带 tools）══
                    tcd2_accum = []
                    # 让 LLM 用工具查看进度、分析结果
                    full_content = ""
                    async for chunk_dict2 in llm_adapter.chat_stream(messages=messages, tools=TOOLS):
                        choices2 = chunk_dict2.get("choices", [])
                        if not choices2:
                            continue
                        delta2 = choices2[0].get("delta", {})
                        finish2 = choices2[0].get("finish_reason")
                        content2 = delta2.get("content", "")
                        if content2:
                            full_content += content2
                            yield f"data: {json.dumps({'token': content2, 'done': False})}\n\n"

                        if delta2.get("tool_calls"):
                            for tc2 in delta2["tool_calls"]:
                                idx = tc2.get("index", 0)
                                if idx < len(tcd2_accum):
                                    exist = tcd2_accum[idx]
                                    if tc2.get("id"): exist["id"] = tc2["id"]
                                    fn = tc2.get("function", {})
                                    if fn.get("name"): exist["function"]["name"] = fn["name"]
                                    if fn.get("arguments"): exist["function"]["arguments"] += fn["arguments"]
                                else:
                                    tcd2_accum.append({
                                        "id": tc2.get("id", ""),
                                        "type": "function",
                                        "function": {
                                            "name": tc2.get("function", {}).get("name", ""),
                                            "arguments": tc2.get("function", {}).get("arguments", ""),
                                        }
                                    })

                        if finish2 == "tool_calls" and tcd2_accum:
                            messages.append({"role": "assistant", "content": full_content or " ", "tool_calls": tcd2_accum})
                            _a2_id = str(uuid.uuid4())
                            _t2_acc = []
                            for tc2 in tcd2_accum:
                                tc_name2 = tc2["function"]["name"]
                                yield f"data: {json.dumps({'type': 'tool_call', 'name': tc_name2, 'arguments': tc2['function']['arguments']})}\n\n"
                                tc_r2 = await execute_tool_call({
                                    "id": tc2["id"],
                                    "function": {"name": tc_name2, "arguments": tc2["function"]["arguments"]}
                                })
                                yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name2, 'result': tc_r2})}\n\n"
                                messages.append({"role": "tool", "tool_call_id": tc2["id"], "content": tc_r2})
                                _t2_acc.append({"id": tc2["id"], "content": tc_r2})
                            # save second round
                            try:
                                async with AsyncSessionLocal() as _s:
                                    _s.add(Message(id=_a2_id, conversation_id=conv_id,
                                        role="assistant", content=full_content or " ", tool_calls=tcd2_accum))
                                    for _rt in _t2_acc:
                                        _s.add(Message(id=str(uuid.uuid4()), conversation_id=conv_id,
                                            role="tool", content=_rt["content"], tool_call_id=_rt["id"]))
                                    await _s.commit()
                            except: pass
                            # ══ 决策循环：基于扫描结果智能决策 ══
                            try:
                                from app.services.decision_integration import DecisionOrchestrator
                                
                                _vulns = []
                                for _m in messages[-15:]:
                                    if _m.get("role") == "tool":
                                        _c = _m.get("content", "")
                                        try:
                                            _d = json.loads(_c) if isinstance(_c, str) else _c
                                            if isinstance(_d, list):
                                                _vulns.extend(_d)
                                            elif isinstance(_d, dict):
                                                for _k in ("vulnerabilities", "results", "findings"):
                                                    _v = _d.get(_k, [])
                                                    if isinstance(_v, list) and len(_v) > 0:
                                                        _vulns.extend(_v)
                                                        break
                                        except:
                                            pass
                                
                                if _vulns:
                                    _vulns = _vulns[:20]
                                    yield f"data: {{'token': '\\n🧠 **%d 个发现，启动智能决策引擎...**\\n', 'done': False}}\\n\\n" % len(_vulns)
                                    
                                    async def _dl_llm(usr, sys):
                                        _m = [{"role": "system", "content": sys}, {"role": "user", "content": usr}]
                                        _t = ""
                                        async for _ch in llm_adapter.chat_stream(messages=_m):
                                            for _c2 in _ch.get("choices", []):
                                                _d2 = _c2.get("delta", {})
                                                if _d2.get("content"):
                                                    _t += _d2["content"]
                                        return _t
                                    
                                    async def _dl_rag(q):
                                        import httpx
                                        try:
                                            _r = await httpx.AsyncClient(timeout=15).post(
                                                "http://yunjing-backend:8000/api/engine/experience/search",
                                                json={"query": q, "top_k": 3},
                                            )
                                            if _r.status_code == 200:
                                                return _r.json().get("results", [])
                                        except:
                                            pass
                                        return []
                                    
                                    _orch = DecisionOrchestrator(
                                        execute_tool=execute_tool_call,
                                        llm_chat_func=_dl_llm,
                                        rag_search=_dl_rag,
                                        max_loop_steps=3,
                                        yield_callback=None,
                                    )
                                    
                                    try:
                                        _r = await _orch.run(target=target, initial_vulns=_vulns, task_id="")
                                        _acts = _r.get("actions_taken", [])
                                        if _acts:
                                            _report_lines = ["\\n🎯 **智能决策分析 — 可深入方向:**"]
                                            for _a in _acts[:3]:
                                                _report_lines.append(f"  - {'\\u2705' if _a['success'] else '\\u2728'} {_a['action']} \\u2192 {_a['reasoning'][:100]}")
                                            _report = "\\n".join(_report_lines)
                                            messages.append({"role": "tool", "tool_call_id": "decis", "content": _report})
                                            yield f"data: {{'token': '%s\\n', 'done': False}}\\n\\n" % _report
                                    except Exception as _e2:
                                        yield f"data: {{'token': '! 决策: %s\\n', 'done': False}}\\n\\n" % str(_e2)
                            except Exception as _e1:
                                pass
                            # ══ 决策循环结束 ══

                            # Third call: analyze tool results
                            full_content = ""
                            async for chunk_dict3 in llm_adapter.chat_stream(messages=messages):
                                choices3 = chunk_dict3.get("choices", [])
                                if not choices3:
                                    continue
                                delta3 = choices3[0].get("delta", {})
                                c3 = delta3.get("content", "")
                                if c3:
                                    full_content += c3
                                    yield f"data: {json.dumps({'token': c3, 'done': False})}\n\n"
                                if choices3[0].get("finish_reason") == "stop":
                                    break
                            break
                        if finish2 == "stop":
                            break

                if finish == "stop":
                    break

            # Capture reasoning
            try:
                from app.database import AsyncSessionLocal as ASL4
                async with ASL4() as gsess:
                    await capture_reasoning(
                        db=gsess, task_id=f"chat-{conv_id}",
                        turn_id=len([m for m in messages if m["role"] in ("assistant","tool")]) // 2 + 1,
                        llm_decision="流式对话回复完成" if not tool_calls_data else "工具执行 + 分析完成",
                        evidence_type="推理",
                        tool=tool_calls_data[0]["function"]["name"] if tool_calls_data else None,
                        result_summary=(full_content or "")[:200],
                        status="success", confidence_after=0.8,
                    )
            except Exception:
                pass
            # Save final analysis (no tool_calls)
            async with AsyncSessionLocal() as sess2:
                sess2.add(Message(
                    id=str(uuid.uuid4()), conversation_id=conv_id,
                    role="assistant", content=full_content,
                    tool_calls=None,
                ))
                conv2 = await sess2.get(Conversation, conv_id)
                if conv2:
                    conv2.updated_at = datetime.utcnow()
                await sess2.commit()
            yield f"data: {json.dumps({'token': '', 'done': True})}\n\n"

        except Exception as e:
            import traceback
            err = traceback.format_exc()
            yield f"data: {json.dumps({'error': str(e), 'detail': err, 'done': True})}\n\n"

    if stream:
        return StreamingResponse(event_stream(), media_type="text/event-stream")
    else:
        # Non-streaming: call once, auto-handle tool calls in a loop (up to 5 turns)
        try:
            messages_for_llm = messages[:]
            final_content = ""
            MAX_TURNS = 5
            for turn in range(MAX_TURNS):
                response = await llm_adapter.chat(messages=messages_for_llm, tools=TOOLS)
                choice = response["choices"][0]

                if choice["finish_reason"] == "tool_calls" and choice.get("message", {}).get("tool_calls"):
                    tcs = choice["message"]["tool_calls"]
                    messages_for_llm.append({
                        "role": "assistant", "content": choice["message"].get("content", "") or " ",
                        "tool_calls": tcs
                    })
                    for tc in tcs:
                        tc_result = await execute_tool_call(tc)
                        messages_for_llm.append({
                            "role": "tool", "tool_call_id": tc["id"], "content": tc_result
                        })
                    # One more LLM call without tools for analysis
                    analysis_resp = await llm_adapter.chat(messages=messages_for_llm)
                    final_content = analysis_resp["choices"][0]["message"].get("content", "")
                    break
                else:
                    final_content = choice["message"].get("content", "")
                    break

            # Save to DB
            async with AsyncSessionLocal() as sess2:
                asst_msg = Message(
                    id=str(uuid.uuid4()), conversation_id=conv_id,
                    role="assistant", content=final_content,
                )
                sess2.add(asst_msg)
                conv2 = await sess2.get(Conversation, conv_id)
                if conv2:
                    conv2.updated_at = datetime.utcnow()
                await sess2.commit()

            return {"token": final_content, "done": True}

        except Exception as e:
            import traceback
            return {"error": str(e), "detail": traceback.format_exc(), "done": True}


@router.post("/conversations/{conv_id}/reset-prompt")
async def reset_prompt(conv_id: str, user: User = Depends(optional_user)):
    """重置对话的 system prompt 缓存"""
    return {"ok": True}



@router.post("/send")
async def simple_send(data: dict, user: User = Depends(optional_user)):
    """简易发送接口 — 兼容前端 POST /chat/send 调用，非流式响应
    支持 tool call 循环：执行工具结果喂回 LLM，最多 5 轮。
    """
    text = data.get("message", "") or data.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="message is required")

    # 1. Check if LLM is configured
    from app.models.llm_provider import LLMProvider as Provider
    async with AsyncSessionLocal() as sess:
        provider = await sess.execute(select(Provider).where(Provider.is_active == True))
        provider_row = provider.scalar_one_or_none()
    if not provider_row:
        return {"reply": "请先在设置页面配置 LLM API Key 并启用", "type": "text"}

    # 2. Create conversation
    conv_id = str(uuid.uuid4())
    async with AsyncSessionLocal() as sess:
        conv = Conversation(
            id=conv_id, title=text[:50], user_id=user.id if user else None,
            created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        )
        sess.add(conv)
        user_msg = Message(id=str(uuid.uuid4()), conversation_id=conv_id, role="user", content=text)
        sess.add(user_msg)
        await sess.commit()

    # 3. Build messages context
    from app.llm.adapter import llm_adapter
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": text},
    ]

    final_reply = ""
    all_tool_results = []
    task_id = None
    max_rounds = 2

    for turn in range(max_rounds):
        # 4. Call LLM (non-streaming)
        try:
            raw = await llm_adapter.chat(messages=messages, tools=TOOLS)
            choice = raw.get("choices", [{}])[0]
            msg_obj = choice.get("message", {})
            reply_text = msg_obj.get("content", "") or ""
            tool_calls = msg_obj.get("tool_calls", [])
        except Exception as e:
            reply_text = f"LLM 调用失败: {str(e)}"
            tool_calls = []

        # Accumulate the final reply text from the last non-tool round
        if not tool_calls:
            final_reply = reply_text

        # 5. Save assistant message to DB (every round)
        async with AsyncSessionLocal() as sess:
            asst_msg = Message(
                id=str(uuid.uuid4()), conversation_id=conv_id,
                role="assistant",
                content=reply_text if tool_calls else (reply_text or " "),
                tool_calls=tool_calls if tool_calls else None,
            )
            sess.add(asst_msg)
            await sess.commit()

        # 6. Execute tool calls (if any)
        if not tool_calls:
            break

        tool_results = []
        for tc in tool_calls:
            try:
                result_str = await execute_tool_call(tc)
            except Exception as e:
                result_str = json.dumps({"error": str(e)})
            result_data = json.loads(result_str) if isinstance(result_str, str) else result_str
            if isinstance(result_data, dict) and result_data.get("task_id"):
                task_id = result_data["task_id"]
            tc_name = tc.get("function", {}).get("name", "")
            all_tool_results.append({"name": tc_name, "content": result_str})
            tool_results.append({"tool_call_id": tc.get("id"), "content": result_str})

        # 7. Save tool results to DB
        async with AsyncSessionLocal() as sess:
            for r in tool_results:
                tool_msg = Message(
                    id=str(uuid.uuid4()), conversation_id=conv_id,
                    role="tool", content=r["content"],
                    tool_call_id=r["tool_call_id"],
                )
                sess.add(tool_msg)
            await sess.commit()

        # 8. Feed tool results back to LLM for next round
        messages.append({"role": "assistant", "content": reply_text or " ", "tool_calls": tool_calls})
        for r in tool_results:
            messages.append({"role": "tool", "tool_call_id": r["tool_call_id"], "content": r["content"]})

    # Fallback: if LLM never gave a text-only response, generate one
    if not final_reply and all_tool_results:
        if all_tool_results[0]["name"] == "start_scan":
            final_reply = task_id and f"扫描已启动，任务ID：{task_id}" or "扫描已启动"
        else:
            final_reply = "✅ 已处理，任务进行中，请稍候查看结果。"

    return {
        "reply": final_reply,
        "task_id": task_id,
        "conversation_id": conv_id,
        "type": "scan" if task_id else "text",
        "tool_calls_executed": len(all_tool_results),
    }

