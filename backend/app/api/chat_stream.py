"""SSE 流式对话处理器"""
import logging
import json
import re
import uuid
from datetime import datetime
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.conversation import Conversation, Message
from app.models.setting import SystemSetting
from app.config import settings
from app.grounding.reasoning_capture import capture_reasoning
from app.grounding.target_parser import extract_target, format_target_summary
from app.services.scan_tools import execute_tool_call
from app.api.chat_helpers import (
    _tool_summary, _build_skills_section, _build_rag_context,
    SYSTEM_PROMPT, _SKILLS_PH,
)

logger = logging.getLogger(__name__)

# ── 对话决策模式：pending tool calls ──
_pending_tool_calls: dict[str, list[dict]] = {}  # conv_id → pending tool_call list

CONFIRM_KEYWORDS = ["干", "好", "确认", "可以", "试试", "来吧", "yes", "do it", "y", "是", "ok", "好的", "行", "中", "搞"]
REJECT_KEYWORDS = ["不", "不用", "否决", "算了", "no", "n", "不干", "不要", "不了", "别", "取消"]

# ── 工具自动执行 vs 需确认 ──
_AUTO_EXECUTE_TOOLS = {
    "start_scan", "_action_port_scan", "_action_service_detect",
    "_action_vuln_scan", "_action_dir_bruteforce", "_action_web_fingerprint",
    "_action_full_port_scan", "check_tool", "search_kali_tools", "run_tool",
    "get_task_status", "get_task_vulnerabilities", "execute_scan_phase", "get_tools_status",
}

_CONFIRM_REQUIRED_TOOLS = {
    "_action_exploit", "_action_post_exploit", "_action_sql_injection",
    "_action_auth_bypass", "_action_credential_test", "_action_ssh_bruteforce",
    "exploit", "upload_payload", "reverse_shell",
}


async def chat_stream(conv_id, data, user, db, llm_adapter, TOOLS):
    """对话式渗透 — 每次消息都是一次交互（SSE 流式版本）"""
    text = data.get("text", "")
    stream = data.get("stream", True)
    history = data.get("history", None)
    mode = data.get("mode", "expert")
    if mode not in ["expert", "verify", "scanner", "assault"]:
        mode = "expert"

    # ── T7 安全约束层 ──
    from app.core.config import MODE_CONSTRAINTS
    constraints = MODE_CONSTRAINTS.get(mode, {})
    PAYLOAD_TOOL_PATTERNS = ["_action_exploit", "_action_post_exploit", "exploit", "post_exploit"]

    def _is_payload_tool(name: str) -> bool:
        for p in PAYLOAD_TOOL_PATTERNS:
            if p in name:
                return True
        return False

    def _filter_tool_calls(tcs: list[dict]) -> list[dict]:
        """根据 block_payload 约束过滤工具调用"""
        if not constraints.get("block_payload", False):
            return tcs
        return [tc for tc in tcs if not _is_payload_tool(tc.get("function", {}).get("name", ""))]

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

        # 根据 mode 加载额外 system prompt
        import os
        prompt_path = os.path.join(os.path.dirname(__file__), "../core/prompts", mode + ".md")
        if os.path.exists(prompt_path):
            try:
                with open(prompt_path, encoding="utf-8") as f:
                    mode_prompt = f.read().strip()
                if mode_prompt:
                    system_content += "\n\n" + mode_prompt
            except Exception as e:
                logger.warning(f"Failed to load mode prompt '{mode}.md': {e}")

        # ── RAG 上下文注入 ──
        try:
            from app.engine.vector_store import RAGEngine
            _rag = RAGEngine()
            _user_msg = data.get("message", "")
            if _user_msg.strip():
                _exps = _rag.search(_user_msg, top_k=3, collections=["experience"])
                _knows = _rag.search(_user_msg, top_k=2, collections=["knowledge"])
                _parts = []
                for _src in [("【历史经验】", _exps), ("【相关知识】", _knows)]:
                    if _src[1]:
                        _parts.append(_src[0])
                        for _e in _src[1]:
                            _p = _e.get("payload", {})
                            _txt = _p.get("text", _p.get("content", "")) if isinstance(_p, dict) else str(_p)
                            if _txt:
                                _parts.append(f"- {_txt[:120]}")
                if _parts:
                    system_content += "\n\n参考信息（基于历史经验和知识库）：\n" + "\n".join(_parts)
        except Exception:
            pass

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
        except Exception as e:
            logger.warning(f"Failed to save user message: {e}")

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

            # ── 对话决策模式：检查有无 pending tool call 等待用户确认 ──
            pending_tool_calls = _pending_tool_calls.pop(conv_id, None)
            if pending_tool_calls:
                user_msg_lower = text.lower().strip()
                is_confirm = any(re.search(rf'\b{re.escape(k)}\b', user_msg_lower) for k in CONFIRM_KEYWORDS)
                is_reject = any(re.search(rf'\b{re.escape(k)}\b', user_msg_lower) for k in REJECT_KEYWORDS)

                if is_confirm:
                    # 用户确认 → 执行 pending tools
                    results = []
                    for tc in pending_tool_calls:
                        tc_name = tc["function"]["name"]
                        yield f"data: {json.dumps({'type': 'tool_call', 'name': tc_name, 'arguments': tc.get('function', {}).get('arguments', '{}')})}\n\n"
                        tc_result = await execute_tool_call(tc)
                        yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name, 'result': json.loads(tc_result) if isinstance(tc_result, str) else tc_result})}\n\n"
                        results.append({"tool_call_id": tc["id"], "content": tc_result})

                    # 移除用户确认消息（避免干扰 LLM 上下文中的消息顺序）
                    for i in range(len(messages) - 1, -1, -1):
                        if messages[i].get("role") == "user":
                            messages.pop(i)
                            break

                    # 添加 tool 结果到 messages
                    for r in results:
                        messages.append({"role": "tool", "tool_call_id": r["tool_call_id"], "content": r["content"]})

                    # 保存 tool 结果到 DB
                    try:
                        async with AsyncSessionLocal() as _save_sess:
                            for r in results:
                                _save_sess.add(Message(
                                    id=str(uuid.uuid4()), conversation_id=conv_id,
                                    role="tool", content=r["content"], tool_call_id=r["tool_call_id"],
                                ))
                            await _save_sess.commit()
                    except Exception as e:
                        logger.error(f"Failed to save tool results: {e}", exc_info=True)

                elif is_reject:
                    # 用户否决 → 添加拒绝说明到 messages
                    for i in range(len(messages) - 1, -1, -1):
                        if messages[i].get("role") == "user":
                            messages.pop(i)
                            break
                    messages.append({"role": "user", "content": "用户否决了建议，请给出替代方案"})

                else:
                    # 用户修改或其它 → 让 LLM 按修改后的意图重新处理
                    for i in range(len(messages) - 1, -1, -1):
                        if messages[i].get("role") == "user":
                            messages.pop(i)
                            break
                    messages.append({"role": "user", "content": f"用户修改了参数: {text}"})

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

                if finish == "tool_calls" and tool_calls_data:
                    done_reason = "tool_calls"

                    # ── T7 安全约束层：allow_tools 检查 ──
                    if not constraints.get("allow_tools", True):
                        expert_msg = "当前是专家模式，不支持工具调用"
                        yield f"data: {json.dumps({'token': expert_msg, 'done': False})}\\n\\n"
                        yield f"data: {json.dumps({'token': '', 'done': True})}\\n\\n"
                        return

                    # ── T7 安全约束层：block_payload 过滤 ──
                    tool_calls_data = _filter_tool_calls(tool_calls_data)
                    if not tool_calls_data:
                        # 所有工具被过滤掉，返回提示
                        blocked_msg = "当前模式禁止执行 payload 类操作"
                        yield f"data: {json.dumps({'token': blocked_msg, 'done': False})}\\n\\n"
                        yield f"data: {json.dumps({'token': '', 'done': True})}\\n\\n"
                        return

                    # ── 对话决策模式：自动执行 vs 需要确认 ──
                    # 判断是否需要用户确认
                    needs_confirm = any(
                        tc["function"]["name"] in _CONFIRM_REQUIRED_TOOLS
                        for tc in tool_calls_data
                    )

                    if not needs_confirm:
                        # ── 自动执行路径（扫描/信息收集类工具） ──
                        # 1. 保存 assistant 消息（含 tool_calls）到 messages 和 DB
                        asst_content = (full_content or "") or _tool_summary(tool_calls_data)
                        asst_dict = {
                            "role": "assistant",
                            "content": asst_content,
                            "tool_calls": tool_calls_data,
                        }
                        if reasoning_content:
                            asst_dict["reasoning_content"] = reasoning_content
                        messages.append(asst_dict)
                        try:
                            async with AsyncSessionLocal() as _save_sess:
                                _save_sess.add(Message(
                                    id=str(uuid.uuid4()), conversation_id=conv_id,
                                    role="assistant", content=asst_content, tool_calls=tool_calls_data,
                                ))
                                await _save_sess.commit()
                        except Exception as e:
                            logger.error(f"Failed to save assistant with tool_calls: {e}", exc_info=True)

                        # 2. 执行工具并发送事件
                        tool_results = []
                        for tc in tool_calls_data:
                            tc_name = tc["function"]["name"]
                            try:
                                tc_args = json.loads(tc["function"]["arguments"])
                            except:
                                tc_args = {}
                            yield f"data: {json.dumps({'type': 'tool_call', 'name': tc_name, 'arguments': tc_args})}\n\n"
                            tc_result = await execute_tool_call(tc)
                            yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name, 'result': json.loads(tc_result) if isinstance(tc_result, str) else tc_result})}\n\n"
                            tool_results.append({"tool_call_id": tc["id"], "content": tc_result})

                        # 3. 添加工具结果到 messages
                        for r in tool_results:
                            messages.append({"role": "tool", "tool_call_id": r["tool_call_id"], "content": r["content"]})

                        # 4. 保存工具结果到 DB
                        try:
                            async with AsyncSessionLocal() as _save_sess:
                                for r in tool_results:
                                    _save_sess.add(Message(
                                        id=str(uuid.uuid4()), conversation_id=conv_id,
                                        role="tool", content=r["content"], tool_call_id=r["tool_call_id"],
                                    ))
                                await _save_sess.commit()
                        except Exception as e:
                            logger.error(f"Failed to save tool results: {e}", exc_info=True)

                        # 5. 继续 LLM 流式分析（带工具结果的新一轮对话）
                        full_content = ""
                        reasoning_content = None
                        tool_calls_data = None
                        _analysis_done = False

                        async for _chunk2 in llm_adapter.chat_stream(messages=messages, tools=TOOLS):
                            _choices2 = _chunk2.get("choices", [])
                            if not _choices2:
                                continue
                            _choice2 = _choices2[0]
                            _delta2 = _choice2.get("delta", {})
                            _finish2 = _choice2.get("finish_reason")

                            if _delta2.get("reasoning_content"):
                                if _delta2["reasoning_content"]:
                                    _rc = _delta2["reasoning_content"]
                                    reasoning_content = (reasoning_content or "") + _rc
                                    yield f"data: {json.dumps({'type': 'reasoning', 'content': _rc})}\n\n"
                                continue

                            if _delta2.get("tool_calls"):
                                # 分析阶段再次请求工具调用 → 简单跳过，避免无限循环
                                _analysis_done = True
                                break

                            _content2 = _delta2.get("content", "")
                            if _content2:
                                full_content += _content2
                                yield f"data: {json.dumps({'token': _content2, 'done': False})}\n\n"

                            if _finish2 == "stop":
                                _analysis_done = True
                                break

                        # 6. 保存最终分析结果
                        if full_content:
                            try:
                                async with AsyncSessionLocal() as _save_sess:
                                    _save_sess.add(Message(
                                        id=str(uuid.uuid4()), conversation_id=conv_id,
                                        role="assistant", content=full_content, tool_calls=None,
                                    ))
                                    _conv2 = await _save_sess.get(Conversation, conv_id)
                                    if _conv2:
                                        _conv2.updated_at = datetime.utcnow()
                                    await _save_sess.commit()
                            except Exception as e:
                                logger.error(f"Failed to save analysis: {e}", exc_info=True)

                        yield f"data: {json.dumps({'token': '', 'done': True})}\n\n"
                        return

                    else:
                        # ── 需要确认路径（利用/渗透类工具） ──
                        # 1. 保存 assistant 消息（含 tool_calls）到 messages 和 DB
                        asst_content = (full_content or "") or _tool_summary(tool_calls_data)
                        asst_dict = {
                            "role": "assistant",
                            "content": asst_content,
                            "tool_calls": tool_calls_data,
                        }
                        if reasoning_content:
                            asst_dict["reasoning_content"] = reasoning_content
                        messages.append(asst_dict)
                        try:
                            async with AsyncSessionLocal() as _save_sess:
                                _save_sess.add(Message(
                                    id=str(uuid.uuid4()), conversation_id=conv_id,
                                    role="assistant", content=asst_content, tool_calls=tool_calls_data,
                                ))
                                await _save_sess.commit()
                        except Exception as e:
                            logger.error(f"Failed to save assistant with tool_calls: {e}", exc_info=True)

                        # 2. 为每个 tool call 吐出 suggestion 事件
                        for tc in tool_calls_data:
                            tc_name = tc["function"]["name"]
                            try:
                                tc_args = json.loads(tc["function"]["arguments"])
                            except:
                                tc_args = {}
                            yield f"data: {json.dumps({'type': 'suggestion', 'tool': tc_name, 'params': tc_args, 'tool_call_id': tc.get('id', '')})}\n\n"

                        # 3. 存储 pending，等用户下一次消息确认
                        _pending_tool_calls[conv_id] = tool_calls_data

                        # 4. 结束当前 SSE 流
                        yield f"data: {json.dumps({'token': '', 'done': True})}\n\n"
                        return

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
            except Exception as e:
                logger.warning(f"Save failed: {e}", exc_info=True)
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

                    # ── T7 安全约束层：allow_tools 检查 ──
                    if not constraints.get("allow_tools", True):
                        final_content = "当前是专家模式，不支持工具调用"
                        break

                    # ── T7 安全约束层：block_payload 过滤 ──
                    tcs = _filter_tool_calls(tcs)
                    if not tcs:
                        final_content = "当前模式禁止执行 payload 类操作"
                        break

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
