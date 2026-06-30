"""SSE 流式对话处理器"""
import logging
import json
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


async def chat_stream(conv_id, data, user, db, llm_adapter, TOOLS):
    """对话式渗透 — 每次消息都是一次交互（SSE 流式版本）"""
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
                        except Exception as e:
                            logger.warning(f"Capture tool result failed: {e}")
                        tc_result = await execute_tool_call({
                            "id": tc["id"],
                            "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]}
                        })
                        yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name, 'result': json.loads(tc_result) if isinstance(tc_result, str) else tc_result})}\n\n"
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
                        except Exception as e:
                            logger.warning(f"Capture tool result failed: {e}")

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
                                role="assistant", content=(full_content or "") or _tool_summary(tool_calls_data), tool_calls=tool_calls_data))
                            for _r in results:
                                _save_sess.add(Message(id=str(uuid.uuid4()), conversation_id=conv_id,
                                    role="tool", content=_r["content"], tool_call_id=_r["tool_call_id"]))
                            await _save_sess.commit()
                    except Exception as e:
                        logger.error(f"Failed to save assistant/tool messages: {e}", exc_info=True)


                    # ⭐ WebSocket 实时接收扫描进度 ⭐
                    if tool_calls_data and any(tc.get("function",{}).get("name")=="start_scan" for tc in tool_calls_data):
                        try:
                            task_id = json.loads(tc_result).get("task_id", "")
                            if task_id:
                                yield "data: {\"token\": \"扫描已启动，任务ID: " + task_id[:12] + "...\\n完成后将自动分析并推送结果。\\n\", \"done\": false}\n\n"
                                # 记录 conversation_id 到 scan_tasks
                                try:
                                    from app.database import AsyncSessionLocal as _CSave
                                    from sqlalchemy import text as _ctext
                                    async with _CSave() as _csess:
                                        await _csess.execute(_ctext(
                                            "UPDATE scan_tasks SET conversation_id=:conv WHERE id=:id"
                                        ), {"conv": conv_id, "id": task_id})
                                        await _csess.commit()
                                except Exception:
                                    pass
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
                                yield f"data: {json.dumps({'type': 'tool_result', 'name': tc_name2, 'result': json.loads(tc_r2) if isinstance(tc_r2, str) else tc_r2})}\n\n"
                                messages.append({"role": "tool", "tool_call_id": tc2["id"], "content": tc_r2})
                                _t2_acc.append({"id": tc2["id"], "content": tc_r2})
                            # save second round
                            try:
                                async with AsyncSessionLocal() as _s:
                                    _s.add(Message(id=_a2_id, conversation_id=conv_id,
                                        role="assistant", content=full_content or _tool_summary(tcd2_accum), tool_calls=tcd2_accum))
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
                                    yield f"data: {{'token': '\\n🧠 **%d 个发现，启动智能决策引擎...**\\n', 'done': False}}\\\n\\n" % len(_vulns)

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
                                            _report_lines = ["\n🎯 **智能决策分析 — 可深入方向:**"]
                                            for _a in _acts[:3]:
                                                _report_lines.append(f"  - {'✅' if _a['success'] else '✨'} {_a['action']} → {_a['reasoning'][:100]}")
                                            _report = "\n".join(_report_lines)
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
