"""对话 API：持久化会话 + LLM Function Calling"""
import logging
import json, uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
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
from app.config import settings
from app.models.setting import SystemSetting
from app.api.chat_helpers import SYSTEM_PROMPT
from app.api.chat_stream import chat_stream, _pending_tool_calls

router = APIRouter()

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
    return await chat_stream(conv_id, data, user, None, llm_adapter, TOOLS)


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


# ═══════════════════════════════════════════════════════════
#  Suggestion 确认 API
# ═══════════════════════════════════════════════════════════


@router.post("/suggestions/respond")
async def respond_to_suggestion(data: dict):
    """用户对工具调用建议的回应（确认/否决/修改）"""
    action = data.get("type", "")  # "confirm", "reject", "modify"
    tool_call_id = data.get("tool_call_id", "")
    params = data.get("params", None)

    # 从 _pending_tool_calls 中查找所属 conv（遍历所有 conv）
    pending_conv_id: str | None = None
    pending_tc = None
    for cid, tcs in _pending_tool_calls.items():
        for tc in tcs:
            if tc.get("id") == tool_call_id or tc.get("id", "").startswith(tool_call_id):
                pending_conv_id = cid
                pending_tc = tc
                break
        if pending_conv_id:
            break

    if not pending_tc or not pending_conv_id:
        return {"status": "error", "message": "该建议已过期或不存在"}

    if action == "confirm":
        # 执行工具
        try:
            result_str = await execute_tool_call(pending_tc)
        except Exception as e:
            return {"status": "error", "message": f"工具执行失败: {str(e)}"}

        # 把结果写入 messages（写入 DB）
        try:
            async with AsyncSessionLocal() as sess:
                # 保存 tool 结果
                sess.add(Message(
                    id=str(uuid.uuid4()), conversation_id=pending_conv_id,
                    role="tool", content=result_str, tool_call_id=pending_tc.get("id", tool_call_id),
                ))
                conv = await sess.get(Conversation, pending_conv_id)
                if conv:
                    conv.updated_at = datetime.utcnow()
                await sess.commit()
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to save confirmed tool result: {e}")

        # 清除 pending
        _pending_tool_calls.pop(pending_conv_id, None)

        return {"status": "ok", "result": result_str, "message": "工具已执行"}

    elif action == "reject":
        _pending_tool_calls.pop(pending_conv_id, None)
        return {"status": "ok", "message": "已否决"}

    elif action == "modify":
        if params:
            pending_tc["function"]["arguments"] = json.dumps(params, ensure_ascii=False)
        try:
            result_str = await execute_tool_call(pending_tc)
        except Exception as e:
            return {"status": "error", "message": f"工具执行失败: {str(e)}"}

        try:
            async with AsyncSessionLocal() as sess:
                sess.add(Message(
                    id=str(uuid.uuid4()), conversation_id=pending_conv_id,
                    role="tool", content=result_str, tool_call_id=pending_tc.get("id", tool_call_id),
                ))
                conv = await sess.get(Conversation, pending_conv_id)
                if conv:
                    conv.updated_at = datetime.utcnow()
                await sess.commit()
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to save modified tool result: {e}")

        _pending_tool_calls.pop(pending_conv_id, None)
        return {"status": "ok", "result": result_str, "message": "已修改并执行"}

    return {"status": "error", "message": f"未知操作类型: {action}"}
