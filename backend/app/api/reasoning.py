"""推理日志展示 API — 对话即证据链 的前端支撑"""
import json
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import create_engine, text

router = APIRouter()
from app.config import settings
DB = settings.DATABASE_URL.replace("+asyncpg", "")


@router.get("/chain/{task_id}")
async def get_reasoning_chain(task_id: str, limit: int = Query(100, le=200)):
    """获取指定任务的推理链"""
    eng = create_engine(DB)
    try:
        with eng.begin() as conn:
            r = conn.execute(
                text("""SELECT id, turn_id, llm_decision, llm_reasoning, evidence_type,
                                tool, target, result_summary, confidence_before, confidence_after,
                                risk_level, status, phase, duration_ms, created_at
                         FROM execution_steps
                         WHERE task_id = :task_id
                         ORDER BY turn_id ASC, created_at ASC
                         LIMIT :limit"""),
                {"task_id": task_id, "limit": limit}
            )
            steps = []
            for row in r:
                steps.append({
                    "id": row[0],
                    "turn_id": row[1],
                    "llm_decision": row[2],
                    "llm_reasoning": row[3],
                    "evidence_type": row[4],
                    "tool": row[5],
                    "target": row[6],
                    "result_summary": row[7],
                    "confidence_before": row[8],
                    "confidence_after": row[9],
                    "risk_level": row[10],
                    "status": row[11],
                    "phase": row[12],
                    "duration_ms": row[13],
                    "created_at": str(row[14]) if row[14] else None,
                })
            return {"task_id": task_id, "total": len(steps), "steps": steps}
    finally:
        eng.dispose()


@router.get("/session/{conv_id}")
async def get_session_reasoning(conv_id: str):
    """获取一次对话的推理链 (task_id = chat-{conv_id})"""
    return await get_reasoning_chain(f"chat-{conv_id}")




@router.get("/stats")
async def get_reasoning_stats():
    """获取推理链统计概览"""
    eng = create_engine(DB)
    try:
        with eng.begin() as conn:
            r = conn.execute(text("""
                SELECT COUNT(DISTINCT task_id) as sessions,
                       COUNT(*) as total_steps,
                       COUNT(DISTINCT turn_id) as total_turns,
                       COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
                       COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count,
                       COUNT(CASE WHEN confidence_after >= 0.7 THEN 1 END) as high_confidence
                FROM execution_steps
            """))
            row = r.fetchone()
            r2 = conn.execute(text("""
                SELECT evidence_type, COUNT(*) as cnt
                FROM execution_steps GROUP BY evidence_type ORDER BY cnt DESC
            """))
            types = {r[0]: r[1] for r in r2}
            return {
                "sessions": row[0],
                "total_steps": row[1],
                "total_turns": row[2],
                "success_count": row[3],
                "failed_count": row[4],
                "high_confidence": row[5],
                "by_evidence_type": types,
            }
    finally:
        eng.dispose()

@router.post("/decide")
async def run_decision_loop(data: dict):
    """
    决策循环 API — 基于扫描结果运行智能攻击链决策
    """
    try:
        from app.services.decision_integration import DecisionOrchestrator
        from app.services.scan_tools import execute_tool_call
        
        target = data.get("target", "")
        task_id = data.get("task_id", "")
        vulns = data.get("vulnerabilities", [])
        max_steps = data.get("max_steps", 10)
        
        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        
        async def rag_search(query: str) -> list[dict]:
            import httpx
            try:
                resp = await httpx.AsyncClient(timeout=15).post(
                    "http://yunjing-backend:8000/api/engine/experience/search",
                    json={"query": query, "top_k": 5},
                )
                if resp.status_code == 200:
                    return resp.json().get("results", [])
            except:
                pass
            return []
        
        async def llm_chat(user_msg: str, system: str) -> str:
            from app.llm.adapter import llm_adapter
            msgs = [{"role": "system", "content": system}, {"role": "user", "content": user_msg}]
            full = ""
            async for chunk in llm_adapter.chat_stream(messages=msgs):
                for c in chunk.get("choices", []):
                    d = c.get("delta", {})
                    if d.get("content"):
                        full += d["content"]
            return full
        
        orch = DecisionOrchestrator(
            execute_tool=execute_tool_call,
            llm_chat_func=llm_chat,
            rag_search=rag_search,
            max_loop_steps=max_steps,
        )
        return await orch.run(target=target, initial_vulns=vulns, task_id=task_id)
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(e))
"""
追加到 reasoning.py 末尾的 next-step 端点
"""
import json, httpx
from fastapi import APIRouter, HTTPException

# ============================================================
#  单步决策 API — Worker 决策循环的智能后端
#  接收当前扫描状态 → RAG检索 → LLM决策 → 返回下一步动作
# ============================================================

# 可用动作列表（供LLM参考）
from app.services.worker_actions import WORKER_ACTIONS


@router.post("/next-step")
async def decide_next_step(data: dict):
    """
    单步决策 API - Worker 每完成一个动作后调用此 API 决定下一步
    
    请求格式:
    {
        "task_id": "...",
        "target": "http://192.168.1.180:8080",
        "step": 3,
        "elapsed_seconds": 120,
        "ports": [22, 80, 8080],
        "services": {"8080": {"name": "http", "product": "Apache httpd", "version": "2.4.25"}},
        "vulnerabilities": [{"title": "DVWA Login", "severity": "critical"}],
        "credentials": [{"service": "http", "username": "admin", "password": "admin"}],
        "actions_taken": ["quick_port_scan", "service_detect"],
        "stale_count": 0,
        "max_remaining": 27,
    }
    
    返回格式:
    {
        "action": "vuln_scan",
        "params": {"ports": [8080], "tags": "cve,apache"},
        "reasoning": "Apache 2.4.25 有已知CVE...",
        "rag_insights": "..."
    }
    """
    try:
        target = data.get("target", "")
        step = data.get("step", 1)
        max_remaining = data.get("max_remaining", 25)
        stale_count = data.get("stale_count", 0)
        
        # 构建当前状态文本
        ports = data.get("ports", [])
        services = data.get("services", {})
        vulns = data.get("vulnerabilities", [])
        credentials = data.get("credentials", [])
        sessions = data.get("sessions", [])
        actions_taken = data.get("actions_taken", [])
        sessions = data.get("sessions", [])
        
        # 如果没有端口信息，第一步必然是端口扫描
        if not ports and step <= 2:
            return {
                "action": "quick_port_scan",
                "params": {},
                "reasoning": "尚无端口信息，先快速扫描发现开放端口",
                "rag_insights": ""
            }
        
        # 如果有端口但没服务信息
        need_service_detect = ports and not services
        if need_service_detect and step <= 5:
            return {
                "action": "service_detect",
                "params": {"ports": ports},
                "reasoning": f"已发现 {len(ports)} 个端口但尚无服务信息，进行版本探测",
                "rag_insights": ""
            }
        
        # ====== RAG检索 ======
        rag_query = f"penetration test {target}"
        if vulns:
            rag_query += " " + " ".join(v.get("title", "")[:50] for v in vulns[:3])
        elif services:
            svc_names = [s.get("product", s.get("name", "")) for s in services.values()]
            rag_query += " " + " ".join(svc_names[:3])
        
        rag_results = []
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    "http://yunjing-backend:8000/api/engine/experience/search",
                    json={"query": rag_query, "top_k": 5},
                )
                if resp.status_code == 200:
                    rag_results = resp.json().get("results", [])
        except:
            pass
        
        # ====== 构建LLM prompt ======
        state_desc = f"""## 当前渗透状态
目标: {target}
步骤: {step}/{step + max_remaining}
已用时间: {data.get('elapsed_seconds', 0)}秒
连续无新发现: {stale_count}轮

### 已发现端口: {ports if ports else '无'}
### 已识别服务: {json.dumps(services, ensure_ascii=False)[:300] if services else '无'}
### 已发现漏洞:
{vulns[:5] if vulns else '暂无'}
### 已获取凭据: {credentials if credentials else '暂无'}
### 已有会话: {sessions if sessions else '暂无'}
### 已执行动作: {actions_taken}
"""
        
        rag_context = ""
        if rag_results:
            rag_context = "### 经验库检索结果（供参考）:\n"
            for i, r in enumerate(rag_results[:3], 1):
                title = r.get("title", r.get("metadata", {}).get("title", "?"))
                summary = r.get("content", "")[:200]
                target_type = r.get("metadata", {}).get("target_type", "?")
                rag_context += f"{i}. [{target_type}] {title}\n   {summary}\n\n"
        
        actions_desc = "\n".join(
            f"- {a['id']}: {a['description']}" 
            for a in WORKER_ACTIONS
        )
        
        system_prompt = f"""你是一个专业的渗透测试决策AI。根据当前渗透状态和RAG经验，选择下一步最合适的动作。

可用的动作列表:
{actions_desc}

规则:
1. 已有端口但无服务信息 → 优先 service_detect
2. 已有服务和版本 → 优先 vuln_scan（按版本搜索已知漏洞）
3. 发现Web服务(80/443/8080/8443等) → 考虑 dir_bruteforce / web_tech_detect
4. 发现登录页面 → 考虑 auth_bypass_test / credential_test
5. 发现API端点 → 考虑 api_scan
6. 发现SQL注入线索 → 考虑 sql_injection_test
7. 发现SMB(445) → 考虑 smb_enum
8. 有凭据/弱口令结果 → 优先 exploit（尝试建立会话）
9. 有活动会话(≥3个) → **必须** post_exploit（信息收集/凭据提取/内网探测）；只需1个会话也要优先尝试
10. 连续3轮没新发现 → 切换策略，尝试不同方向
11. 如果所有方向都探索过 → 返回 complete
12. 每步只选一个动作，集中火力

输出格式（仅返回JSON，不要其他文字）:
{{"action": "动作ID", "params": {{}}, "reasoning": "为什么选这个动作"}}"""
        
        # ====== LLM调用 ======
        from app.llm.adapter import llm_adapter
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": state_desc + "\n\n" + rag_context + "\n请选择下一步动作并说明理由。"}
        ]
        
        full_response = ""
        async for chunk in llm_adapter.chat_stream(messages=messages):
            for c in chunk.get("choices", []):
                d = c.get("delta", {})
                if d.get("content"):
                    full_response += d["content"]
        
        # ====== 解析LLM输出 ======
        import re
        decision = {}
        
        # 尝试JSON解析
        json_match = re.search(r'\{[^{}]*\}', full_response, re.DOTALL)
        if json_match:
            try:
                decision = json.loads(json_match.group())
            except:
                pass
        
        if not decision or "action" not in decision:
            # fallback: 从文本提取
            for a in WORKER_ACTIONS:
                if a["id"] in full_response:
                    decision = {"action": a["id"], "params": {}, "reasoning": full_response[:200]}
                    break
            
            if not decision:
                # 最终fallback
                decision = {
                    "action": "vuln_scan", 
                    "params": {},
                    "reasoning": "LLM未能解析，默认执行漏洞扫描"
                }
        
        return {
            "action": decision.get("action", "vuln_scan"),
            "params": decision.get("params", {}),
            "reasoning": decision.get("reasoning", full_response)[:300],
            "rag_insights": rag_context[:300]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"决策失败: {str(e)}")

12061
