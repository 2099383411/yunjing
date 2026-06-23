"""
决策循环集成模块 — 连接 chat.py 与 decision_loop.py
=====================================================

把「全自动扫大街」模式升级为「智能决策循环」模式：

流程:
  1. 初始完整扫描（现有 start_scan 逻辑）
  2. 分析结果填充 AttackState
  3. RAG 检索相关经验
  4. LLM 决策下一步（针对性扫描 vs 停止）
  5. 执行单步（调用 start_scan 指定 skills 或直接执行工具）
  6. 更新状态，回到第3步
  7. 循环直到: 死循环检测触发 / 达到最大步数 / LLM判定完成 / 用户打断

用法:
    from services.decision_integration import DecisionOrchestrator
    orchestrator = DecisionOrchestrator()
    result = await orchestrator.run(target, initial_results, yield_callback)
"""

import json, asyncio, time, logging
from datetime import datetime
from typing import Callable, Optional

from .attack_state import AttackState, AttackStep, Asset, Credential, Exploit
from .anti_loop import AntiLoopDetector

logger = logging.getLogger(__name__)


class DecisionOrchestrator:
    """
    决策编排器 — 将 DecisionLoop 接入聊天流程
    
    yield_callback: 用于向 SSE 流推送消息的异步函数
    execute_tool: 用于执行工具调用的异步函数 (tool_call_dict) → str
    rag_search: RAG 搜索函数 (query) → list[dict]
    """
    
    def __init__(self,
                 execute_tool: Callable,
                 llm_chat_func: Callable,
                 rag_search: Optional[Callable] = None,
                 max_loop_steps: int = 10,
                 yield_callback: Optional[Callable] = None):
        
        self.execute_tool = execute_tool
        self.llm_chat = llm_chat_func
        self.rag_search = rag_search
        self.max_loop_steps = max_loop_steps
        self.yield_callback = yield_callback
        
        self.state: Optional[AttackState] = None
        self.anti_loop = AntiLoopDetector()
    
    async def _yield(self, msg: str):
        """推送消息到 SSE 流"""
        if self.yield_callback is not None:
            if asyncio.iscoroutinefunction(self.yield_callback):
                await self.yield_callback(msg)
    
    async def run(self, target: str, initial_vulns: list[dict] = None, task_id: str = "") -> dict:
        """
        执行决策循环
        
        参数:
            target: 目标资产
            initial_vulns: 初始扫描发现的漏洞列表
            task_id: 原始扫描任务 ID
        
        返回:
            {
                "status": "completed" | "stopped" | "max_steps" | "error",
                "loop_count": int,
                "actions_taken": [...],  # 决策的每一步
                "summary": str,
                "state": {...}
            }
        """
        # 初始化状态
        self.state = AttackState(target=target, task_id=task_id)
        self.state.current_phase = "decision_loop"
        
        # 将初始扫描结果注入状态
        if initial_vulns:
            await self._inject_initial_findings(initial_vulns)
        
        await self._yield(f"\n🧠 **决策循环引擎启动** — 基于发现结果智能决策下一步\n")
        await self._yield(f"📊 当前发现: {len(self.state.exploits)}个可利用点, {len(self.state.assets)}个资产\n\n")
        
        loop_count = 0
        actions_taken = []
        
        while loop_count < self.max_loop_steps:
            loop_count += 1
            
            # 1. 感知
            state_summary = self.state.summarize()
            
            # 2. RAG 检索
            experiences = await self._rag_retrieve()
            
            # 3. LLM 决策
            decision = await self._decide(state_summary, experiences)
            
            action = decision.get("action", "stop")
            if action == "stop":
                await self._yield(f"✅ **决策完成** — {decision.get('reasoning', '无进一步操作')}\n")
                break
            
            await self._yield(f"\n🔍 **决策#{loop_count}**: {decision.get('reasoning', '')}\n")
            await self._yield(f"⚡ 执行: {action} → {decision.get('target', target)} (工具: {decision.get('tool', '自动')})\n")
            
            # 4. 执行
            result = await self._execute_decision(decision, target)
            
            # 5. 更新状态
            await self._update_from_result(decision, result, target)
            
            actions_taken.append({
                "step": loop_count,
                "action": action,
                "target": decision.get("target", target),
                "tool": decision.get("tool", ""),
                "reasoning": decision.get("reasoning", ""),
                "success": result.get("status") not in ("error", "skipped"),
                "findings_count": len(result.get("findings", []))
            })
            
            # 6. 反死循环检测
            is_looping, reasons = self.anti_loop.check(self.state)
            if is_looping:
                suggestion = self.anti_loop.suggest_switch(self.state)
                await self._yield(f"⚠️ **检测到死循环**: {'; '.join(reasons)}\n")
                await self._yield(f"💡 建议: {suggestion}\n")
                
                # 如果连续两轮都是死循环，直接停止
                if self.state.consecutive_stale_rounds >= 7:
                    await self._yield(f"🛑 **连续7轮无进展，自动停止决策循环**\n")
                    break
            
            # 7. 如果整体进展很高，也停止
            if self.state.overall_progress >= 0.95:
                await self._yield(f"🎯 目标达成率很高，停止决策循环\n")
                break
        
        # 构建最终结果
        final_state = self.state.to_dict() if self.state else {}
        final_summary = self.state.summarize() if self.state else "无状态"
        
        await self._yield(f"\n📋 **决策循环结束** — 共{loop_count}轮, {len(actions_taken)}个操作\n")
        
        return {
            "status": "completed" if loop_count < self.max_loop_steps else "max_steps",
            "loop_count": loop_count,
            "actions_taken": actions_taken,
            "summary": final_summary,
            "state": final_state,
        }
    
    async def _inject_initial_findings(self, vulns: list[dict]):
        """将初始扫描结果注入 AttackState"""
        if not self.state:
            return
        
        targets_seen = set()
        
        for v in vulns:
            vuln_target = v.get("target", v.get("ip", ""))
            vuln_title = v.get("title", v.get("vuln_name", "?"))
            vuln_severity = v.get("severity", "medium")
            vuln_detail = v.get("detail", v.get("description", ""))
            
            # 提取资产信息
            if vuln_target and vuln_target not in targets_seen:
                targets_seen.add(vuln_target)
                asset = Asset(ip=vuln_target)
                # 尝试提取端口
                if ":" in vuln_target:
                    parts = vuln_target.split(":")
                    asset.ip = parts[0]
                    try:
                        asset.ports.append(int(parts[1]))
                    except ValueError:
                        pass
                # 从漏洞描述提取服务信息
                for kw in ["http", "https", "ssh", "mysql", "redis", "nginx", "apache"]:
                    if kw in vuln_detail.lower():
                        asset.services.append({"name": kw, "version": "", "port": 0})
                        break
                self.state.add_asset(asset)
            
            # 提取利用信息
            if vuln_severity in ("critical", "high"):
                exploit = Exploit(
                    target=vuln_target,
                    vuln_type=vuln_title,
                    detail=vuln_detail[:200],
                    severity=vuln_severity,
                )
                self.state.add_exploit(exploit)
                self.state.overall_progress = max(self.state.overall_progress, 0.3)
    
    async def _rag_retrieve(self) -> list[dict]:
        """从 RAG 检索相关经验"""
        if not self.rag_search or not self.state:
            return []
        
        results = []
        
        # 构造查询：根据当前发现的服务和攻击面
        queries = []
        
        # 从漏洞信息构造查询
        for e in self.state.exploits[-3:]:
            queries.append(f"{e.vuln_type} exploit technique")
        
        # 从服务信息构造查询
        for a in self.state.assets[-3:]:
            for s in a.services[:3]:
                svc = s.get("name", s.get("service", ""))
                if svc:
                    queries.append(f"{svc} penetration testing")
        
        # 从失败尝试构造查询
        if self.state.failed_attempts:
            last = self.state.failed_attempts[-1]
            queries.append(f"{last.action} bypass method")
        
        # 通用兜底
        if not queries:
            queries = [f"{self.state.target} pentest methodology"]
        
        # 去重
        seen = set()
        unique_queries = []
        for q in queries:
            if q not in seen:
                seen.add(q)
                unique_queries.append(q)
        
        for q in unique_queries[:3]:
            try:
                exp_list = await self.rag_search(q) if asyncio.iscoroutinefunction(self.rag_search) else self.rag_search(q)
                if isinstance(exp_list, list):
                    for exp in exp_list[:3]:
                        results.append({
                            "title": exp.get("title", exp.get("metadata", {}).get("title", "?")),
                            "content": (exp.get("content", "") or exp.get("text", ""))[:300],
                            "score": exp.get("score", exp.get("similarity", 0)),
                        })
            except Exception as e:
                logger.warning(f"[RAG] 搜索失败: {e}")
        
        # 按分数排序去重
        seen_titles = set()
        deduped = []
        for r in sorted(results, key=lambda x: x.get("score", 0), reverse=True):
            t = r.get("title", "")
            if t not in seen_titles and len(deduped) < 5:
                seen_titles.add(t)
                deduped.append(r)
        
        return deduped
    
    async def _decide(self, state_summary: str, experiences: list[dict]) -> dict:
        """LLM 决策下一步"""
        system_prompt = """你是一个实战渗透测试专家。基于当前攻击状态和经验库参考，决定下一步做什么。

关键原则：
1. 每步只做一件事（一个具体操作）
2. 不重复失败尝试
3. 先信息收集再漏洞利用
4. 基于已有证据做决策
5. 如果所有攻击面都尝试过且无进展，输出 {"action": "stop"}

可用的动作类型：
- nmap_scan: 端口/服务扫描
- dir_bruteforce: 目录爆破
- sql_injection: SQL注入测试
- file_upload: 文件上传测试
- brute_force: 暴力破解
- service_exploit: 特定服务漏洞利用
- credential_use: 使用已获取凭据登录
- pivoting: 横向移动
- privilege_escalation: 提权
- info_collect: 基础信息收集
- stop: 停止决策循环

输出必须是JSON，不要其他内容：
{"action": "...", "target": "...", "tool": "...", "params": {...}, "reasoning": "决策理由"}"""

        user_prompt = f"## 当前攻击状态\n{state_summary}\n"
        
        if experiences:
            user_prompt += "\n## 相关经验参考\n"
            for i, exp in enumerate(experiences[:5], 1):
                user_prompt += f"\n经验{i}: [{exp.get('title','?')}] (相关度:{exp.get('score',0):.3f})\n{exp.get('content','')[:200]}\n"
        
        user_prompt += "\n根据以上状态和经验，决定下一步操作。如果所有攻击面都尝试过且没有突破，输出 stop。"
        
        try:
            response = await self.llm_chat(user_prompt, system=system_prompt)
            return self._parse_decision(response)
        except Exception as e:
            logger.error(f"[决策] LLM错误: {e}")
            return {"action": "stop", "target": self.state.target if self.state else "", "tool": "", "params": {}, "reasoning": f"LLM错误: {e}"}
    
    def _parse_decision(self, response: str) -> dict:
        """解析LLM JSON响应"""
        # 尝试直接解析
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass
        
        # 尝试从```json块提取
        import re
        for pattern in [
            r'```(?:json)?\s*\n?({.*?})\n?```',
            r'({[^{}]*"action"[^{}]*})',
        ]:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue
        
        return {"action": "stop", "target": "", "tool": "", "params": {}, "reasoning": "解析失败"}
    
    async def _execute_decision(self, decision: dict, original_target: str) -> dict:
        """执行决策决定的动作"""
        action = decision.get("action", "info_collect")
        target = decision.get("target", original_target)
        tool = decision.get("tool", "")
        params = decision.get("params", {})
        
        if action == "stop":
            return {"status": "skipped", "findings": []}
        
        # 构造工具调用
        tool_call = {
            "id": f"decision_{int(time.time())}",
            "function": {
                "name": "start_scan",
                "arguments": json.dumps({
                    "target": target,
                    "description": f"决策循环: {decision.get('reasoning', '')}",
                    "skills": params.get("skills", [tool]) if tool else []
                })
            }
        }
        
        try:
            result_str = await self.execute_tool(tool_call)
            result = json.loads(result_str) if isinstance(result_str, str) else result_str
            
            # 等几秒让扫描启动
            await asyncio.sleep(3)
            
            # 查一次进度
            progress_call = {
                "id": f"prog_{int(time.time())}",
                "function": {
                    "name": "get_task_progress",
                    "arguments": json.dumps({"task_id": result.get("task_id", "")})
                }
            }
            prog_str = await self.execute_tool(progress_call)
            
            return {
                "status": result.get("status", "PENDING"),
                "task_id": result.get("task_id", ""),
                "message": result.get("message", ""),
                "findings": [],
                "progress_result": prog_str,
            }
        except Exception as e:
            logger.error(f"[执行] 失败: {e}")
            return {"status": "error", "message": str(e), "findings": []}
    
    async def _update_from_result(self, decision: dict, result: dict, original_target: str):
        """根据执行结果更新状态"""
        if not self.state:
            return
        
        action = decision.get("action", "unknown")
        target = decision.get("target", original_target)
        
        step = AttackStep(
            step_id=len(self.state.attack_chain) + 1,
            action=action,
            target=target,
            tool=decision.get("tool", ""),
            params=decision.get("params", {}),
            result_summary=result.get("message", result.get("status", "executed")),
            findings=result.get("findings", []),
            reasoning=decision.get("reasoning", ""),
            success=result.get("status") not in ("error", "skipped"),
        )
        self.state.add_step(step)
        
        if not step.success:
            self.state.mark_no_new_finding()
            self.state.add_failed_attempt(action=action, target=target, reason=result.get("message", "执行失败"))
        else:
            self.state._on_new_finding()
        
        # 更新进度
        if len(self.state.attack_chain) > 3:
            ratio = len([s for s in self.state.attack_chain[-5:] if s.success]) / 5
            self.state.overall_progress = min(
                1.0,
                0.3 + (len(self.state.attack_chain) / self.max_loop_steps) * 0.7
            )
