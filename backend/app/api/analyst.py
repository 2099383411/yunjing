"""
AI渗透分析师 — 分析扫描结果，生成下一步渗透建议
"""
import json, logging
from fastapi import APIRouter, Depends
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.user import User
from app.api.deps import optional_user

logger = logging.getLogger(__name__)
router = APIRouter()

ANALYST_PROMPT = """你是一名资深渗透测试专家。下面是自动扫描的结果，请分析并给出下一步建议。

分析要求：
1. 总结关键发现（最多3条）
2. 对每个发现给出具体的下一步操作建议
3. 如果有可立即利用的漏洞，优先建议
4. 如果未发现明显漏洞，建议替换扫描策略
5. 用中文回复，简洁专业

格式要求：
{
  "summary": "一句话总结",
  "findings": [{"name": "发现名称", "risk": "高/中/低", "suggestion": "具体操作建议"}],
  "next_steps": ["步骤1", "步骤2"],
  "confidence": 0.5
}
"""

@router.post("/analyze")
async def analyze_scan(data: dict, user: User = Depends(optional_user)):
    """分析扫描结果，生成渗透建议"""
    task_id = data.get("task_id", "")
    if not task_id:
        return {"status": "error", "message": "task_id required"}

    async with AsyncSessionLocal() as sess:
        from app.models.task import ScanTask
        task = await sess.get(ScanTask, task_id)
        if not task:
            return {"status": "error", "message": "任务不存在"}

        # 构建分析上下文
        result = task.result or {}
        findings = result.get("findings", []) if isinstance(result, dict) else []
        ports = result.get("ports", []) if isinstance(result, dict) else []
        summary = result.get("summary", {}) if isinstance(result, dict) else {}

        context = f"目标: {task.target}\n扫描类型: {task.scan_type}\n"
        context += f"发现数: {len(findings)}\n"
        context += f"开放端口: {', '.join(str(p) for p in ports[:10]) if ports else '无'}\n"
        
        for i, f_item in enumerate(findings[:10]):
            if isinstance(f_item, dict):
                context += f"发现{i+1}: {f_item.get('name','?')} [{f_item.get('severity','?')}]\n"

        # 调用LLM分析
        try:
            from app.llm.adapter import llm_adapter
            messages = [
                {"role": "system", "content": ANALYST_PROMPT},
                {"role": "user", "content": context}
            ]
            resp = await llm_adapter.chat(messages=messages, temperature=0.3, max_tokens=1000)
            content = resp.get("choices", [{}])[0].get("message", {}).get("content", "")
            
            # Try parse JSON
            try:
                analysis = json.loads(content)
            except json.JSONDecodeError:
                # Extract JSON from markdown
                import re
                m = re.search(r'\{[^}]+\}', content, re.DOTALL)
                analysis = json.loads(m.group(0)) if m else {"summary": content[:200], "next_steps": []}
            
            analysis["status"] = "ok"
            analysis["task_id"] = task_id
            return analysis
        except Exception as e:
            logger.error(f"[分析师] LLM调用失败: {e}", exc_info=True)
            return {"status": "error", "message": f"分析失败: {str(e)}"}
