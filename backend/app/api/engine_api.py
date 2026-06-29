import json, os, logging, uuid
from typing import Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter()

_ENGINE_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "engine"))
_LEARNING_PATH = os.path.join(_ENGINE_DIR, "learning_data.json")
_KB_QUERY_PATH = os.path.join(_ENGINE_DIR, "kb_query.py")


# ── 知识库统计 ──────────────────────────────────────────

@router.get('/kb-stats')
async def engine_kb_stats():
    """知识库统计"""
    try:
        from app.engine.kb_query import get_kb_index
        kb = get_kb_index()
        stats = kb.get_stats()
        return {"status": "ok", "stats": stats}
    except Exception as e:
        import traceback
        logger.error(f"kb_stats error: {e}\n{traceback.format_exc()}")
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 自学习统计 ──────────────────────────────────────────

@router.get('/learning-stats')
async def engine_learning_stats():
    """自学习数据统计"""
    try:
        from app.engine.learning import LearningEngine
        le = LearningEngine(storage_path=_LEARNING_PATH)
        stats = le.get_summary()
        return {"status": "ok", "stats": stats}
    except Exception as e:
        import traceback
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 假设列表 ───────────────────────────────────────────

@router.get('/hypotheses')
async def engine_hypotheses(task_id: str = ""):
    """查询当前活跃假设 / 历史假设"""
    try:
        from app.engine.hypothesis_scanner import HypothesisScanner
        from app.database import AsyncSessionLocal
        hs = HypothesisScanner(None)
        async with AsyncSessionLocal() as sess:
            hyps = await hs.list_active_hypotheses(sess, limit=50)
        return {"status": "ok", "hypotheses": [
            {
                "id": h.id, "name": h.name, "pattern_id": h.pattern_id,
                "target": h.target, "confidence": h.confidence,
                "status": h.status.value, "created_at": str(h.created_at),
            } for h in hyps
        ]}
    except Exception as e:
        import traceback
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 状态查询 ───────────────────────────────────────────

@router.get('/state')
async def engine_state():
    """引擎综合状态"""
    try:
        from app.engine.learning import LearningEngine
        from app.engine.vector_store import RAGEngine
        le = LearningEngine(storage_path=_LEARNING_PATH)
        rag = RAGEngine()
        exp_count = len(le.data.get('experiences', le.data.get('experiments', le.data.get('knowledge', []))))
        return {
            "status": "ok",
            "experience": {
                "total": exp_count,
                "patterns": le.get_pattern_summary(),
            },
            "vector_store": rag.health(),
        }
    except Exception as e:
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 全流程引擎 ─────────────────────────────────────────

@router.post('/run-pipeline')
async def engine_run_pipeline(data: dict):
    """执行完整推理管线：感知 → 假设生成 → 验证 → 学习

    Body: { target, ports:[], type }
    """
    try:
        from app.engine.hypothesis_scanner import HypothesisScanner
        from app.engine.hypothesis import HypothesisGenerator
        from app.engine.verification import VerificationEngine
        from app.engine.learning import LearningEngine
        from app.engine.models import TargetPerception, PortInfo

        target = data.get("target", "unknown")
        target_type = data.get("type", "common")
        ports_raw = data.get("ports", [])

        perception = TargetPerception(
            target=target,
            open_ports=[PortInfo(port=p) if isinstance(p, int) else PortInfo(port=p.get("port"), service=p.get("service")) for p in ports_raw],
        )

        # 生成假设
        hg = HypothesisGenerator(llm_generator=None)
        hypotheses = hg.generate(perception, target_type=target_type)

        return {
            "status": "ok",
            "target": target,
            "hypotheses": [
                {"name": h.name, "confidence": h.source_confidence,
                 "pattern_id": h.pattern_id, "impact": h.impact}
                for h in hypotheses
            ],
            "count": len(hypotheses),
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "detail": traceback.format_exc()}


# ── 扫描回调 ───────────────────────────────────────────

@router.post("/scan-callback")
async def scan_callback(data: dict):
    """Worker 扫描完成后回调"""
    import traceback
    try:
        from app.engine.hypothesis_scanner import HypothesisScanner
        from app.engine.learning import LearningEngine
        from app.engine.vector_store import RAGEngine
        from app.database import AsyncSessionLocal

        task_id = data.get("task_id")
        target = data.get("target")
        scan_type = data.get("scan_type", "unknown")
        status = data.get("status", "completed")
        findings = data.get("findings", [])

        if not task_id:
            return {"status": "error", "message": "task_id required"}

        # 1. 记录到 learning_data
        le = LearningEngine(storage_path=_LEARNING_PATH)
        vuln_count = le.record_scan_callback(
            task_id=task_id, target=target, scan_type=scan_type,
            findings=findings, status=status,
        )
        logger.info(f"[扫描回调] 记录结果: task={task_id}, vulns={vuln_count}")

        # 2. 更新假设
        async with AsyncSessionLocal() as sess:
            hs = HypothesisScanner(le)
            # 从学习引擎获取当前活跃假设
            active = le.get_active_hypotheses() if hasattr(le, "get_active_hypotheses") else [] if hasattr(le, "get_active_hypotheses") else []
            if active:
                hypothesis = None
                for h in active:
                    if target in (h.payload or ""):
                        hypothesis = await hs.feed_back(h, True if status=="completed" else False, findings)
                        break
                if not hypothesis:
                    logger.warning(f"[扫描回调] 无匹配假设, 跳过")
                    hypothesis = None
            else:
                logger.warning(f"[扫描回调] 无活跃假设, 跳过")
                hypothesis = None
        le.amplify_weights()
        hs_s = getattr(hypothesis, "status", None)
        hs_v = getattr(hs_s, "value", "无")
        logger.info(f"[扫描回调] 假设更新: {hs_v}")
        le.amplify_weights()  # 经验闭环：成功经验自动提升权重

        # 3. 自动同步经验到 Qdrant
        try:
            rag = RAGEngine()
            # 读取最新的 learning_data.json
            with open(_LEARNING_PATH, "r") as f:
                all_data = json.load(f)
            experiences = all_data.get("experiments", all_data.get("experiences", []))
            if experiences:
                rag.index_experience(experiences, force=False)
                logger.info(f"[扫描回调] 经验库向量已同步 (Qdrant: {rag.count('experience')} 条)")
        except Exception as e:
            logger.warning(f"[扫描回调] 向量同步失败（不影响主流程）: {e}")

        return {
            "status": "ok",
            "task_id": task_id,
            "learning_updated": True,
            "hypothesis_status": getattr(getattr(hypothesis, "status", None), "value", None),
            "vuln_found": vuln_count,
        }

    except Exception as e:
        import traceback
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 经验搜索（RAG 语义 + 关键词降级）──────────────────

@router.post("/experience/search")
async def experience_search(data: dict):
    """查询过往经验（LLM 推理时 RAG 检索用）

    Body:
        query: 语义查询文本（使用 RAG 向量搜索，推荐）
        pattern: 按模式筛选（如 sql-injection）
        target_type: 按目标类型筛选（如 web-app）
        signal: 按信号类型筛选（如 port）
        limit/top_k: 最多返回条数 (默认5, 最大20)
    """
    try:
        query = data.get("query", "")
        pattern_id = data.get("pattern", "")
        target_type = data.get("target_type", "")
        signal_type = data.get("signal", "")
        top_k = min(data.get("top_k", data.get("limit", 5)), 20)

        # 语义搜索优先
        if query:
            try:
                from app.engine.vector_store import RAGEngine
                rag = RAGEngine()
                results = rag.search(query, top_k=top_k)
                formatted = []
                for r in results:
                    p = r.get("payload", {})
                    formatted.append({
                        "title": p.get("title", ""),
                        "target_type": p.get("target_type", ""),
                        "verification_steps": p.get("verification_steps", ""),
                        "tools": p.get("tools", []),
                        "expected_outcomes": p.get("expected_outcomes", ""),
                        "hypothesis": p.get("hypothesis", ""),
                        "score": r.get("rerank_score", r.get("score", 0)),
                        "channel": r.get("channel", ""),
                        "collection": r.get("collection", ""),
                    })
                return {"status": "ok", "results": formatted, "count": len(formatted)}
            except Exception as e:
                logger.warning(f"[经验查询] RAG 搜索失败，降级到关键词: {e}")

        # 降级：关键词搜索（向后兼容）
        learning_path = os.path.normpath(os.path.join(
            os.path.dirname(__file__), "..", "engine", "learning_data.json"
        ))
        from app.engine.learning import LearningEngine
        le = LearningEngine(storage_path=learning_path)

        experiments = le.search_experiences(
            pattern_id=pattern_id if pattern_id else None,
            target_type=target_type if target_type else None,
            signal_type=signal_type if signal_type else None,
            limit=top_k
        )

        return {
            "status": "ok",
            "experiments": experiments,
            "count": len(experiments)
        }
    except Exception as e:
        import traceback
        logger.error(f"[经验查询] 失败: {e}\n{traceback.format_exc()}")
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


@router.get("/experience/stats")
async def experience_stats(pattern: str = "", target_type: str = ""):
    """获取经验统计摘要"""
    try:
        learning_path = os.path.normpath(os.path.join(
            os.path.dirname(__file__), "..", "engine", "learning_data.json"
        ))
        from app.engine.learning import LearningEngine
        le = LearningEngine(storage_path=learning_path)
        summary = le.get_experience_summary(
            pattern_id=pattern if pattern else None,
            target_type=target_type if target_type else None,
        )
        return {"status": "ok", "summary": summary}
    except Exception as e:
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


# ── 引擎配置 ──────────────────────────────────────────────────────

@router.get('/config')
async def engine_config_get():
    """获取引擎配置"""
    config_path = os.path.join(_ENGINE_DIR, "config.json")
    cfg = {
        "max_concurrent_tasks": 5,
        "default_timeout": 600,
        "enable_auto_report": True,
        "output_dir": "/root/yunjing/reports",
    }
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg.update(json.load(f))
        except Exception as e:
            pass
    return {"status": "ok", "config": cfg}


@router.post('/config')
async def engine_config_save(config: dict):
    """保存引擎配置"""
    config_path = os.path.join(_ENGINE_DIR, "config.json")
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    return {"status": "ok", "message": "配置已保存"}


# ── 引擎会话管理 ──────────────────────────────────────────────────

@router.get('/sessions/list')
async def engine_sessions_list(page: int = 1, page_size: int = 100):
    """获取引擎会话列表"""
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as sess:
            offset = (page - 1) * page_size
            result = await sess.execute(
                text("SELECT id, target, scan_type, status, created_at, updated_at FROM scan_tasks ORDER BY created_at DESC LIMIT :limit OFFSET :offset"),
                {"limit": page_size, "offset": offset}
            )
            rows = result.fetchall()
            total = await sess.execute(text("SELECT COUNT(*) FROM scan_tasks"))
            total_count = total.scalar() or 0
            sessions = []
            for row in rows:
                sessions.append({
                    "id": str(row[0]),
                    "target": str(row[1]),
                    "scan_type": str(row[2]) if row[2] else "",
                    "status": str(row[3]),
                    "created_at": str(row[4]) if row[4] else "",
                    "updated_at": str(row[5]) if row[5] else "",
                })
            return {"status": "ok", "sessions": sessions, "total": total_count, "page": page, "page_size": page_size}
    except Exception as e:
        import traceback
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}


@router.post('/sessions/{session_id}/kill')
async def engine_session_kill(session_id: str):
    """终止指定会话"""
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as sess:
            await sess.execute(
                text("UPDATE scan_tasks SET status='CANCELLED' WHERE id=:id AND status IN ('PENDING','RUNNING')"),
                {"id": session_id}
            )
            await sess.commit()
        return {"status": "ok", "message": f"会话 {session_id} 已终止"}
    except Exception as e:
        import traceback
        logger.error(f"[扫描回调] 失败: {e}\n{traceback.format_exc()}")
        return {"status": "ok", "message": "processed (with warnings)"}

