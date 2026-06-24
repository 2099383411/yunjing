#!/usr/bin/env python3
"""云镜 RAG 检索层 v2 — 语义 + 关键词 双通道 + Reranker 精排

架构：
  用户查询
     │
     ├──→ ① 语义通道: BGE-large-zh → Qdrant 余弦搜索（top_k×5）
     │
     ├──→ ② 关键词通道: 提取关键词 → Qdrant 全文索引搜索（top_k×3）
     │
     ├──→ ③ 合并 + 去重（按 point ID 去重）
     │
     └──→ ④ Reranker 精排: BGE-reranker-v2-m3（取 top_k）
               │
               └──→ 返回最终结果

依赖:
  - Qdrant v1.18+ (full-text payload index on "text" field)
  - BGE-large-zh (embedding)
  - BGE-reranker-v2-m3 (reranking)
"""
import os
import json
import hashlib
import logging
import time
import re
from typing import Optional
import httpx

# Lazy import - qdrant_client only imported when RAGEngine is instantiated
# This avoids import errors during server startup when dependencies are missing
import importlib

def _get_qdrant_client():
    """Lazy import qdrant_client - only loaded when needed."""
    try:
        qc = importlib.import_module("qdrant_client")
        qm = importlib.import_module("qdrant_client.http.models")
        return qc.QdrantClient, qm
    except ImportError:
        return None, None

QdrantClient = None
qdrant_models = None

logger = logging.getLogger(__name__)

# ── 配置 ────────────────────────────────────────────────
BGE_SERVICE_URL = os.environ.get("BGE_SERVICE_URL", "http://yunjing-bge:8000")
QDRANT_URL = os.environ.get("QDRANT_URL", "http://yunjing-qdrant:6333")
KNOWLEDGE_BASE_DIR = os.environ.get(
    "KB_PATH",
    os.path.join("/app", "app", "data", "knowledge-base"),
)
EMBED_DIM = 1024

KW_MIN_LENGTH = 3         # 关键词最短长度
KW_MAX_TERMS = 5          # 关键词最多数量
TOP_K_FACTOR_SEMANTIC = 3  # 语义通道候选池放大倍数（原5，GTX1650显存/算力有限）
TOP_K_FACTOR_KEYWORD = 2   # 关键词通道候选池放大倍数（原3）


class RAGEngine:
    """RAG 检索引擎 v2 — 语义 + 关键词 双通道 + Reranker 精排"""

    def __init__(self):
        _QdrantClient, _ = _get_qdrant_client()
        if _QdrantClient is None:
            import warnings
            warnings.warn("QdrantClient unavailable - RAGEngine disabled. Install qdrant-client SDK.")
            self._qdrant = None
            self._http = None
            self._bge_url = None
            return
        self._qdrant = _QdrantClient(url=QDRANT_URL)
        self._bge_url = BGE_SERVICE_URL
        self._http = httpx.Client(timeout=60)
        self._ensure_collections()

    # ── 初始化集合 & 全文索引 ─────────────────────────

    def _ensure_collections(self):
        """确保集合存在，并为 text 字段创建全文索引"""
        for name in ("knowledge", "experience"):
            collections = self._qdrant.get_collections().collections
            exists = any(c.name == name for c in collections)
            if not exists:
                self._qdrant.create_collection(
                    collection_name=name,
                    vectors_config=qdrant_models.VectorParams(
                        size=EMBED_DIM,
                        distance=qdrant_models.Distance.COSINE,
                    ),
                )
                logger.info(f"[RAG] 创建集合: {name}")
            # 为 text 字段创建全文索引（用于关键词搜索降级）
            self._ensure_payload_index(name, "text")

    def _ensure_payload_index(self, collection: str, field: str):
        """为指定字段创建全文索引（幂等操作）"""
        try:
            self._qdrant.create_payload_index(
                collection_name=collection,
                field_name=field,
                field_schema=qdrant_models.PayloadSchemaType.TEXT,
            )
        except Exception:
            pass  # 索引已存在时静默忽略

    # ── Embedding ───────────────────────────────────────

    def _embed(self, text: str) -> list[float]:
        """单条文本向量化"""
        resp = self._http.post(
            f"{self._bge_url}/embed",
            json={"text": text, "normalize": True},
        )
        resp.raise_for_status()
        return resp.json()["vector"]

    def _embed_batch(self, texts: list[str]) -> list[list[float]]:
        """批量向量化"""
        resp = self._http.post(
            f"{self._bge_url}/embed_batch",
            json={"texts": texts, "normalize": True},
        )
        resp.raise_for_status()
        return resp.json()["vectors"]

    # ── 搜索文本构建 ────────────────────────────────────

    def _build_knowledge_text(self, doc: dict) -> str:
        """知识库文档 → 搜索文本（兼容新旧两种格式）
        
        新格式 (v2 payload): text 字段已预计算好，直接返回
        旧格式 (v1 payload): 从 title/content/summary/description 中构建
        """
        # 新格式: 直接使用预计算的 text 字段
        text_field = doc.get("text", "")
        if text_field and text_field.strip():
            return text_field[:3000]

        # 旧格式: 从各字段拼接
        parts = []
        for field in ("title", "content", "summary", "description"):
            v = doc.get(field)
            if v:
                if isinstance(v, dict):
                    parts.append(json.dumps(v, ensure_ascii=False))
                elif isinstance(v, list):
                    parts.append(" ".join(str(x) for x in v))
                else:
                    parts.append(str(v))

        # 兜底: 从 metadata 构建
        if not parts:
            meta = doc.get("metadata", {})
            if isinstance(meta, dict):
                for f in ("title", "source", "h2", "h3"):
                    val = meta.get(f, "")
                    if val:
                        parts.append(str(val))

        return ". ".join(parts) if parts else ""

    def _build_experience_text(self, exp: dict) -> str:
        """经验条目 → 搜索文本（兼容新旧两种格式）
        
        旧格式 (InternalAllTheThings):
          exp_id, target, hypothesis(dict), signals, reasoning_path, verification, exploitation
        新格式 (PayloadsAllTheThings / HackTricks):
          title, hypothesis(str), target_type, verification_steps, tools, expected_outcomes
        """
        parts = []

        # ─── title / pattern_id ───
        title = exp.get("title", "")
        if title:
            parts.append(f"[{title}]")
        elif exp.get("pattern_id"):
            parts.append(f"[{exp.get('pattern_id', '')}]")

        # ─── hypothesis ───
        hyp = exp.get("hypothesis", "")
        if hyp:
            if isinstance(hyp, dict):
                # 旧格式: hypothesis 是个 dict，提取 name 字段
                parts.append(f"假设: {hyp.get('name', json.dumps(hyp, ensure_ascii=False))}")
            elif isinstance(hyp, str):
                parts.append(f"假设: {hyp}")

        # ─── target_type ───
        tt = exp.get("target_type", "") or exp.get("category", "") or exp.get("type", "")
        if tt:
            parts.append(f"类型: {tt}")

        # ─── target (旧格式) ───
        target = exp.get("target", {})
        if isinstance(target, dict):
            tname = target.get("name", "") or target.get("host", "") or target.get("url", "")
            if tname:
                parts.append(f"目标: {tname}")
        elif isinstance(target, str) and target:
            parts.append(f"目标: {target}")

        # ─── verification_steps (新格式) ───
        steps = exp.get("verification_steps", [])
        if isinstance(steps, list) and steps:
            s_text = "; ".join(str(s)[:200] for s in steps[:5])
            if s_text:
                parts.append(f"验证: {s_text}")
        elif isinstance(steps, str) and steps:
            parts.append(f"验证: {steps}")

        # ─── verification (旧格式) ───
        ver = exp.get("verification", "")
        if ver and not steps:
            parts.append(f"验证: {str(ver)[:500]}")

        # ─── signals (旧格式) ───
        signals = exp.get("signals", "")
        if signals:
            if isinstance(signals, list):
                sig_parts = []
                for s in signals[:5]:
                    if isinstance(s, dict):
                        sig_parts.append(str(s.get("name", s.get("detail", ""))))
                    else:
                        sig_parts.append(str(s))
                if sig_parts:
                    parts.append(f"信号: {', '.join(sig_parts)}")
            elif isinstance(signals, dict):
                parts.append(f"信号: {json.dumps(signals, ensure_ascii=False)[:300]}")
            else:
                parts.append(f"信号: {str(signals)[:300]}")

        # ─── tools (新格式) ───
        tools = exp.get("tools", [])
        if isinstance(tools, list) and tools:
            parts.append(f"工具: {', '.join(str(t)[:50] for t in tools[:8])}")

        # ─── expected_outcomes (新格式) ───
        outcomes = exp.get("expected_outcomes", [])
        if isinstance(outcomes, list) and outcomes:
            parts.append(f"预期: {'; '.join(str(o)[:100] for o in outcomes[:3])}")

        # ─── exploitation (旧格式) ───
        expl = exp.get("exploitation", "")
        if expl and not outcomes:
            parts.append(f"利用: {str(expl)[:300]}")

        # ─── reasoning_path (旧格式) ───
        rp = exp.get("reasoning_path", "")
        if rp:
            if isinstance(rp, list):
                parts.append(f"推理链: {' -> '.join(str(x)[:100] for x in rp[:5])}")
            elif isinstance(rp, str):
                parts.append(f"推理链: {rp[:300]}")

        # ─── CVE / 编号 ───
        cve = exp.get("cve", "") or exp.get("reference", "")
        if cve:
            parts.append(f"编号: {str(cve)[:100]}")

        return ". ".join(parts) if parts else ""

    # ── 关键词提取 ──────────────────────────────────────

    def _extract_keywords(self, query: str) -> list[str]:
        """从查询中提取有检索价值的关键词
        
        规则:
          - 保留 CVE 编号（如 CVE-2020-1472）
          - 保留英文技术术语（长度≥3）
          - 保留中文短语（去掉常见停用词）
          - 去掉纯符号/数字
        """
        # 提取 CVE 编号
        cves = re.findall(r'CVE-\d{4}-\d+', query, re.IGNORECASE)

        # 提取英文单词（≥3字符，去掉停用词）
        eng_stop = {"the", "and", "for", "are", "was", "but", "not", "you", "all",
                    "can", "had", "her", "his", "its", "may", "see", "the", "use",
                    "how", "why", "via", "get", "use", "set", "new", "old"}
        eng_words = [w for w in re.findall(r'[a-zA-Z][a-zA-Z0-9._-]{2,}', query)
                     if w.lower() not in eng_stop]

        # 提取中文短语（2+字符的非停用字）
        cn_stop = {"的", "了", "在", "是", "有", "和", "就", "不", "人", "都",
                   "而", "及", "与", "着", "或", "一个", "没有", "我们", "你们",
                   "他们", "它们", "这个", "那个", "什么", "怎么", "如何", "为什么",
                   "可以", "需要", "使用", "通过", "进行", "利用", "可能", "是否"}
        cn_chars = re.findall(r'[\u4e00-\u9fff]{2,}', query)
        chinese = [w for w in cn_chars if w not in cn_stop]

        # 合并去重
        keywords = []
        seen = set()
        for kw in cves + chinese[:KW_MAX_TERMS] + eng_words[:KW_MAX_TERMS]:
            lowered = kw.lower()
            if lowered not in seen:
                keywords.append(kw)
                seen.add(lowered)

        return keywords[:KW_MAX_TERMS]

    # ── 核心搜索 ────────────────────────────────────────

    def search(
        self,
        query: str,
        top_k: int = 5,
        collections: Optional[list[str]] = None,
    ) -> list[dict]:
        """双通道搜索主入口

        Args:
            query: 搜索查询
            top_k: 最终返回结果数
            collections: 搜索的集合列表，默认 ["experience", "knowledge"]

        Returns:
            list[dict]: 每条含 payload 和 score
        """
        if collections is None:
            collections = ["experience", "knowledge"]

        t_start = time.time()
        logger.info(f"[RAG] search: {query[:80]} (top_k={top_k}, collections={collections})")

        # ── Step 0: 向量化查询 ──
        query_vec = self._embed(query)
        keywords = self._extract_keywords(query)
        logger.info(f"[RAG] 关键词: {keywords}")

        all_candidates = {}
        seen_ids = set()

        for col in collections:
            # ── 通道 A: 语义搜索（宽池） ──
            semantic_limit = top_k * TOP_K_FACTOR_SEMANTIC
            semantic_results = self._qdrant.query_points(
                collection_name=col,
                query=query_vec,
                limit=semantic_limit,
                with_payload=True,
                score_threshold=0.5,  # 低于 0.5 的语义不太相关
            )
            for point in semantic_results.points:
                uid = f"{col}_{point.id}"
                if uid not in seen_ids:
                    seen_ids.add(uid)
                    all_candidates[uid] = {
                        "payload": point.payload or {},
                        "score": point.score,
                        "collection": col,
                        "channel": "semantic",
                    }

            # ── 通道 B: 关键词搜索（全文索引） ──
            if keywords:
                kw_limit = top_k * TOP_K_FACTOR_KEYWORD
                # 用 MatchText 构建全文搜索 filter（Qdrant 内建 TF-IDF 评分）
                kw_filters = [
                    qdrant_models.FieldCondition(
                        key="text",
                        match=qdrant_models.MatchText(text=kw),
                    )
                    for kw in keywords[:3]  # 最多 3 个关键词
                ]
                if kw_filters:
                    keyword_results = self._qdrant.query_points(
                        collection_name=col,
                        query=query_vec,
                        query_filter=qdrant_models.Filter(
                            should=kw_filters,
                        ),
                        limit=kw_limit,
                        with_payload=True,
                    )
                    for point in keyword_results.points:
                        uid = f"{col}_{point.id}"
                        if uid not in seen_ids:
                            seen_ids.add(uid)
                            all_candidates[uid] = {
                                "payload": point.payload or {},
                                "score": point.score,
                                "collection": col,
                                "channel": "keyword",
                            }

        candidates = list(all_candidates.values())
        logger.info(f"[RAG] 候选池: {len(candidates)} 条 (语义+关键词)")

        if not candidates:
            logger.info(f"[RAG] 无结果,耗时: {time.time()-t_start:.2f}s")
            return []

        # ── Step: Reranker 精排 ──
        # 候选池最多 20 条（GTX1650 算力限制），超过则用余弦分数截断
        query_text = query
        doc_texts = []
        candidates_sorted = sorted(candidates, key=lambda x: x.get("score", 0), reverse=True)
        for c in candidates_sorted[:12]:
            col = c["collection"]
            payload = c["payload"]
            if col == "knowledge":
                text = self._build_knowledge_text(payload)
            else:
                text = self._build_experience_text(payload)
            doc_texts.append(text[:300])

        if len(candidates_sorted) > 20:
            logger.info(f"[RAG] 候选池 {len(candidates_sorted)} 条, 截断到 12 条精排")

        ranked_indices = self._rerank(query_text, doc_texts, top_k=top_k)

        results = []
        for idx, score in ranked_indices:
            c = candidates[idx]
            c["rerank_score"] = score
            # ── Payload 规范化 ──
            payload = c.get("payload", {})
            # 知识库 payload: title 在 metadata.title 嵌套, 提取到顶层
            if not payload.get("title") and isinstance(payload.get("metadata"), dict):
                meta = payload["metadata"]
                # 从 metadata 提取 title
                if meta.get("title") and meta["title"].strip():
                    payload["title"] = meta["title"]
                elif meta.get("h2") or meta.get("h3"):
                    # 用最细粒度的标题
                    payload["title"] = meta.get("h3") or meta.get("h2") or ""
                elif meta.get("source"):
                    # 最后 fallback: 用 source 文件名
                    src = meta["source"]
                    payload["title"] = src.replace(".md","").replace("-"," ").split("/")[-1]
                # 也合并其它有用字段
                for k in ("source", "h2", "h3"):
                    if meta.get(k):
                        payload.setdefault(k, meta[k])
            results.append(c)

        elapsed = time.time() - t_start
        logger.info(f"[RAG] 返回 {len(results)} 条, 耗时: {elapsed:.2f}s")

        return results

    # ── Reranker ────────────────────────────────────────

    def _rerank(
        self, query: str, docs: list[str], top_k: int = 5
    ) -> list[tuple[int, float]]:
        """BGE-reranker 精排

        BGE 服务 API:
          POST /rerank
          Body: {"query": str, "docs": list[str]}
          Response: {"query": ..., "results": [{"doc": ..., "score": float, "rank": int}, ...]}

        返回: [(原始索引, 精排分数), ...]，按分数降序
        """
        if not docs:
            return []

        try:
            resp = self._http.post(
                f"{self._bge_url}/rerank",
                json={"query": query, "docs": docs},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()

            # BGE-reranker v3 格式: {"results": [{"doc": ..., "score": 0.98, "rank": 1}, ...]}
            if "results" in data:
                for r in data["results"]:
                    if "rank" in r:
                        # 按 rank 排序（rank=1 最相关）
                        ranked = sorted(
                            data["results"],
                            key=lambda x: x.get("rank", 999),
                        )[:top_k]
                        return [(r["rank"] - 1, r.get("score", 0)) for r in ranked]
                    if "index" in r:
                        # 按 index 格式（兼容旧版）
                        ranked = sorted(
                            data["results"],
                            key=lambda x: x.get("relevance_score", 0),
                            reverse=True,
                        )[:top_k]
                        return [(r["index"], r.get("relevance_score", 0)) for r in ranked]

            # 兼容: scores 数组格式
            if "scores" in data:
                scores = data["scores"]
                indexed = list(enumerate(scores))
                ranked = sorted(indexed, key=lambda x: x[1], reverse=True)[:top_k]
                return ranked

        except Exception as e:
            logger.warning(f"[RAG] Reranker 失败, 降级为余弦排序: {e}", exc_info=True)
            pass

        # 降级: 用原始余弦相似度排序
        return [(i, 0.0) for i in range(min(top_k, len(docs)))]

    # ── 索引维护 ────────────────────────────────────────

    def index_knowledge_base(self, docs: list[dict]):
        """索引知识库文档到 Qdrant"""
        _index_documents(self._qdrant, self._embed_batch, "knowledge", docs, self._build_knowledge_text)

    def index_experience(self, exps: list[dict]):
        """索引经验到 Qdrant"""
        _index_documents(self._qdrant, self._embed_batch, "experience", exps, self._build_experience_text)

    # ── 辅助方法 ────────────────────────────────────────

    def count(self, collection: str = "experience") -> int:
        """查询集合中的向量数量"""
        try:
            info = self._qdrant.get_collection(collection)
            # Qdrant 1.18.x 使用 points_count
            if hasattr(info, "points_count") and info.points_count is not None:
                return info.points_count
            # 兼容旧版本
            if hasattr(info, "vectors_count") and info.vectors_count is not None:
                return info.vectors_count
            return 0
        except Exception as e:
            logger.warning(f"[RAG] count({collection}) 失败: {e}")
            return 0

    def health(self) -> dict:
        """服务健康检查"""
        status = {}
        try:
            self._http.get(f"{self._bge_url}/health", timeout=10)
            status["bge"] = "ok"
        except Exception:
            status["bge"] = "error"

        try:
            col_info = self._qdrant.get_collection("experience")
            status["qdrant"] = "ok"
        except Exception:
            status["qdrant"] = "error"

        status["experience_count"] = self.count("experience")
        status["knowledge_count"] = self.count("knowledge")
        return status


# ── 索引工具函数 ──────────────────────────────────────

def _index_documents(
    qdrant: QdrantClient,
    embed_fn,
    collection: str,
    docs: list[dict],
    build_text_fn,
    batch_size: int = 32,
):
    """索引文档/经验到 Qdrant（含全文索引 text 字段）"""
    if not docs:
        return

    # 确保全文索引
    try:
        qdrant.create_payload_index(
            collection_name=collection,
            field_name="text",
            field_schema=qdrant_models.PayloadSchemaType.TEXT,
        )
    except Exception:
        pass

    texts = []
    valid_docs = []
    for d in docs:
        t = build_text_fn(d)
        if t.strip():
            texts.append(t)
            valid_docs.append(d)

    if not texts:
        return

    vectors = embed_fn(texts)

    # 获取当前最大 ID
    current_max = 0
    try:
        info = qdrant.get_collection(collection)
        current_max = info.points_count or 0
    except Exception:
        pass

    points = []
    for i, (doc, vec, text) in enumerate(zip(valid_docs, vectors, texts)):
        points.append(qdrant_models.PointStruct(
            id=current_max + i + 1,
            vector=vec,
            payload={
                **doc,
                "text": text[:5000],  # 截断到 5000 字符
            },
        ))

    # 分批 upsert
    for i in range(0, len(points), batch_size):
        qdrant.upsert(
            collection_name=collection,
            points=points[i:i+batch_size],
            wait=True,
        )

    logger.info(f"[RAG] 索引 {len(points)} 条到 {collection}")
