"""BGE Embedding & Reranking 服务

提供 HTTP API：
  POST /embed        → 单条文本向量化
  POST /embed_batch  → 批量文本向量化
  POST /rerank       → 重排序
  GET  /health       → 健康检查
"""
import time
import logging
from typing import List, Optional

import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer, CrossEncoder

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("bge-server")

app = FastAPI(title="BGE Embedding Service")

# ── 模型 ────────────────────────────────────────────────
_MODEL: SentenceTransformer = None
_RERANKER: CrossEncoder = None
_DEVICE = "cuda" if torch.cuda.is_available() else "cpu"


@app.on_event("startup")
def load_models():
    global _MODEL, _RERANKER
    logger.info(f"[BGE] 加载 Embedding 模型 (device={_DEVICE})...")
    t0 = time.time()
    _MODEL = SentenceTransformer("BAAI/bge-large-zh-v1.5", device=_DEVICE, model_kwargs={"torch_dtype": torch.float16})
    logger.info(f"[BGE] Embedding 模型加载完成, 耗时 {time.time()-t0:.1f}s")

    logger.info(f"[BGE] 加载 Reranker 模型 (device={_DEVICE})...")
    t0 = time.time()
    _RERANKER = CrossEncoder("BAAI/bge-reranker-v2-m3", device="cuda", automodel_args={"torch_dtype": torch.float16})
    logger.info(f"[BGE] Reranker 模型加载完成, 耗时 {time.time()-t0:.1f}s")


# ── 请求/响应模型 ────────────────────────────────────────

class EmbedRequest(BaseModel):
    text: str
    normalize: bool = True


class EmbedBatchRequest(BaseModel):
    texts: List[str]
    normalize: bool = True


class EmbedResponse(BaseModel):
    vector: List[float]
    dim: int
    elapsed: float


class EmbedBatchResponse(BaseModel):
    vectors: List[List[float]]
    dim: int
    elapsed: float


class RerankPair(BaseModel):
    query: str
    doc: str


class RerankRequest(BaseModel):
    query: str
    docs: List[str]
    top_k: Optional[int] = None


class RerankItem(BaseModel):
    doc: str
    score: float
    rank: int


class RerankResponse(BaseModel):
    query: str
    results: List[RerankItem]
    elapsed: float


# ── API ────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": _MODEL is not None,
        "reranker_loaded": _RERANKER is not None,
        "device": _DEVICE,
    }


@app.post("/embed", response_model=EmbedResponse)
def embed(req: EmbedRequest):
    if _MODEL is None:
        raise HTTPException(503, "模型未加载")
    t0 = time.time()
    vec = _MODEL.encode(req.text, normalize_embeddings=req.normalize).tolist()
    return EmbedResponse(vector=vec, dim=len(vec), elapsed=time.time() - t0)


@app.post("/embed_batch", response_model=EmbedBatchResponse)
def embed_batch(req: EmbedBatchRequest):
    if _MODEL is None:
        raise HTTPException(503, "模型未加载")
    t0 = time.time()
    vecs = _MODEL.encode(req.texts, normalize_embeddings=req.normalize).tolist()
    dim = len(vecs[0]) if vecs else 0
    return EmbedBatchResponse(vectors=vecs, dim=dim, elapsed=time.time() - t0)


@app.post("/rerank", response_model=RerankResponse)
def rerank(req: RerankRequest):
    """对候选文档重排序，按分数从高到低返回"""
    if _RERANKER is None:
        raise HTTPException(503, "Reranker 模型未加载")
    t0 = time.time()

    pairs = [[req.query, doc] for doc in req.docs]
    scores = _RERANKER.predict(pairs).tolist()

    ranked = sorted(
        [{"doc": doc, "score": score} for doc, score in zip(req.docs, scores)],
        key=lambda x: x["score"],
        reverse=True,
    )

    if req.top_k:
        ranked = ranked[: req.top_k]

    results = [
        RerankItem(doc=r["doc"], score=round(r["score"], 4), rank=i + 1)
        for i, r in enumerate(ranked)
    ]

    return RerankResponse(
        query=req.query, results=results, elapsed=time.time() - t0
    )
