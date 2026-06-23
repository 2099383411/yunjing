#!/usr/bin/env python3
"""
RAG v2 完全重索引 — 分小批 Embedding
目标: 用新的 _build_experience_text 重建经验库 + 知识库 + 全文索引
"""
import json, sys, time, os
import httpx
from qdrant_client import QdrantClient
from qdrant_client.http import models as qdrant_models

BGE_URL = "http://yunjing-bge:8000"
QDRANT_URL = "http://qdrant:6333"
LEARNING_FILE = "/app/app/engine/learning_data.json"
KB_DIR = "/app/app/data/knowledge-base"
EMBED_DIM = 1024
BATCH_SIZE = 16
UPSERT_BATCH = 100

qdrant = QdrantClient(url=QDRANT_URL)
http = httpx.Client(timeout=60)


def build_exp_text_v2(exp):
    """新版 _build_experience_text (从 vector_store.py 同步)"""
    parts = []
    title = exp.get("title", "")
    if title:
        parts.append(f"[{title}]")
    elif exp.get("pattern_id"):
        parts.append(f"[{exp.get('pattern_id', '')}]")
    hyp = exp.get("hypothesis", "")
    if hyp:
        if isinstance(hyp, dict):
            parts.append(f"假设: {hyp.get('name', json.dumps(hyp, ensure_ascii=False))}")
        elif isinstance(hyp, str):
            parts.append(f"假设: {hyp}")
    tt = exp.get("target_type", "")
    if tt:
        parts.append(f"类型: {tt}")
    target = exp.get("target", {})
    if isinstance(target, dict):
        tname = target.get("name", "") or target.get("host", "") or target.get("url", "")
        if tname:
            parts.append(f"目标: {tname}")
    elif isinstance(target, str) and target:
        parts.append(f"目标: {target}")
    steps = exp.get("verification_steps", [])
    if isinstance(steps, list) and steps:
        s_text = "; ".join(str(s)[:200] for s in steps[:5])
        if s_text:
            parts.append(f"验证: {s_text}")
    elif isinstance(steps, str) and steps:
        parts.append(f"验证: {steps}")
    ver = exp.get("verification", "")
    if ver and not steps:
        parts.append(f"验证: {str(ver)[:500]}")
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
    tools = exp.get("tools", [])
    if isinstance(tools, list) and tools:
        parts.append(f"工具: {', '.join(str(t)[:50] for t in tools[:8])}")
    outcomes = exp.get("expected_outcomes", [])
    if isinstance(outcomes, list) and outcomes:
        parts.append(f"预期: {'; '.join(str(o)[:100] for o in outcomes[:3])}")
    expl = exp.get("exploitation", "")
    if expl and not outcomes:
        parts.append(f"利用: {str(expl)[:300]}")
    rp = exp.get("reasoning_path", "")
    if rp:
        if isinstance(rp, list):
            parts.append(f"推理链: {' -> '.join(str(x)[:100] for x in rp[:5])}")
        elif isinstance(rp, str):
            parts.append(f"推理链: {rp[:300]}")
    cve = exp.get("cve", "") or exp.get("reference", "")
    if cve:
        parts.append(f"编号: {str(cve)[:100]}")
    return ". ".join(parts) if parts else ""


def embed_one(text):
    resp = http.post(f"{BGE_URL}/embed", json={"text": text, "normalize": True}, timeout=30)
    resp.raise_for_status()
    return resp.json()["vector"]


def embed_batch(texts):
    """分小批 embedding 并返回完整向量列表"""
    vecs = []
    total = len(texts)
    for i in range(0, total, BATCH_SIZE):
        batch = texts[i:i+BATCH_SIZE]
        resp = http.post(
            f"{BGE_URL}/embed_batch",
            json={"texts": batch, "normalize": True},
            timeout=120,
        )
        resp.raise_for_status()
        batch_vecs = resp.json()["vectors"]
        vecs.extend(batch_vecs)
        elapsed = time.time() - t_start
        pct = min(i + BATCH_SIZE, total) / total * 100
        rate = (i + BATCH_SIZE) / elapsed if elapsed > 0 else 0
        sys.stderr.write(f"\r  [{pct:5.1f}%] {min(i+BATCH_SIZE, total):>5d}/{total} ({rate:.1f} item/s)")
        sys.stderr.flush()
    sys.stderr.write("\n")
    return vecs


def recreate_collection(name, points):
    """删除重建集合，带全文索引"""
    try:
        qdrant.delete_collection(name)
        print(f"  已删除集合 {name}")
    except:
        pass
    time.sleep(0.5)

    qdrant.create_collection(
        collection_name=name,
        vectors_config=qdrant_models.VectorParams(
            size=EMBED_DIM, distance=qdrant_models.Distance.COSINE
        ),
    )
    try:
        qdrant.create_payload_index(
            collection_name=name,
            field_name="text",
            field_schema=qdrant_models.PayloadSchemaType.TEXT,
        )
        print(f"  已创建全文索引 {name}")
    except Exception as e:
        print(f"  索引创建警告: {e}")

    for i in range(0, len(points), UPSERT_BATCH):
        batch = points[i:i+UPSERT_BATCH]
        qdrant.upsert(collection_name=name, points=batch, wait=True)
        print(f"  upsert {min(i+UPSERT_BATCH, len(points))}/{len(points)} [{name}]")

    info = qdrant.get_collection(name)
    print(f"  {name}: {info.points_count} points")
    return info.points_count


def test_search(query, top_k=3):
    """执行同步搜索验证"""
    # Step 1: Embed query
    qv = embed_one(query)
    keywords = re.findall(r"CVE-\d{4}-\d+|[a-zA-Z][a-zA-Z0-9._-]{2,}|[\u4e00-\u9fff]{2,}", query)
    keywords = [k for k in keywords if k.lower() not in {"the","and","for","are","was","but","not","you","all","can","how","why","via","get","use","set","new","old"}]
    
    candidates = []
    seen = set()
    
    for col in ["experience", "knowledge"]:
        # Semantic
        sr = qdrant.query_points(
            collection_name=col, query=qv, limit=top_k * 5,
            with_payload=True, score_threshold=0.5,
        )
        for p in sr.points:
            uid = f"{col}_{p.id}"
            if uid not in seen:
                seen.add(uid)
                candidates.append({"payload": p.payload or {}, "score": p.score, "col": col})
        
        # Keyword
        if keywords:
            kw_filters = [
                qdrant_models.FieldCondition(
                    key="text",
                    match=qdrant_models.MatchText(text=k),
                ) for k in keywords[:3]
            ]
            kr = qdrant.query_points(
                collection_name=col, query=qv,
                query_filter=qdrant_models.Filter(should=kw_filters),
                limit=top_k * 3, with_payload=True,
            )
            for p in kr.points:
                uid = f"{col}_{p.id}"
                if uid not in seen:
                    seen.add(uid)
                    candidates.append({"payload": p.payload or {}, "score": p.score, "col": col})
    
    # Rerank
    if not candidates:
        return (query, [])
    docs = []
    for c in candidates:
        exp = c["payload"]
        if c["col"] == "knowledge":
            doc = exp.get("content", "")[:2000]
        else:
            doc = build_exp_text_v2(exp)[:2000]
        docs.append(doc)
    
    try:
        rr = http.post(
            f"{BGE_URL}/rerank",
            json={"query": query, "texts": docs},
            timeout=30,
        )
        rr.raise_for_status()
        rd = rr.json()
        if "results" in rd:
            ranked = sorted(rd["results"], key=lambda x: x.get("relevance_score", 0), reverse=True)[:top_k]
            return (query, [(candidates[r["index"]], r.get("relevance_score", 0)) for r in ranked])
    except:
        pass
    return (query, [(candidates[0], 0)])


if __name__ == "__main__":
    import re as re_mod
    re = re_mod
    
    global t_start
    t_start = time.time()
    print("=" * 60)
    print("RAG v2 完全重索引 (分批 embedding)")
    print(f"  BGE: {BGE_URL}")
    print(f"  Qdrant: {QDRANT_URL}")
    print(f"  Batch size: {BATCH_SIZE}")
    print("=" * 60)

    # ====== 1. 经验库 ======
    print("\n[1/2] 重建经验库...")
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    raw = doc.get("experiences", doc)
    if isinstance(raw, dict) and "experiences" in raw:
        raw = raw["experiences"]
    exps = list(raw)
    print(f"  读取: {len(exps)} 条")

    exp_texts = [build_exp_text_v2(e) for e in exps]
    empty = sum(1 for t in exp_texts if not t.strip())
    print(f"  空文本: {empty} 条")
    
    if empty > 100:
        print("  ⚠️ 过多空文本，检查样本...")
        for i, e in enumerate(exps):
            t = build_exp_text_v2(e)
            if not t.strip():
                print(f"    样本[{i}]: keys={list(e.keys())}, title={e.get('title','')[:50]}, pattern={e.get('pattern_id','')[:30]}")
                if i >= 3:
                    break

    print(f"  向量化 {len(exp_texts)} 条...")
    exp_vecs = embed_batch(exp_texts)
    print(f"  完成: {len(exp_vecs)} 向量")

    exp_points = []
    for i, (exp, vec, text) in enumerate(zip(exps, exp_vecs, exp_texts)):
        exp_points.append(qdrant_models.PointStruct(
            id=i + 1,
            vector=vec,
            payload={**exp, "text": text[:5000]},
        ))

    n_exp = recreate_collection("experience", exp_points)

    # ====== 2. 知识库 ======
    print("\n[2/2] 重建知识库...")
    kb_docs = []
    for root, dirs, files in os.walk(KB_DIR):
        for f in files:
            if f.endswith(".md"):
                fp = os.path.join(root, f)
                try:
                    with open(fp, encoding="utf-8") as fh:
                        content = fh.read()
                    name = os.path.relpath(fp, KB_DIR)
                    kb_docs.append({"title": name, "content": content, "path": name})
                except:
                    pass
    print(f"  读取: {len(kb_docs)} 个文档")

    kb_texts = [doc.get("title", "") + ": " + doc.get("content", "")[:3000] for doc in kb_docs]
    print(f"  向量化 {len(kb_texts)} 条...")
    kb_vecs = embed_batch(kb_texts)
    print(f"  完成: {len(kb_vecs)} 向量")

    kb_points = []
    for i, (doc, vec, text) in enumerate(zip(kb_docs, kb_vecs, kb_texts)):
        kb_points.append(qdrant_models.PointStruct(
            id=i + 1,
            vector=vec,
            payload={**doc, "text": text[:5000]},
        ))

    n_kb = recreate_collection("knowledge", kb_points)

    # ====== 3. 验证 ======
    print(f"\n{'=' * 60}")
    print(f"索引完成: 经验={n_exp}, 知识库={n_kb}")
    print(f"耗时: {time.time() - t_start:.1f}s")
    print(f"{'=' * 60}")
    
    print("\n验证搜索...")
    queries = [
        "SQL injection detection",
        "Windows privilege escalation token",
        "Kerberos attack AD",
        "ZeroLogon CVE-2020-1472",
        "Linux SUID privilege escalation",
        "NTLM relay attack",
        "Apache path traversal",
        "SSRF vulnerability detection",
    ]
    for q in queries:
        qry, results = test_search(q, top_k=3)
        if results:
            scores = [f"{s:.4f}" for _, s in results]
            titles = []
            for r, _ in results:
                p = r["payload"]
                t = p.get("title", p.get("pattern_id", ""))[:40]
                titles.append(t)
            print(f"  {q[:30]:30s} scores={scores} title={titles[0] if titles else '?'}")
        else:
            print(f"  {q[:30]:30s} ❌ 无结果")

    print(f"\n✅ 全部完成!")
