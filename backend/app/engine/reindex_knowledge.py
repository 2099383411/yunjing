#!/usr/bin/env python3
"""重新索引知识库: 读 md 文件 -> chunking -> embedding -> Qdrant (附带全文索引 text 字段)"""
import json, time, sys, os, re as re_mod
import httpx
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

BGE_URL = "http://yunjing-bge:8000"
QDRANT_URL = "http://qdrant:6333"
KB_DIR = "/app/app/data/knowledge-base"
EMBED_DIM = 1024
CHUNK_SIZE = 500     # 每个 chunk 的字符数
CHUNK_OVERLAP = 50
EMBED_BATCH = 16

qdrant = QdrantClient(url=QDRANT_URL)
http = httpx.Client(timeout=60)

def split_markdown(filepath):
    """将 md 文件切片
    策略:
      - 按 ## 标题分割成较大块
      - 超过 CHUNK_SIZE 的块继续按段落/句子切分
    """
    with open(filepath, encoding="utf-8") as f:
        text = f.read()
    
    relpath = os.path.relpath(filepath, KB_DIR)
    
    # 先按 ## 标题分割
    sections = re_mod.split(r'(?=^## )', text, flags=re_mod.MULTILINE)
    chunks = []
    
    for section in sections:
        if not section.strip():
            continue
        
        # 提取标题
        h2 = ""
        m = re_mod.search(r'^## (.+)', section, re_mod.MULTILINE)
        if m:
            h2 = m.group(1).strip()
        
        # 提取 h3
        h3 = ""
        m = re_mod.search(r'^### (.+)', section, re_mod.MULTILINE)
        if m:
            h3 = m.group(1).strip()
        
        # 去掉 markdown 标记的标题行
        content = re_mod.sub(r'^#{1,6} .*\n?', '', section, flags=re_mod.MULTILINE).strip()
        
        if len(content) <= CHUNK_SIZE:
            if content:
                chunks.append({
                    "source": relpath,
                    "h2": h2,
                    "h3": h3,
                    "title": h3 or h2 or os.path.basename(relpath).replace(".md",""),
                    "content": content,
                })
        else:
            # 长内容分段
            start = 0
            for i in range(0, len(content), CHUNK_SIZE - CHUNK_OVERLAP):
                chunk_text = content[i:i+CHUNK_SIZE]
                if len(chunk_text) < 50 and i > 0:
                    continue
                chunks.append({
                    "source": relpath,
                    "h2": h2,
                    "h3": h3 + f" (part{i//CHUNK_SIZE+1})" if h3 else f"part{i//CHUNK_SIZE+1}",
                    "title": h3 or h2 or os.path.basename(relpath).replace(".md",""),
                    "content": chunk_text,
                })
    
    return chunks


def build_kb_text(doc):
    """知识库文档 → 搜索文本"""
    parts = []
    if doc.get("title"):
        parts.append(f"[{doc['title']}]")
    if doc.get("source"):
        parts.append(f"来源: {doc['source']}")
    if doc.get("h2"):
        parts.append(f"章节: {doc['h2']}")
    if doc.get("content"):
        parts.append(doc["content"][:3000])
    return ". ".join(parts) if parts else ""


def embed_batch(texts):
    """分小批 embedding"""
    vecs = []
    total = len(texts)
    for i in range(0, total, EMBED_BATCH):
        batch = texts[i:i+EMBED_BATCH]
        resp = http.post(
            f"{BGE_URL}/embed_batch",
            json={"texts": batch, "normalize": True},
            timeout=120,
        )
        resp.raise_for_status()
        batch_vecs = resp.json()["vectors"]
        vecs.extend(batch_vecs)
        pct = min(i+EMBED_BATCH, total) / total * 100
        sys.stderr.write(f"\r  embedding [{pct:5.1f}%] {min(i+EMBED_BATCH, total):>4d}/{total}")
        sys.stderr.flush()
    sys.stderr.write("\n")
    return vecs


if __name__ == "__main__":
    re = re_mod
    t0 = time.time()
    print("=" * 60)
    print("知识库重索引 (带 content & text 字段)")
    print(f"  KB_DIR: {KB_DIR}")
    print(f"  CHUNK_SIZE: {CHUNK_SIZE}")
    print(f"  BGE: {BGE_URL}")
    print("=" * 60)
    
    # Step 1: 读取所有 md 文件并切片
    print("\n[1/3] 读取并切片 Markdown...")
    all_chunks = []
    for root, dirs, files in os.walk(KB_DIR):
        for fn in sorted(files):
            if fn.endswith(".md"):
                fp = os.path.join(root, fn)
                chunks = split_markdown(fp)
                all_chunks.extend(chunks)
    print(f"  总切片数: {len(all_chunks)}")

    # Step 2: 构建搜索文本 + Embedding
    print("\n[2/3] 构建搜索文本 + Embedding...")
    texts = [build_kb_text(doc) for doc in all_chunks]
    vectors = embed_batch(texts)
    print(f"  完成: {len(vectors)} 向量")

    # Step 3: 删除旧集合并重建
    print("\n[3/3] 重建 knowledge 集合...")
    try:
        qdrant.delete_collection("knowledge")
        print("  已删除旧集合")
    except:
        pass
    time.sleep(0.5)
    
    qdrant.create_collection(
        collection_name="knowledge",
        vectors_config=qm.VectorParams(
            size=EMBED_DIM,
            distance=qm.Distance.COSINE,
        ),
    )
    
    # 创建全文索引
    try:
        qdrant.create_payload_index(
            collection_name="knowledge",
            field_name="text",
            field_schema=qm.PayloadSchemaType.TEXT,
        )
        print("  全文索引已创建")
    except Exception as e:
        print(f"  索引警告: {e}")
    
    # Upsert
    UPSERT_BATCH = 100
    points = []
    for i, (doc, vec, text) in enumerate(zip(all_chunks, vectors, texts)):
        points.append(qm.PointStruct(
            id=i + 1,
            vector=vec,
            payload={
                **doc,
                "text": text[:5000],
            },
        ))
    
    for i in range(0, len(points), UPSERT_BATCH):
        batch = points[i:i+UPSERT_BATCH]
        qdrant.upsert(collection_name="knowledge", points=batch, wait=True)
        print(f"  upsert {min(i+UPSERT_BATCH, len(points))}/{len(points)}")
    
    info = qdrant.get_collection("knowledge")
    print(f"\n  知识库: {info.points_count} points ✅")

    # Step 4: 验证
    print(f"\n{'='*60}")
    print(f"全部完成! 耗时: {time.time()-t0:.1f}s")
    
    # 抽样验证
    print("\n抽样检查知识库 text 字段:")
    rec, _ = qdrant.scroll("knowledge", limit=3, with_payload=True, with_vectors=False)
    for r in rec:
        txt = (r.payload.get("text", "") or "")[:100]
        print(f"  ID={r.id}: {txt}...")
