#!/usr/bin/env python3
"""修复知识库 text 字段：从 md 源文件读取内容，不重新 embedding"""
import sys, os, time, re as re_mod
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

QDRANT_URL = "http://qdrant:6333"
KB_DIR = "/app/app/data/knowledge-base"
BATCH = 100

qdrant = QdrantClient(url=QDRANT_URL)

def extract_section(filepath, h2_target, h3_target):
    """从 md 文件中提取指定 section 的内容"""
    try:
        with open(filepath, encoding="utf-8") as f:
            text = f.read()
    except:
        return ""
    
    lines = text.split("\n")
    
    # 如果没有 h2/h3，返回整个文件前 2000 字符
    if not h2_target and not h3_target:
        return text[:2000]
    
    # 找到 h2 的位置
    h2_pattern = re_mod.compile(r'^##\s+' + re_mod.escape(h2_target) + r'\s*$', re_mod.MULTILINE)
    h2_match = h2_pattern.search(text)
    if not h2_match:
        return f"[{h2_target}] (section not found)"
    
    h2_start = h2_match.end()
    
    # 找到下一个 ## 的位置（同级别标题）
    next_h2 = re_mod.search(r'\n## ', text[h2_start:])
    h2_end = h2_start + next_h2.start() if next_h2 else len(text)
    
    section_text = text[h2_start:h2_end].strip()
    
    # 如果有 h3，进一步定位
    if h3_target:
        h3_pattern = re_mod.compile(r'^###\s+' + re_mod.escape(h3_target) + r'\s*$', re_mod.MULTILINE)
        h3_match = h3_pattern.search(text[h2_start:h2_end])
        if h3_match:
            h3_start = h2_start + h3_match.end()
            next_h3 = re_mod.search(r'\n### |\n## ', text[h3_start:h2_end+10])
            h3_end = h2_start + next_h3.start() if next_h3 else h2_end
            section_text = text[h3_start:h3_end].strip()
    
    return section_text[:3000]


def build_knowledge_text(payload):
    """从 payload metadata + 源文件构建搜索文本"""
    meta = payload.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    
    source = meta.get("source", "")
    h2 = meta.get("h2", "")
    h3 = meta.get("h3", "")
    title = meta.get("title", "")
    
    # 读取源文件内容
    content = ""
    if source:
        fp = os.path.join(KB_DIR, source)
        content = extract_section(fp, h2, h3)
    
    parts = []
    if title:
        parts.append(f"[{title}]")
    if source:
        parts.append(f"来源: {source}")
    if h2:
        parts.append(f"章节: {h2}")
    if content:
        parts.append(content[:2000])
    
    return ". ".join(parts) if parts else ""


if __name__ == "__main__":
    re = re_mod
    t0 = time.time()
    print("=" * 60)
    print("知识库 text 字段修复 (从源文件重建, 不重新 embedding)")
    print(f"  Qdrant: {QDRANT_URL}")
    print(f"  KB_DIR: {KB_DIR}")
    print("=" * 60)
    
    # Step 1: Scroll 所有 knowledge points
    print("\n[1/2] 读取知识库 points...")
    next_offset = None
    all_records = []
    while True:
        records, next_offset = qdrant.scroll(
            collection_name="knowledge",
            limit=BATCH,
            offset=next_offset,
            with_payload=True,
            with_vectors=False,
        )
        if not records:
            break
        all_records.extend(records)
        print(f"  已读取 {len(all_records)} 条...", end="\r")
        sys.stdout.flush()
        if next_offset is None:
            break
    
    print(f"\n  总计 {len(all_records)} 条知识库记录")
    
    # Step 2: 为每个 point 构建 text 字段并更新
    print("\n[2/2] 更新 text 字段 (set_payload)...")
    updated = 0
    errors = 0
    empty = 0
    
    for pt in all_records:
        text = build_knowledge_text(pt.payload)
        if not text.strip():
            empty += 1
            # fallback: 至少用 metadata 里的信息
            meta = pt.payload.get("metadata", {})
            if isinstance(meta, dict):
                text = f"[{meta.get('title','')}] 来源: {meta.get('source','')} 章节: {meta.get('h2','')}"
        
        try:
            qdrant.set_payload(
                collection_name="knowledge",
                payload={"text": text[:5000]},
                points=[pt.id],
                wait=True,
            )
            updated += 1
        except Exception as e:
            errors += 1
        
        if updated % 200 == 0:
            print(f"  已更新 {updated} (错误 {errors}, 空 {empty})...", end="\r")
    
    print(f"\n  完成: {updated} 条更新, {errors} 错误, {empty} 空文本")
    
    # Step 3: 确认全文索引
    try:
        qdrant.create_payload_index(
            collection_name="knowledge",
            field_name="text",
            field_schema=qm.PayloadSchemaType.TEXT,
        )
        print("  全文索引已确认")
    except Exception as e:
        if "already exists" in str(e).lower():
            print("  全文索引已存在")
        else:
            print(f"  全文索引: {e}")
    
    # Step 4: 验证
    print(f"\n{'='*60}")
    print(f"完成! 耗时: {time.time()-t0:.1f}s")
    
    # 抽样验证
    print("\n抽样检查:")
    rec, _ = qdrant.scroll("knowledge", limit=3, with_payload=True, with_vectors=False)
    for r in rec:
        txt = (r.payload.get("text", "") or "")[:120]
        print(f"  ID={r.id}: {txt}")
