#!/usr/bin/env python3
"""高效更新: 保留现有向量, 只更新 payload text 字段 + 创建全文索引"""
import json, time, sys, os
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

QDRANT_URL = "http://qdrant:6333"
LEARNING_FILE = "/app/app/engine/learning_data.json"
KB_DIR = "/app/app/data/knowledge-base"
BATCH = 100

qdrant = QdrantClient(url=QDRANT_URL)


def build_exp_text(exp):
    """v2 _build_experience_text"""
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
    tt = exp.get("target_type", "") or exp.get("category", "") or exp.get("type", "")
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
            sig_parts = [str(s.get("name", s.get("detail", ""))) if isinstance(s, dict) else str(s) for s in signals[:5]]
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


def update_collection_text(name, docs, build_fn):
    """遍历集合 point, 计算新的 text 字段, 用 set_payload 更新"""
    print(f"\n{'='*50}")
    print(f"更新 {name} 集合 text 字段...")
    t0 = time.time()

    # Step 1: 创建全文索引（幂等）
    try:
        qdrant.create_payload_index(
            collection_name=name,
            field_name="text",
            field_schema=qm.PayloadSchemaType.TEXT,
        )
        print("  全文索引已创建")
    except Exception as e:
        if "already exists" in str(e).lower():
            print("  全文索引已存在")
        else:
            print(f"  索引警告: {e}")

    # Step 2: Scroll 所有 points, 更新 text 字段
    next_offset = None
    updated = 0
    errors = 0
    
    while True:
        records, next_offset = qdrant.scroll(
            collection_name=name,
            limit=BATCH,
            offset=next_offset,
            with_payload=True,
            with_vectors=False,
        )
        if not records:
            break

        points_to_update = []
        for pt in records:
            # 找到匹配的文档
            pid = pt.id  # 1-based
            if pid <= len(docs):
                doc = docs[pid - 1]
            else:
                doc = pt.payload

            text = build_fn(doc)
            if not text.strip():
                # 用当前 payload 构建 fallback
                text = build_fn(pt.payload)
            
            points_to_update.append(qm.PointStruct(
                id=pt.id,
                vector={},  # 不更新向量
                payload={"text": text[:5000]},
            ))

        # 使用 overwrite_payload 或 upsert 只更新 payload
        if points_to_update:
            try:
                qdrant.upsert(
                    collection_name=name,
                    points=[qm.PointStruct(
                        id=p.id,
                        vector=qdrant._client.get_collection(name).points.get(p.id, {}).get("vector", []),
                        payload=p.payload,
                    ) for p in points_to_update],
                    wait=True,
                )
            except:
                # fallback: set_payload
                for p in points_to_update:
                    try:
                        qdrant.set_payload(
                            collection_name=name,
                            payload=p.payload,
                            points=[p.id],
                            wait=True,
                        )
                    except:
                        errors += 1

            updated += len(points_to_update)
        
        sys.stderr.write(f"\r  已更新 {updated} 条 (错误 {errors})...")
        sys.stderr.flush()

        if next_offset is None:
            break

    print(f"\n  完成: {updated} 条更新, {errors} 错误, 耗时 {time.time()-t0:.1f}s")
    info = qdrant.get_collection(name)
    print(f"  {name}: {info.points_count} points")


def update_via_scroll_only(name, docs, build_fn):
    """使用 set_payload 逐个更新 text 字段（轻量）"""
    print(f"\n{'='*50}")
    print(f"轻量更新 {name} 集合 text 字段...")
    t0 = time.time()

    # 创建全文索引（幂等）
    try:
        qdrant.create_payload_index(
            collection_name=name,
            field_name="text",
            field_schema=qm.PayloadSchemaType.TEXT,
        )
        print("  全文索引已创建")
    except:
        print("  全文索引已存在")

    next_offset = None
    updated = 0
    errors = 0

    while True:
        records, next_offset = qdrant.scroll(
            collection_name=name,
            limit=BATCH,
            offset=next_offset,
            with_payload=True,
            with_vectors=False,
        )
        if not records:
            break

        for pt in records:
            pid = pt.id
            if pid <= len(docs):
                doc = docs[pid - 1]
            else:
                doc = pt.payload
            text = build_fn(doc)
            if not text.strip():
                text = build_fn(pt.payload)

            try:
                qdrant.set_payload(
                    collection_name=name,
                    payload={"text": text[:5000]},
                    points=[pt.id],
                    wait=True,
                )
                updated += 1
            except Exception as e:
                errors += 1

            if updated % 200 == 0:
                sys.stderr.write(f"\r  已更新 {updated} 条 (错误 {errors})...")
                sys.stderr.flush()

        if next_offset is None:
            break

    print(f"\n  完成: {updated} 条更新, {errors} 错误, 耗时 {time.time()-t0:.1f}s")
    info = qdrant.get_collection(name)
    print(f"  {name}: {info.points_count} points")


if __name__ == "__main__":
    print("=" * 60)
    print("RAG v2 payload 更新 (保留向量, 只加 text 字段)")
    print(f"  Qdrant: {QDRANT_URL}")
    print("=" * 60)

    # 1. 经验库
    print("\n[1/2] 读取经验库数据...")
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    raw = doc.get("experiences", doc)
    if isinstance(raw, dict) and "experiences" in raw:
        raw = raw["experiences"]
    exps = list(raw)
    print(f"  读取: {len(exps)} 条经验")

    update_via_scroll_only("experience", exps, build_exp_text)

    # 2. 知识库
    print("\n[2/2] 读取知识库数据...")
    kb_docs = []
    for root, dirs, files in os.walk(KB_DIR):
        for fn in files:
            if fn.endswith(".md"):
                fp = os.path.join(root, fn)
                try:
                    with open(fp, encoding="utf-8") as fh:
                        content = fh.read()
                    name = os.path.relpath(fp, KB_DIR)
                    kb_docs.append({"title": name, "content": content, "path": name})
                except:
                    pass
    print(f"  读取: {len(kb_docs)} 个文档")

    def build_kb_text(doc):
        return doc.get("title", "") + ": " + doc.get("content", "")[:3000]

    update_via_scroll_only("knowledge", kb_docs, build_kb_text)

    # 3. 验证
    print(f"\n{'='*60}")
    info_kb = qdrant.get_collection("knowledge")
    info_exp = qdrant.get_collection("experience")
    print(f"  知识库: {info_kb.points_count} points (full-text index: text)")
    print(f"  经验库: {info_exp.points_count} points (full-text index: text)")
    print(f"\n✅ 完成! text 字段已更新, 全文索引已就绪")
