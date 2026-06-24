#!/usr/bin/env python3
"""Merge 200 new AD/Win experiences into learning_data.json and index to Qdrant."""
import json, sys, urllib.request

LEARNING_FILE = "/app/app/engine/learning_data.json"
NEW_FILE = "/app/exp_new.json"
BGE_URL = "http://yunjing-bge:8000/embed_batch"
QDRANT_URL = "http://qdrant:6333"
BATCH_SIZE = 16

def safe_str(v):
    if v is None: return ""
    if isinstance(v, dict): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return " ".join(str(x) for x in v)
    return str(v)

def main():
    print("="*50, flush=True)
    print("STEP 1: Merge experiences", flush=True)
    print("="*50, flush=True)
    
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    exps = doc["experiences"]
    print(f"Existing: {len(exps)}", flush=True)
    
    with open(NEW_FILE) as f:
        new_data = json.load(f)
    print(f"New: {len(new_data)}", flush=True)
    
    existing_titles = {e.get("title", "").strip(): i for i, e in enumerate(exps) if e.get("title")}
    added = 0
    for e in new_data:
        title = e.get("title", "").strip()
        if title and title not in existing_titles:
            exps.append(e)
            existing_titles[title] = len(exps) - 1
            added += 1
    
    print(f"Merged: {len(exps)} (+{added} new)", flush=True)
    
    doc["experiences"] = exps
    doc["meta"]["total_experiences"] = len(exps)
    import datetime
    doc["meta"]["last_updated"] = str(datetime.datetime.now())
    
    with open(LEARNING_FILE, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    print(f"Saved to {LEARNING_FILE}", flush=True)
    
    if added == 0:
        print("No new entries to add", flush=True)
        return
    
    print("\n" + "="*50, flush=True)
    print(f"STEP 2: Embed {added} new experiences", flush=True)
    print("="*50, flush=True)
    
    # Build texts for ONLY the new entries (last `added` items)
    new_exps = exps[-added:]
    texts = []
    for e in new_exps:
        parts = []
        if e.get("title"): parts.append(safe_str(e["title"]))
        if e.get("hypothesis"): parts.append(safe_str(e["hypothesis"]))
        if e.get("target_type"): parts.append("Target: " + safe_str(e["target_type"]))
        if e.get("verification_steps"): parts.append(" ".join(safe_str(s) for s in (e["verification_steps"] if isinstance(e["verification_steps"], list) else [])[:3]))
        if e.get("tools"): parts.append("Tools: " + ", ".join(safe_str(t) for t in (e["tools"] if isinstance(e["tools"], list) else [])[:5]))
        texts.append(". ".join(parts) if parts else "")
    
    all_vectors = []
    n_batches = (len(texts) + BATCH_SIZE - 1) // BATCH_SIZE
    
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i:i+BATCH_SIZE]
        t0 = __import__('time').time()
        try:
            data = json.dumps({"texts": batch, "normalize": True}).encode()
            req = urllib.request.Request(BGE_URL, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            vecs = result.get("vectors", [])
            all_vectors.extend(vecs)
            dt = __import__('time').time() - t0
            print(f"  [{i//BATCH_SIZE+1}/{n_batches}] {min(i+BATCH_SIZE, len(texts))}/{len(texts)} ({dt:.1f}s)", flush=True)
        except Exception as e:
            print(f"  [ERROR] batch {i//BATCH_SIZE+1}: {e}", flush=True)
            sys.exit(1)
    
    print(f"Embedded {len(all_vectors)} vectors, dim={len(all_vectors[0])}", flush=True)
    
    print("\n" + "="*50, flush=True)
    print(f"STEP 3: Index to Qdrant (append to existing 1695)", flush=True)
    print("="*50, flush=True)
    
    # Get current max point ID from Qdrant
    from urllib.request import urlopen
    info = json.loads(urlopen(f"{QDRANT_URL}/collections/experience", timeout=10).read())
    current_count = info.get("result", {}).get("points_count", 0)
    start_id = current_count
    print(f"Current points: {current_count}, appending from ID {start_id + 1}", flush=True)
    
    points = []
    for i, (exp, vec) in enumerate(zip(new_exps, all_vectors)):
        has_title = bool(exp.get("title", ""))
        points.append({
            "id": start_id + i + 1,
            "vector": vec,
            "payload": {
                "exp_id": f"exp_{start_id + i + 1}",
                "title": safe_str(exp.get("title", exp.get("pattern_id", "")))[:200],
                "target_type": safe_str(exp.get("target_type", "unknown"))[:100],
                "hypothesis": safe_str(exp.get("hypothesis", ""))[:500],
                "source": "hacktricks" if has_title and "verification_steps" in exp else "hacktricks"
            }
        })
    
    for i in range(0, len(points), 100):
        batch = points[i:i+100]
        data = json.dumps({"points": batch}).encode()
        url = f"{QDRANT_URL}/collections/experience/points?wait=true"
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        req.method = "PUT"
        with urllib.request.urlopen(req, timeout=120) as resp:
            r = json.loads(resp.read())
            top_status = r.get("status", "")
            op_status = r.get("result", {}).get("status", "") if isinstance(r.get("result"), dict) else ""
            if top_status == "ok" or op_status == "completed":
                print(f"  Indexed {i+len(batch)}/{len(points)}", flush=True)
            else:
                print(f"  [WARN] batch {i//100+1}: {str(r)[:200]}", flush=True)
                sys.exit(1)
    
    print(f"\nDone! {len(points)} new experiences indexed to Qdrant", flush=True)
    
    # Verify
    info2 = json.loads(urlopen(f"{QDRANT_URL}/collections/experience", timeout=10).read())
    count2 = info2.get("result", {}).get("points_count", 0)
    print(f"Qdrant experience collection: {count2} vectors (was {current_count}) ✅", flush=True)

if __name__ == "__main__":
    main()
