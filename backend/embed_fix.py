#!/usr/bin/env python3
"""Embed all experiences and index to Qdrant. Handles mixed schema."""
import json, sys, time, urllib.request

LEARNING_FILE = "/app/app/engine/learning_data.json"
BGE_URL = "http://yunjing-bge:8000/embed_batch"
QDRANT_URL = "http://qdrant:6333"
BATCH_SIZE = 16

def safe_str(v):
    if v is None: return ""
    if isinstance(v, dict): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return " ".join(str(x) for x in v)
    return str(v)

def build_text(e):
    parts = []
    if "title" in e and e["title"]: parts.append(safe_str(e["title"]))
    if "hypothesis" in e and e["hypothesis"]: parts.append(safe_str(e["hypothesis"]))
    if "target_type" in e and e["target_type"]: parts.append("Target: " + safe_str(e["target_type"]))
    if "verification_steps" in e: parts.append(" ".join(safe_str(s) for s in (e["verification_steps"] if isinstance(e["verification_steps"], list) else [])[:3]))
    if "signals" in e: parts.append(safe_str(e["signals"]))
    if "verification" in e: parts.append(safe_str(e["verification"]))
    if "expected_outcomes" in e: parts.append(" ".join(safe_str(s) for s in (e["expected_outcomes"] if isinstance(e["expected_outcomes"], list) else [])[:2]))
    if "pattern_id" in e: parts.append("Pattern: " + safe_str(e["pattern_id"]))
    if "tools" in e and isinstance(e["tools"], list): parts.append("Tools: " + ", ".join(safe_str(t) for t in e["tools"][:5]))
    return ". ".join(parts) if parts else ""

def main():
    print("Loading experiences...", flush=True)
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    exps = doc.get("experiences", doc) if isinstance(doc, dict) else doc
    if isinstance(exps, dict):
        keys = list(exps.keys())
        if "experiences" in exps:
            exps = exps["experiences"]
        else:
            print(f"Dict with keys: {keys[:10]}", flush=True)
            return
    
    total = len(exps)
    print(f"Total: {total} experiences", flush=True)
    print(f"Sample keys: {list(exps[0].keys()) if exps else 'empty'}", flush=True)
    
    texts = [build_text(e) for e in exps]
    print(f"Sample text[:150]: {texts[0][:150]}", flush=True)
    
    # Batch embed
    all_vectors = []
    n_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
    
    for i in range(0, total, BATCH_SIZE):
        batch = texts[i:i+BATCH_SIZE]
        t0 = time.time()
        try:
            data = json.dumps({"texts": batch, "normalize": True}).encode()
            req = urllib.request.Request(BGE_URL, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=300) as resp:
                result = json.loads(resp.read())
            vecs = result.get("vectors", [])
            all_vectors.extend(vecs)
            dt = time.time() - t0
            print(f"  [{i//BATCH_SIZE+1}/{n_batches}] {min(i+BATCH_SIZE,total)}/{total} ({dt:.1f}s)", flush=True)
        except Exception as e:
            print(f"  [ERROR] batch {i//BATCH_SIZE+1}: {e}", flush=True)
            sys.exit(1)
    
    print(f"Embedded {len(all_vectors)} vectors, dim={len(all_vectors[0])}", flush=True)
    
    # Recreate collection
    print("Recreating Qdrant collection...", flush=True)
    try:
        req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:
            json.loads(resp.read())
    except:
        pass
    
    create = json.dumps({"vectors": {"size": len(all_vectors[0]), "distance": "Cosine"}}).encode()
    req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", data=create, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        json.loads(resp.read())
    print("Collection created", flush=True)
    
    # Upsert
    points = []
    for i, (exp, vec) in enumerate(zip(exps, all_vectors)):
        has_title = "title" in exp and exp["title"]
        points.append({
            "id": i + 1,
            "vector": vec,
            "payload": {
                "exp_id": f"exp_{i+1}",
                "title": safe_str(exp.get("title", exp.get("pattern_id", ""))),
                "target_type": safe_str(exp.get("target_type", "unknown")),
                "hypothesis": safe_str(exp.get("hypothesis", "")),
                "source": "hacktricks" if has_title and "verification_steps" in exp else "internal-all-the-things" if has_title else "payloads-all-the-things"
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
            if r.get("status") == "ok":
                print(f"  Indexed: {i+len(batch)}/{len(points)}", flush=True)
            else:
                print(f"  [WARN] batch {i//100+1}: {r}", flush=True)
                sys.exit(1)
    
    print(f"\nDone! {len(points)} experiences indexed to Qdrant", flush=True)
    
    # Verify
    with urllib.request.urlopen(f"{QDRANT_URL}/collections/experience", timeout=10) as resp:
        info = json.loads(resp.read())
    count = info.get("result", {}).get("vectors_count", 0)
    print(f"Qdrant experience collection: {count} vectors", flush=True)

if __name__ == "__main__":
    main()
