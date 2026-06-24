#!/usr/bin/env python3
"""Index pre-computed BGE vectors to Qdrant."""
import json, sys, urllib.request

LEARNING_FILE = "/app/app/engine/learning_data.json"
VECTORS_FILE = "/app/exp_vectors.json"
QDRANT_URL = "http://qdrant:6333"

def safe_str(v):
    if v is None: return ""
    if isinstance(v, dict): return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list): return " ".join(str(x) for x in v)
    return str(v)

def main():
    print("Loading experiences...", flush=True)
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    exps = doc.get("experiences", doc) if isinstance(doc, dict) else doc
    if isinstance(exps, dict) and "experiences" in exps:
        exps = exps["experiences"]
    
    print(f"Experiences: {len(exps)}", flush=True)
    
    print("Loading vectors...", flush=True)
    with open(VECTORS_FILE) as f:
        vec_data = json.load(f)
    vectors = vec_data["vectors"]
    print(f"Vectors: {len(vectors)}, dim={vec_data['dim']}", flush=True)
    
    assert len(exps) == len(vectors), f"Count mismatch: {len(exps)} vs {len(vectors)}"
    
    # Recreate Qdrant collection - delete first (may 404 if doesn't exist)
    print("Recreating Qdrant collection...", flush=True)
    try:
        req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:
            _ = resp.read()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"  Delete failed: {e.code} {e.reason}", flush=True)
    except Exception as e:
        print(f"  Delete error: {e}", flush=True)
    
    create = json.dumps({"vectors": {"size": vec_data["dim"], "distance": "Cosine"}}).encode()
    req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", data=create,
                                 headers={"Content-Type": "application/json"})
    req.method = "PUT"
    with urllib.request.urlopen(req, timeout=30) as resp:
        json.loads(resp.read())
    print("Collection created", flush=True)
    
    # Build points
    points = []
    for i, (exp, vec) in enumerate(zip(exps, vectors)):
        has_title = bool(exp.get("title", ""))
        points.append({
            "id": i + 1,
            "vector": vec,
            "payload": {
                "exp_id": f"exp_{i+1}",
                "title": safe_str(exp.get("title", exp.get("pattern_id", "")))[:200],
                "target_type": safe_str(exp.get("target_type", "unknown"))[:100],
                "hypothesis": safe_str(exp.get("hypothesis", ""))[:500],
                "source": "hacktricks" if has_title and "verification_steps" in exp 
                          else "payloads-all-the-things" if has_title 
                          else "internal-all-the-things"
            }
        })
    
    # Upsert in batches
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
                print(f"  [WARN] batch {i//100+1}: {json.dumps(r)[:200]}", flush=True)
                sys.exit(1)
    
    print(f"\nDone! {len(points)} experiences indexed to Qdrant", flush=True)
    
    # Verify
    with urllib.request.urlopen(f"{QDRANT_URL}/collections/experience", timeout=10) as resp:
        info = json.loads(resp.read())
    count = info.get("result", {}).get("vectors_count", 0)
    print(f"Qdrant experience collection: {count} vectors ✅", flush=True)

if __name__ == "__main__":
    main()
