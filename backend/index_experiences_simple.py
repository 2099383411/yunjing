#!/usr/bin/env python3
"""
Simple indexer: batch embed all experiences and upsert to Qdrant.
"""
import json, sys, time, urllib.request

LEARNING_FILE = "/app/app/engine/learning_data.json"
BGE_URL = "http://yunjing-bge:8000/embed_batch"
QDRANT_URL = "http://qdrant:6333"
BATCH_SIZE = 16

def call_bge(texts):
    data = json.dumps({"texts": texts, "normalize": True}).encode()
    req = urllib.request.Request(BGE_URL, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())

def main():
    print("Loading experiences...", flush=True)
    with open(LEARNING_FILE) as f:
        doc = json.load(f)
    exps = doc["experiences"]
    total = len(exps)
    print(f"Total: {total} experiences", flush=True)
    
    # Prepare texts
    texts = []
    for e in exps:
        title = e.get("title", "")
        hyp = e.get("hypothesis", "")
        steps = " ".join(e.get("verification_steps", [])[:3])
        outcomes = " ".join(e.get("expected_outcomes", [])[:2])
        texts.append(f"{title}. {hyp} {steps} {outcomes}")
    
    # Batch embed
    all_vectors = []
    n_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
    
    for i in range(0, total, BATCH_SIZE):
        batch = texts[i:i+BATCH_SIZE]
        try:
            result = call_bge(batch)
            vectors = result.get("vectors", [])
            all_vectors.extend(vectors)
        except Exception as e:
            print(f"  [BGE Error] batch {i//BATCH_SIZE + 1}: {e}", flush=True)
            sys.exit(1)
        
        if (i + BATCH_SIZE) % 64 == 0 or i + BATCH_SIZE >= total:
            print(f"  Embedding: {min(i+BATCH_SIZE, total)}/{total}", flush=True)
    
    print(f"Embedded {len(all_vectors)} vectors, dim={len(all_vectors[0])}", flush=True)
    
    # Check collection exists
    with urllib.request.urlopen(f"{QDRANT_URL}/collections/experience", timeout=10) as resp:
        col_info = json.loads(resp.read())
    
    if col_info.get("result", {}).get("vectors_count", 0) > 0:
        print("Recreating collection...", flush=True)
        # Delete and recreate
        req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:
            json.loads(resp.read())
        
        create_data = json.dumps({
            "vectors": {"size": len(all_vectors[0]), "distance": "Cosine"}
        }).encode()
        req = urllib.request.Request(f"{QDRANT_URL}/collections/experience", data=create_data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            json.loads(resp.read())
        print("Collection recreated", flush=True)
    
    # Prepare points
    points = []
    for i, (exp, vec) in enumerate(zip(exps, all_vectors)):
        points.append({
            "id": i + 1,
            "vector": vec,
            "payload": {
                "exp_id": f"exp_{i+1}",
                "title": exp.get("title", ""),
                "target_type": exp.get("target_type", ""),
                "hypothesis": exp.get("hypothesis", ""),
                "verification_steps": json.dumps(exp.get("verification_steps", [])),
                "tools": json.dumps(exp.get("tools", [])),
                "expected_outcomes": json.dumps(exp.get("expected_outcomes", [])),
                "risk_level": exp.get("risk_level", "medium"),
                "mitigation": exp.get("mitigation", ""),
                "source": exp.get("source", "internal-all-the-things"),
                "category": exp.get("target_type", "")
            }
        })
    
    # Upsert in batches
    for i in range(0, len(points), 100):
        batch = points[i:i+100]
        data = json.dumps({"points": batch}).encode()
        url = f"{QDRANT_URL}/collections/experience/points?wait=true"
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        req.method = 'PUT'
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read())
            if result.get("status") == "ok":
                print(f"  Indexed: {i+len(batch)}/{len(points)}", flush=True)
            else:
                print(f"  [WARN] Batch {i//100 + 1}: {result}", flush=True)
                sys.exit(1)
    
    print(f"\nDone! {len(points)} experiences indexed to Qdrant", flush=True)
    
    # Verify
    with urllib.request.urlopen(f"{QDRANT_URL}/collections/experience", timeout=10) as resp:
        info = json.loads(resp.read())
    count = info.get("result", {}).get("vectors_count", 0)
    print(f"Qdrant experience collection: {count} vectors", flush=True)

if __name__ == "__main__":
    main()
