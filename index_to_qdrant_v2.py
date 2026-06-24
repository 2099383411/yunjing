#!/usr/bin/env python3
"""Index experiences from learning_data.json to Qdrant (run inside backend container)."""
import json, hashlib, time, sys
import httpx

QDRANT_URL = "http://yunjing-qdrant:6333"
BGE_URL = "http://yunjing-bge:8000"

def embed(text):
    r = httpx.post(f"{BGE_URL}/embed", json={"text": text}, timeout=30)
    r.raise_for_status()
    d = r.json()
    if isinstance(d, list):
        return d
    return d.get("embedding", d.get("vector", d.get("data", [])))

def upsert(collection, point):
    httpx.put(f"{QDRANT_URL}/collections/{collection}/points",
              json={"points": [point]}, timeout=10).raise_for_status()

def ensure_collection(name):
    r = httpx.get(f"{QDRANT_URL}/collections/{name}", timeout=5)
    if r.status_code != 200:
        httpx.put(f"{QDRANT_URL}/collections/{name}",
                  json={"vectors": {"size": 1024, "distance": "Cosine"}}, timeout=10)

def main():
    print("Loading learning_data.json...")
    ld_path = "/app/app/engine/learning_data.json"
    with open(ld_path) as f:
        ld = json.load(f)
    
    print("Fetching existing exp_ids from Qdrant...")
    existing_ids = set()
    try:
        r = httpx.post(f"{QDRANT_URL}/collections/experience/points/scroll",
                       json={"limit": 5000, "with_payload": ["metadata.exp_id"]}, timeout=10)
        for pt in r.json().get("result", {}).get("points", []):
            eid = pt.get("payload", {}).get("metadata", {}).get("exp_id", "")
            if eid:
                existing_ids.add(eid)
    except Exception as e:
        print(f"  Warning: {e}")
    
    print(f"Existing in Qdrant: {len(existing_ids)}")
    ensure_collection("experience")
    
    exps = ld.get("experiences", [])
    indexed = skipped = errors = 0
    
    for i, exp in enumerate(exps):
        title = exp.get("title", "")
        if not title:
            skipped += 1; continue
        exp_id = "iaat-" + hashlib.md5(title.encode()).hexdigest()[:12]
        if exp_id in existing_ids:
            skipped += 1; continue
        
        target_type = exp.get("target_type", "unknown")
        hypothesis = exp.get("hypothesis", "")
        mitigation = exp.get("mitigation", "")
        steps = "\n".join(exp.get("verification_steps", []))
        tools = ", ".join(exp.get("tools", []))
        outcomes = "\n".join(exp.get("expected_outcomes", []))
        
        search_text = f"""Title: {title}
Target: {target_type}
Hypothesis: {hypothesis}
Verification Steps: {steps}
Tools: {tools}
Expected Outcomes: {outcomes}
Mitigation: {mitigation}"""
        
        try:
            vec = embed(search_text)
        except Exception as e:
            print(f"  Embed error [{i+1}/{len(exps)}]: {e}")
            errors += 1; continue
        if not isinstance(vec, list):
            vec = list(vec)
        
        pid = int.from_bytes(hashlib.md5(exp_id.encode()).digest()[:8]) % (2**63)
        
        try:
            upsert("experience", {
                "id": pid,
                "vector": vec,
                "payload": {
                    "text": search_text,
                    "metadata": {
                        "exp_id": exp_id, "title": title,
                        "target_type": target_type,
                        "risk_level": exp.get("risk_level", "medium"),
                        "hypothesis": hypothesis[:300],
                        "tools": tools[:200],
                        "source": "InternalAllTheThings",
                        "timestamp": time.time(),
                    }
                }
            })
            indexed += 1
        except Exception as e:
            print(f"  Upsert error [{i+1}/{len(exps)}]: {e}")
            errors += 1
        
        if indexed % 10 == 0 and indexed > 0:
            print(f"  Progress: {indexed} indexed, {skipped} skipped, {errors} errors")
    
    print(f"\nDone! Indexed: {indexed}, Skipped: {skipped}, Errors: {errors}")
    
    if indexed > 0:
        for exp in exps:
            t = exp.get("title", "")
            if t:
                exp["exp_id"] = "iaat-" + hashlib.md5(t.encode()).hexdigest()[:12]
        with open(ld_path, "w") as f:
            json.dump(ld, f, ensure_ascii=False, indent=2)
        print("Updated learning_data.json with exp_ids")

if __name__ == "__main__":
    main()
