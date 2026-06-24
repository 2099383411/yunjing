#!/usr/bin/env python3
"""
Merge HackTricks experiences (1033 entries) into existing learning_data.json (662 entries),
deduplicate by title, and index all to Qdrant.
"""
import json, sys, time, urllib.request, urllib.parse

LEARNING_FILE = "/root/yunjing/backend/app/engine/learning_data.json"
NEW_FILE = "/root/yunjing/backend/experience_hacktricks.json"
OUTPUT_FILE = LEARNING_FILE

def call_bge(texts, endpoint="http://172.18.0.13:8000/embed"):
    """Batch embedding via BGE service."""
    data = json.dumps({"texts": texts, "normalize": True}).encode('utf-8')
    req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"  [BGE Error] {e}")
        return None

def main():
    print("=" * 60)
    print("STEP 1: Merge experiences")
    print("=" * 60)
    
    # Load existing
    with open(LEARNING_FILE) as f:
        existing_doc = json.load(f)
    
    # The experiences are in the 'experiences' key
    if isinstance(existing_doc, dict) and 'experiences' in existing_doc:
        existing = existing_doc['experiences']
        top_level = existing_doc
    elif isinstance(existing_doc, list):
        existing = existing_doc
        top_level = None
    else:
        existing = existing_doc
        top_level = None
    print(f"Existing: {len(existing)} entries (in 'experiences' key)" if top_level else f"Existing: {len(existing)} entries")
    
    # Load new
    with open(NEW_FILE) as f:
        new_data = json.load(f)
    print(f"New: {len(new_data)} entries")
    
    # Deduplicate by title
    existing_titles = {e.get("title", ""): i for i, e in enumerate(existing)}
    merged = list(existing)
    added = 0
    for e in new_data:
        title = e.get("title", "")
        if title and title not in existing_titles:
            merged.append(e)
            existing_titles[title] = len(merged) - 1
            added += 1
    
    print(f"Merged: {len(merged)} (+{added} new)")
    
    # Save merged (preserve top-level structure)
    if top_level:
        top_level['experiences'] = merged
        top_level['meta']['total_experiences'] = len(merged)
        top_level['meta']['last_updated'] = '2026-06-09'
        save_data = top_level
    else:
        save_data = merged
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(save_data, f, ensure_ascii=False, indent=2)
    print(f"Saved to {OUTPUT_FILE} ({len(merged)} experiences)")
    
    # Statistics
    cats = {}
    for e in merged:
        t = e.get("target_type", "unknown")
        cats[t] = cats.get(t, 0) + 1
    print(f"\nTarget type distribution ({len(cats)} types):")
    for c, n in sorted(cats.items(), key=lambda x: -x[1])[:15]:
        print(f"  {c}: {n}")
    
    print("\n" + "=" * 60)
    print("STEP 2: Index to Qdrant")
    print("=" * 60)
    
    # Prepare experience texts for embedding
    exp_texts = []
    exp_ids = []
    for i, e in enumerate(merged):
        text = f"{e.get('title','')}. {e.get('hypothesis','')} {e.get('verification_steps','')} {e.get('expected_outcomes','')}"
        exp_texts.append(text)
        exp_ids.append(f"exp_{i+1}")
    
    # Batch embed
    BATCH_SIZE = 16
    all_vectors = []
    
    for i in range(0, len(exp_texts), BATCH_SIZE):
        batch = exp_texts[i:i+BATCH_SIZE]
        result = call_bge(batch)
        if result and 'embeddings' in result:
            all_vectors.extend(result['embeddings'])
        else:
            print(f"  [ERROR] Batch {i//BATCH_SIZE + 1} failed")
            sys.exit(1)
        
        if (i + BATCH_SIZE) % 64 == 0:
            print(f"  Embedded {min(i+BATCH_SIZE, len(exp_texts))}/{len(exp_texts)}")
    
    print(f"  Embedded {len(all_vectors)} vectors")
    
    # Index to Qdrant
    qdrant_url = "http://localhost:6333"
    
    # Upsert points
    points = []
    for i, (exp_id, exp, vec) in enumerate(zip(exp_ids, merged, all_vectors)):
        points.append({
            "id": i + 1,
            "vector": vec,
            "payload": {
                "exp_id": exp_id,
                "title": exp.get("title", ""),
                "target_type": exp.get("target_type", ""),
                "hypothesis": exp.get("hypothesis", ""),
                "verification_steps": json.dumps(exp.get("verification_steps", [])),
                "tools": json.dumps(exp.get("tools", [])),
                "expected_outcomes": json.dumps(exp.get("expected_outcomes", [])),
                "risk_level": exp.get("risk_level", "medium"),
                "mitigation": exp.get("mitigation", ""),
                "source": "hacktricks",
                "category": exp.get("target_type", "")
            }
        })
    
    # Index in batches of 100
    for i in range(0, len(points), 100):
        batch = points[i:i+100]
        data = json.dumps({"points": batch}).encode('utf-8')
        params = urllib.parse.urlencode({"wait": "true"})
        url = f"{qdrant_url}/collections/experience/points?{params}"
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        req.method = 'PUT'
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                result = json.loads(resp.read().decode('utf-8'))
                if result.get("status") != "ok":
                    print(f"  [WARN] Batch {i//100 + 1}: {result}")
                else:
                    print(f"  Indexed batch {i//100 + 1} ({i+len(batch)}/{len(points)})")
        except Exception as e:
            print(f"  [ERROR] Batch {i//100 + 1}: {e}")
            sys.exit(1)
    
    print(f"\n{'='*50}")
    print(f"✅ Done! {len(points)} experiences indexed to Qdrant")
    
    # Verify
    from urllib.request import urlopen
    resp = json.loads(urlopen(f"{qdrant_url}/collections/experience", timeout=10).read().decode())
    count = resp.get("result", {}).get("vectors_count", 0)
    print(f"Qdrant collection 'experience': {count} vectors")

if __name__ == "__main__":
    main()
