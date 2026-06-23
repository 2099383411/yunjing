#!/usr/bin/env python3
"""Fast embedding: run inside BGE container, process all 1695 texts in batches of 16."""
import json, urllib.request, time, sys

BGE_URL = "http://localhost:8000/embed_batch"
BATCH_SIZE = 16

def main():
    with open("/app/exp_texts.json") as f:
        texts = json.load(f)
    
    total = len(texts)
    all_vecs = []
    
    print(f"Starting embedding {total} texts, batch={BATCH_SIZE}", flush=True)
    
    for i in range(0, total, BATCH_SIZE):
        batch = texts[i:i+BATCH_SIZE]
        t0 = time.time()
        
        for retry in range(3):
            try:
                data = json.dumps({"texts": batch, "normalize": True}).encode()
                req = urllib.request.Request(BGE_URL, data=data, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=300) as resp:
                    result = json.loads(resp.read())
                vecs = result.get("vectors", [])
                break
            except Exception as e:
                if retry < 2:
                    print(f"  [RETRY {retry+1}] batch {i//BATCH_SIZE+1}: {e}", flush=True)
                    time.sleep(5)
                    continue
                print(f"  [FAIL] batch {i//BATCH_SIZE+1}: {e}", flush=True)
                return
        
        all_vecs.extend(vecs)
        dt = time.time() - t0
        
        if (i + BATCH_SIZE) % 64 == 0 or i + BATCH_SIZE >= total:
            print(f"  [{i//BATCH_SIZE+1}/{total//BATCH_SIZE+1}] {min(i+BATCH_SIZE,total)}/{total} ({dt:.1f}s, {len(all_vecs)} total)", flush=True)
    
    print(f"Done! {len(all_vecs)} vectors, dim={len(all_vecs[0])}", flush=True)
    
    with open("/app/exp_vectors.json", "w") as f:
        json.dump({"vectors": all_vecs, "count": len(all_vecs), "dim": len(all_vecs[0])}, f)
    print("Saved to /app/exp_vectors.json", flush=True)

if __name__ == "__main__":
    main()
