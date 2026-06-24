#!/usr/bin/env python3
"""Test BGE batch performance from inside container."""
import urllib.request, json, time

BGE_URL = "http://yunjing-bge:8000/embed_batch"

for i in range(10):
    t = time.time()
    data = json.dumps({"texts": ["Test embedding performance batch " + str(i) for _ in range(16)], "normalize": True}).encode()
    req = urllib.request.Request(BGE_URL, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        r = json.loads(resp.read())
    elapsed = time.time() - t
    print(f"Batch {i+1}/10: {len(r.get('vectors',[]))} vecs in {elapsed:.1f}s", flush=True)
print("Done!", flush=True)
