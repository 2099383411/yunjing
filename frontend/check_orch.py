#!/usr/bin/env python3
"""Check OrchestrationPage for node styling"""
with open("/root/yunjing/frontend_nextgen/src/pages/OrchestrationPage.tsx") as f:
    c = f.read()

idx = c.find("<ReactFlow")
if idx > 0:
    start = max(0, idx - 30)
    print("=== ReactFlow component ===")
    print(c[start:idx+600])

idx2 = c.find("nodeTypes")
if idx2 > 0:
    print("\n=== nodeTypes ===")
    print(c[idx2:idx2+300])

for keyword in ["CustomNode", "customNode", "nodeTypes = {", "nodeTypes={"]:
    i = c.find(keyword)
    if i > 0:
        print(f"\n=== {keyword} at {i} ===")
        print(c[i:i+400])
