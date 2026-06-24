#!/usr/bin/env python3
"""Find and show AttackNode component"""
with open("/root/yunjing/frontend_nextgen/src/pages/OrchestrationPage.tsx") as f:
    c = f.read()

idx = c.find("const AttackNode")
if idx < 0:
    idx = c.find("function AttackNode")
if idx < 0:
    idx = c.find("AttackNode")
    
if idx >= 0:
    print(f"AttackNode at {idx}")
    print(c[idx:idx+2000])
