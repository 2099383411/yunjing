#!/usr/bin/env python3
"""检查 agent_main.py 中密码相关行"""
with open("/root/yunjing/agent/app/agent_main.py", "r") as f:
    lines = f.readlines()
for i, line in enumerate(lines, 1):
    if "password" in line.lower() or "AGENT" in line or "login" in line.lower():
        print(f"L{i}: {line.rstrip()}")
