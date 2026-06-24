#!/usr/bin/env python3
"""Check ToolOverviewPage for runtime issues"""
import re

path = "/root/yunjing/frontend_nextgen/src/pages/ToolOverviewPage.tsx"

with open(path) as f:
    c = f.read()

# Check for bodyStyle (deprecated in Antd 5)
print(f"bodyStyle count: {c.count('bodyStyle')}")

# Check fetchTools block
idx = c.find('const fetchTools')
print(f"\n--- fetchTools ---\n{c[idx:idx+350]}")

# Check the render return
ridx = c.find('return (')
print(f"\n--- Return starts at char {ridx} ---")
print(c[ridx:ridx+200])

# Check the full JSX for any issues
# BodyStyle was deprecated - let's see if we need to use styles instead
if c.count('bodyStyle') > 0:
    print("\nWARNING: bodyStyle is deprecated in AntD 5. This may cause warnings but not crashes.")
