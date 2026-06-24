#!/usr/bin/env python3
"""Remove remaining mock data from OfflineUpdatePage and ToolOverviewPage"""
import re

pages_dir = "/root/yunjing/frontend_nextgen/src/pages"

# ===== 1. OfflineUpdatePage =====
path = pages_dir + "/OfflineUpdatePage.tsx"
with open(path) as f:
    c = f.read()

# Remove the mockData constant entirely
c = re.sub(r"const mockData: UpdateData = \{.*?\};", "", c, flags=re.DOTALL)
# Change useState initializations to empty arrays
c = c.replace(
    "useState<UpdateModule[]>(mockData.modules)",
    "useState<UpdateModule[]>([])"
)
c = c.replace(
    "useState<UpdateLog[]>(mockData.logs)",
    "useState<UpdateLog[]>([])"
)
c = c.replace(
    "mockData.lastGlobalCheck",
    '""'
)
c = c.replace(
    "res.data.modules ?? mockData.modules",
    "res.data.modules ?? []"
)
c = c.replace(
    "res.data.logs ?? mockData.logs",
    "res.data.logs ?? []"
)
c = c.replace(
    "res.data.lastGlobalCheck ?? mockData.lastGlobalCheck",
    'res.data.lastGlobalCheck ?? ""'
)
c = c.replace(
    "setModules(mockData.modules);\n      setLogs(mockData.logs);",
    'message.warning("加载更新状态失败");'
)

with open(path, 'w') as f:
    f.write(c)
print("OfflineUpdatePage DONE")

# ===== 2. ToolOverviewPage - remove mockData constant =====
path = pages_dir + "/ToolOverviewPage.tsx"
with open(path) as f:
    c = f.read()

# Remove the mockData constant
c = re.sub(r"const mockData: ToolItem\[\] = \[.*?\];", "", c, flags=re.DOTALL)

with open(path, 'w') as f:
    f.write(c)
print("ToolOverviewPage DONE")

# ===== 3. Verify no more MOCK references =====
import subprocess
result = subprocess.run(
    ["grep", "-rn", "MOCK_\|mockData\|mock_data", pages_dir],
    capture_output=True, text=True, timeout=5
)
if result.stdout:
    print(f"\nRemaining mock references:\n{result.stdout}")
else:
    print("\nNo more mock references found!")
