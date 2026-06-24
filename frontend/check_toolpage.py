#!/usr/bin/env python3
"""Check ToolOverviewPage for issues"""
import re

path = "/root/yunjing/frontend_nextgen/src/pages/ToolOverviewPage.tsx"

with open(path) as f:
    c = f.read()
    lines = c.split('\n')

print(f"Total lines: {len(lines)}")

# Check for mockData references
for i, line in enumerate(lines, 1):
    if 'mockData' in line:
        print(f"  LINE {i}: {line}")

# Check component definition
for i, line in enumerate(lines, 1):
    if 'React.FC' in line or 'export default function ToolOverviewPage' in line or 'export default ToolOverviewPage' in line:
        print(f"  COMPONENT at line {i}: {line}")

# Check if the Provider wrapping is an issue
# The ToolOverviewPage is rendered in a Card, so check the full return JSX
in_return = False
return_start = 0
for i, line in enumerate(lines, 1):
    if 'return (' in line and i > 100:
        return_start = i
        break

print(f"\nReturn starts at line {return_start}")

# Check for common issues: antd icon usage, missing imports
imports = [l for l in lines if l.startswith('import ') or l.startswith('import type')]
print(f"\nTotal imports: {len(imports)}")

# Check for undefined references
# Look for any remaining issues with the regex removal
# The mock data was removed with re.sub, check if the replacement was clean
mock_idx = c.find('const mockData')
if mock_idx >= 0:
    print(f"\nWARNING: mockData still present at char {mock_idx}")
    print(f"  Context: {c[mock_idx:mock_idx+80]}")
else:
    print("\nOK: mockData fully removed")

# Check for the re.sub artifact
# If the regex didn't match, the original text remains. Let me check what's around line 56 (where mockData was)
if len(lines) > 50:
    print(f"\nLines 50-70:")
    for i in range(50, min(70, len(lines))):
        print(f"  {i+1}: {lines[i]}")
