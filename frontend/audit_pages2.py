#!/usr/bin/env python3
"""Audit all pages for mock data vs real API usage"""
import os, re

pages_dir = "/root/yunjing/frontend_nextgen/src/pages"
files = sorted(os.listdir(pages_dir))
tsx_files = [f for f in files if f.endswith(".tsx")]

for fname in tsx_files:
    path = os.path.join(pages_dir, fname)
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
    except:
        print(f"❌ Cannot read {fname}")
        continue
    
    # Check for API calls
    api_calls = re.findall(r'request\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)', content)
    
    # Check for mock data
    mock_vars = set(re.findall(r'(?:MOCK_\w+|mock_\w+|mockData|MOCK_DATA)', content))
    mock_comments = re.findall(r'//.*(?:Mock|mock|模拟|兜底|假数据)', content)
    
    # Check if the page has useEffect with API calls
    has_use_effect = 'useEffect' in content
    has_try_catch = 'catch' in content
    
    # Determine mock dependency level
    if not api_calls:
        status = "🟥 NO API"
    elif mock_vars:
        # Check if it falls back to mock on error
        has_mock_fallback = any('catch' in c for c in content.split('\n') if 'mock' in c.lower() or 'MOCK' in c or 'Mock' in c)
        if has_mock_fallback:
            status = "🟡 API+Mock fallback"
        else:
            status = "🟢 Real API"
    else:
        status = "🟢 Real API"
    
    print(f"\n{'='*60}")
    print(f"{status}  {fname}")
    print(f"{'='*60}")
    
    for method, url in api_calls:
        print(f"  📡 {method.upper()} {url}")
    
    if mock_vars:
        print(f"  🔵 Mock data: {', '.join(sorted(mock_vars))}")
    
    if mock_comments:
        print(f"  💬 Mock comments: {mock_comments}")
