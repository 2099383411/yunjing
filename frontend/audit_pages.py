#!/usr/bin/env python3
"""Audit all pages for mock data vs real API usage"""
import os, re

pages_dir = "/root/yunjing/frontend_nextgen/src/pages"
api_dir = "/root/yunjing/frontend_nextgen/src/api"

files = sorted(os.listdir(pages_dir))
tsx_files = [f for f in files if f.endswith(".tsx")]

for fname in tsx_files:
    path = os.path.join(pages_dir, fname)
    with open(path) as f:
        content = f.read()
    
    # Check for API calls
    api_calls = re.findall(r'request\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)', content)
    
    # Check for mock data
    mock_vars = re.findall(r'(MOCK_\w+|mock_\w+|mockData|MOCK_DATA)', content)
    mock_comments = re.findall(r'//.*(?:Mock|mock|模拟|兜底|假数据)', content)
    
    # Check for catch blocks with mock fallback
    catch_mocks = content.count("catch") 
    
    status = "✅" if len(api_calls) > 0 else "❌ NO API"
    mock_info = ""
    if mock_vars:
        unique_mocks = list(set(mock_vars))
        mock_info = f" Mock vars: {unique_mocks}"
    if mock_comments:
        mock_info += f" Comments: {mock_comments[:3]}"
    
    print(f"{status} {fname}")
    for method, url in api_calls:
        print(f"    API: {method} {url}")
    if mock_vars:
        print(f"    MOCK: {list(set(mock_vars))}")
    print()
