#!/usr/bin/env python3
"""手动触发 scan_callback 测试分析推送"""
import httpx, asyncio

async def main():
    async with httpx.AsyncClient(timeout=30) as c:
        # 触发 callback
        r = await c.post("http://backend:8000/api/engine/scan-callback", json={
            "task_id": "58a5d12c-6c9c-4c16-9969-3af8fed7856d",
            "target": "192.168.1.180:8080",
            "scan_type": "full",
            "status": "completed",
            "findings": []
        })
        print(f"Callback: {r.status_code}")
        print(f"Response: {r.text[:200]}")

asyncio.run(main())
