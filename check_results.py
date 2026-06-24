#!/usr/bin/env python3
"""完整渗透测试 - DVWA"""
import httpx, asyncio

async def main():
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post("http://backend:8000/api/auth/login", json={"username": "admin", "password": "yunjing123"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 先检查已有的任务结果
        r = await c.get("http://backend:8000/api/tasks/", headers=headers)
        for t in r.json()[-3:]:
            print(f"已有任务: {t['target']} -> {t['status']}")
            if t.get("result"):
                res = t["result"]
                if isinstance(res, str):
                    res = res[:100]
                print(f"  结果: {res}")

asyncio.run(main())
