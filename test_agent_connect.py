#!/usr/bin/env python3
"""从 Agent 容器内部测试后端登录和技能加载"""
import httpx, asyncio, os

async def main():
    pw = os.getenv("AGENT_BACKEND_PASSWORD", "yunjing123")
    async with httpx.AsyncClient(timeout=10) as c:
        # Login
        r = await c.post("http://backend:8000/api/auth/login", json={"username": "admin", "password": pw})
        print(f"Login: {r.status_code}")
        if r.status_code == 200:
            token = r.json()["access_token"]
            # Fetch skills
            r2 = await c.get("http://backend:8000/api/skills/", headers={"Authorization": f"Bearer {token}"})
            print(f"Skills: {r2.status_code} {r2.text[:200]}")
        else:
            print(f"Failed: {r.text[:200]}")

asyncio.run(main())
