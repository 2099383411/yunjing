#!/usr/bin/env python3
"""测试 load_skills 函数 - 模拟 Agent 启动流程"""
import httpx, asyncio, os

BACKEND_URL = "http://backend:8000"

async def load_skills():
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Login with retries
            token = None
            for attempt in range(5):
                login_resp = await client.post(
                    f"{BACKEND_URL}/api/auth/login",
                    json={"username": "admin", "password": os.getenv("AGENT_BACKEND_PASSWORD", "yunjing123")},
                )
                if login_resp.status_code == 200:
                    token = login_resp.json().get("access_token", "")
                    print(f"Login OK on attempt {attempt+1}")
                    break
                print(f"Login attempt {attempt+1}: {login_resp.status_code}")
                await asyncio.sleep(2)

            if not token:
                print("Login failed after 5 retries")
                return

            # Fetch skills
            skills_resp = await client.get(
                f"{BACKEND_URL}/api/skills/",
                headers={"Authorization": f"Bearer {token}"},
            )
            if skills_resp.status_code == 200:
                data = skills_resp.json()
                skills = data.get("skills", [])
                print(f"Skills loaded: {len(skills)}")
                if skills:
                    print(f"First skill: {skills[0].get('name')}")
            else:
                print(f"Skills fetch failed: {skills_resp.status_code} {skills_resp.text[:100]}")

    except Exception as e:
        print(f"Error: {e}")

asyncio.run(load_skills())
