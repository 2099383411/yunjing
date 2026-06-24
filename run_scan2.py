#!/usr/bin/env python3
"""简单触发扫描任务并监控"""
import httpx, asyncio

async def main():
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post("http://backend:8000/api/auth/login", json={"username": "admin", "password": "yunjing123"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("✅ 登录成功")

        # 创建任务
        r = await c.post("http://backend:8000/api/tasks/", headers=headers, json={
            "targets": ["192.168.1.180:8080"],
            "scan_type": "quick",
            "tools": ["nmap", "nuclei"]
        })
        tasks = r.json()
        task_ids = []
        for t in tasks.get("task_ids", []):
            if isinstance(t, dict):
                task_ids.append(t["task_id"])
            else:
                task_ids.append(t)
        print(f"📌 任务: {task_ids}")

        # 监控前 2 分钟
        for i in range(24):
            await asyncio.sleep(5)
            for tid in task_ids:
                r = await c.get(f"http://backend:8000/api/tasks/{tid}", headers=headers)
                task = r.json()
                print(f"  [{i*5}s] {tid[:12]} 状态: {task.get('status')} 进度: {task.get('progress')}")
                if str(task.get("status", "")).upper() in ("COMPLETED", "FAILED", "SUCCESS"):
                    print(f"  ✅ 完成! 结果: {str(task.get('result', ''))[:200]}")
                    return
        print("⏰ 监控超时，手动检查")
        for tid in task_ids:
            r = await c.get(f"http://backend:8000/api/tasks/{tid}", headers=headers)
            print(f"  {tid[:12]}: {r.json().get('status')}")

asyncio.run(main())
