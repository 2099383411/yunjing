#!/usr/bin/env python3
"""通过云镜 API 启动对 DVWA 的渗透测试"""
import httpx, asyncio, json, time

BASE = "http://backend:8000/api"

async def main():
    async with httpx.AsyncClient(timeout=30) as c:
        # 1. 登录
        r = await c.post(f"{BASE}/auth/login", json={"username": "admin", "password": "yunjing123"})
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"✅ 登录成功，Token: {token[:20]}...")

        # 2. 获取当前任务列表
        r = await c.get(f"{BASE}/tasks/", headers=headers)
        tasks = r.json()
        print(f"📋 已有任务: {len(tasks)}")

        # 3. 创建新扫描任务 - 目标 DVWA 192.168.1.180:8080
        print("\n🚀 启动对 DVWA (192.168.1.180:8080) 的渗透测试...")
        r = await c.post(f"{BASE}/tasks/", headers=headers, json={
            "targets": ["192.168.1.180:8080"],
            "scan_type": "web",
            "tools": ["nmap", "nuclei", "gobuster", "nikto"]
        })
        tasks_created = r.json().get("task_ids", [])
        print(f"📌 创建的任务: {tasks_created}")

        # 提取 task_id
        task_ids = []
        for t in tasks_created:
            if isinstance(t, dict):
                task_ids.append(t.get("task_id", ""))
            else:
                task_ids.append(t)
        task_ids = [t for t in task_ids if t]

        # 4. 轮询任务状态
        for task_id in task_ids:
            for i in range(60):
                await asyncio.sleep(5)
                try:
                    r = await c.get(f"{BASE}/tasks/{task_id}", headers=headers)
                    task = r.json()
                    status = task.get("status", "unknown")
                    progress = task.get("progress", 0)
                    tid_short = task_id[:12] if len(task_id) > 12 else task_id
                    print(f"  [{i*5}s] {tid_short} 状态: {status} 进度: {progress}")
                    if str(status).upper() in ("COMPLETED", "FAILED", "CANCELLED", "SUCCESS"):
                        print(f"\n📊 任务完成! 结果:")
                        result = task.get("result", {})
                        if isinstance(result, dict):
                            findings = result.get("findings", [])
                            print(f"   发现 {len(findings)} 项")
                            for f in findings[:5]:
                                print(f"   - {f.get('title', 'N/A')} [{f.get('severity', 'N/A')}]")
                        if task.get("error"):
                            print(f"   错误: {task['error'][:200]}")
                        break
                except Exception as e:
                    print(f"  [{i*5}s] 查询失败: {e}")
                    continue

asyncio.run(main())
