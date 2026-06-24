#!/usr/bin/env python3
"""启动 DVWA 渗透测试 + 全程监控 + 报告验证"""
import httpx, asyncio, json, sys, time
from datetime import datetime

BASE = "http://backend:8000/api"

async def watch_logs(container, label, interval=3):
    """持续拉取容器日志"""
    import subprocess
    last_len = 0
    while True:
        await asyncio.sleep(interval)
        try:
            r = subprocess.run(
                ["docker", "logs", container, "--tail", "5"],
                capture_output=True, text=True, timeout=5
            )
            output = r.stdout.strip()
            if output and len(output) != last_len:
                last_len = len(output)
                # 只输出错误级别日志
                for line in output.split("\n"):
                    if any(k in line.lower() for k in ["error", "traceback", "exception", "typeerror", "500", "fail", "crash"]):
                        print(f"  🚨 [{label}] {line.strip()}")
        except:
            pass

async def main():
    start = time.time()
    print(f"\n{'='*60}")
    print(f"🚀 云镜 DVWA 渗透测试 - {datetime.now()}")
    print(f"{'='*60}\n")

    async with httpx.AsyncClient(timeout=30) as c:
        # 登录
        r = await c.post(f"{BASE}/auth/login", json={"username": "admin", "password": "yunjing123"})
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}
        print(f"✅ 登录成功 (Token: {token[:16]}...)")

        # 启动后台日志监控
        print(f"\n📋 启动日志监控 (全程跟踪)...")

        # 创建全量扫描任务
        print(f"\n🎯 目标: DVWA (192.168.1.180:8080)")
        print(f"📡 扫描类型: full (全端口 + 漏洞扫描 + Web检测 + 利用验证)")
        
        r = await c.post(f"{BASE}/tasks/", headers=h, json={
            "targets": ["192.168.1.180:8080"],
            "scan_type": "full",
            "tools": ["nmap", "nuclei", "gobuster", "nikto", "sqlmap", "hydra"]
        })
        task_data = r.json()
        task_ids = []
        for t in task_data.get("task_ids", []):
            if isinstance(t, dict):
                task_ids.append(t.get("task_id", ""))
            elif isinstance(t, str):
                task_ids.append(t)
        print(f"📌 任务ID: {task_ids}\n")

        # 轮询监控
        last_status = {}
        for i in range(200):  # 最多 ~16 分钟
            await asyncio.sleep(5)
            all_done = True
            for tid in task_ids:
                try:
                    r = await c.get(f"{BASE}/tasks/{tid}", headers=h)
                    task = r.json()
                    s = task.get("status", "?")
                    p = task.get("progress", 0)
                    ts = task.get("target", "?")
                    e = task.get("error", "")

                    if tid not in last_status or last_status[tid] != s:
                        last_status[tid] = s
                        t_elapsed = time.time() - start
                        print(f"  [{int(t_elapsed)}s] TASK {tid[:10]}... | {ts} | {s} | 进度 {p}%")
                        if e:
                            print(f"    ⚠️  错误: {e[:150]}")

                    if str(s).upper() not in ("COMPLETED", "FAILED", "SUCCESS", "CANCELLED"):
                        all_done = False

                    # 完成时输出详细结果
                    if str(s).upper() in ("COMPLETED", "SUCCESS") and (tid not in last_status or last_status.get(tid+"_result") != "done"):
                        last_status[tid+"_result"] = "done"
                        result = task.get("result", {})
                        if isinstance(result, str):
                            try: result = json.loads(result)
                            except: pass
                        if isinstance(result, dict):
                            print(f"\n  📊 任务完成 - {ts}")
                            print(f"     发现总数: {result.get('findings_count', result.get('total', '?'))}")
                            vulns = result.get("vulnerability_names", []) or result.get("findings", [])
                            if vulns:
                                print(f"     漏洞列表 ({len(vulns)} 项):")
                                for v in vulns[:15]:
                                    if isinstance(v, dict):
                                        print(f"       - {v.get('title','?')} [{v.get('severity','?')}]")
                                    else:
                                        print(f"       - {str(v)[:100]}")
                            sessions = result.get("sessions", [])
                            if sessions:
                                print(f"     已建立会话 ({len(sessions)} 个):")
                                for s in sessions:
                                    print(f"       - {s.get('type','?')}: {s.get('url','') or s.get('hostname','')} ({s.get('credential','')})")

                except Exception as e:
                    print(f"  ⚠️  查询异常: {e}")

            if all_done:
                break

        # 检查报告生成
        elapsed = time.time() - start
        print(f"\n{'='*60}")
        print(f"⏱️  总耗时: {elapsed:.0f}s")
        print(f"{'='*60}")

        # 获取报告列表
        r = await c.get(f"{BASE}/reports/", headers=h)
        reports = r.json()
        print(f"\n📄 已有报告: {len(reports)} 份")
        for rep in (reports if isinstance(reports, list) else reports.get("items", []))[-3:]:
            rid = rep.get("id", rep.get("task_id", "?"))
            print(f"   - {rid[:20]}... | {rep.get('status','?')}")

asyncio.run(main())
