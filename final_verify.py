#!/usr/bin/env python3
"""验证所有修复"""
import os, glob

print("=" * 50)
print("云镜项目修复验证报告")
print("=" * 50)

# 1. 验证 P0 安全修复
print("\n## P0 安全修复")
with open("/root/yunjing/backend/app/config.py") as f:
    c = f.read()
print(f"  DEBUG=False: {'DEBUG: bool = False' in c}")
print(f"  JWT无硬编码: {'JWT_SECRET: str = \"\"' in c}")
print(f"  CORS受限:   {'http://127.0.0.1' in c}")
print(f"  JWT过期4h:  {'JWT_EXPIRE_HOURS: int = 4' in c}")
print(f"  DB_URL动态: {'DATABASE_URL: str = \"\"' in c}")

# 2. 验证 docker-compose
with open("/root/yunjing/docker-compose.yml") as f:
    c = f.read()
print(f"  nginx无docker.sock: {'nginx' in c and '/var/run/docker.sock' not in c.split('nginx:')[1].split('depends_on')[0] if 'nginx:' in c else 'N/A'}")

# 3. 验证 main.py
with open("/root/yunjing/backend/app/main.py") as f:
    c = f.read()
print(f"  管理员密码动态: {'DEFAULT_ADMIN_PASSWORD' in c}")

# 4. 验证 agent
with open("/root/yunjing/agent/app/agent_main.py") as f:
    c = f.read()
print(f"  Agent密码动态: {'AGENT_BACKEND_PASSWORD' in c}")

# 5. 验证 .env
print(f"  .env存在: {os.path.exists('/root/yunjing/.env')}")
print(f"  .gitignore存在: {os.path.exists('/root/yunjing/.gitignore')}")

# 6. 检查残留fix脚本
fix_scripts = glob.glob("/root/yunjing/fix_*.py") + glob.glob("/root/yunjing/verify*.py") + glob.glob("/root/yunjing/check*.py")
if fix_scripts:
    print(f"\n  残留修复脚本({len(fix_scripts)}个): 待清理")
    for s in fix_scripts:
        print(f"    {os.path.basename(s)}")

print("\n✅ 验证完成")
