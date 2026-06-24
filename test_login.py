#!/usr/bin/env python3
"""测试 admin 登录"""
import httpx, asyncio, asyncpg
from passlib.hash import bcrypt

async def main():
    # 1. 从数据库获取 hash
    conn = await asyncpg.connect(
        user="yunjing", password="RuYaBmIFiGYq",
        database="yunjing", host="postgres", port=5432
    )
    row = await conn.fetchrow("SELECT password_hash FROM users WHERE username=$1", "admin")
    pw_hash = row[0]
    print(f"Hash: {pw_hash}")
    print(f"Verify 123: {bcrypt.verify('yunjing123', pw_hash)}")
    await conn.close()

    # 2. 测试 API 登录
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "http://backend:8000/api/auth/login",
            json={"username": "admin", "password": "yunjing123"}
        )
        print(f"API login: {r.status_code} {r.text[:100]}")

asyncio.run(main())
