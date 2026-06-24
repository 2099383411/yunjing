#!/usr/bin/env python3
"""修复 admin 用户密码"""
import asyncpg, asyncio
from passlib.hash import bcrypt

async def main():
    conn = await asyncpg.connect(
        user="yunjing", password="RuYaBmIFiGYq",
        database="yunjing", host="postgres", port=5432
    )
    new_hash = bcrypt.hash("yunjing123")
    await conn.execute("UPDATE users SET password_hash=$1 WHERE username=$2", new_hash, "admin")
    print(f"Admin password updated to yunjing123")
    print(f"New hash: {new_hash}")
    await conn.close()

asyncio.run(main())
