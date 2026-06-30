import os
"""云镜·安全检测助手 主入口"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
from app.config import settings
from app.api import auth, chat, tasks, reports, settings_api, users
from app.api import ws, audit, system_info, tools_status, dashboard, engine_api
from app.api import analyst, report_download
from app.api import notifications

# ── Seed default role/permissions on startup ──────────────────────────────
async def seed_rbac():
    from app.database import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.role import Role, Permission, RolePermission, SEED_PERMISSIONS, SEED_ROLES
    from app.models.user import User
    from passlib.hash import bcrypt
    import uuid

    async with AsyncSessionLocal() as sess:
        # 1. Seed permissions
        existing_perms = (await sess.execute(select(Permission.resource, Permission.action))).all()
        existing_set = {(r, a) for r, a in existing_perms}
        for res, act, desc in SEED_PERMISSIONS:
            if (res, act) not in existing_set:
                sess.add(Permission(id=str(uuid.uuid4()), resource=res, action=act, description=desc))

        # 2. Seed roles
        for rname, rdesc, rsystem in SEED_ROLES:
            role = (await sess.execute(select(Role).where(Role.name == rname))).scalar_one_or_none()
            if not role:
                role = Role(id=str(uuid.uuid4()), name=rname, description=rdesc, is_system=rsystem)
                sess.add(role)
                await sess.flush()

                # Grant all permissions to 超级管理员
                if rname == "超级管理员":
                    all_perms = (await sess.execute(select(Permission))).scalars().all()
                    for p in all_perms:
                        sess.add(RolePermission(role_id=role.id, permission_id=p.id))

        # 3. Ensure admin user exists
        admin = (await sess.execute(select(User).where(User.username == "admin"))).scalar_one_or_none()
        if not admin:
            admin = User(
                id=str(uuid.uuid4()), username="admin",
                password_hash=bcrypt.hash(os.getenv("DEFAULT_ADMIN_PASSWORD", "yunjing123_change_me")),
                display_name="超级管理员",
            )
            sess.add(admin)
            await sess.flush()
            # Assign 超级管理员 role
            super_role = (await sess.execute(select(Role).where(Role.name == "超级管理员"))).scalar_one_or_none()
            if super_role:
                from app.models.role import user_roles
                await sess.execute(user_roles.insert().values(user_id=admin.id, role_id=super_role.id))

        await sess.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await seed_rbac()
    # 启动时同步内置技能到数据库
    try:
        from app.api.skills import sync_builtin_skills
        await sync_builtin_skills()
    except Exception as e:
        import logging
        logging.warning(f"技能同步失败: {e}")
    yield


app = FastAPI(
    title="云镜·安全检测助手",
    description="AI 驱动的自动化渗透测试智能体",
    version="0.2.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 尾部斜杠兼容中间件 ──────────────────────────────────────────
@app.middleware("http")
async def trailing_slash_middleware(request, call_next):
    import re
    path = request.url.path
    # 如果路径不带尾斜杠且对应路由只有带尾斜杠版本，自动重定向
    if not path.endswith("/") and not path.startswith("/api/ws"):
        slash_prefixes = ("/api/tasks", "/api/reports", "/api/engine")
        for prefix in slash_prefixes:
            if path == prefix:
                new_path = path + "/"
                if str(request.url.query):
                    new_path += "?" + str(request.url.query)
                return RedirectResponse(url=new_path, status_code=307)
    response = await call_next(request)
    return response


# ── Routers ───────────────────────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/auth", tags=["认证"])
app.include_router(chat.router, prefix="/api/chat", tags=["对话"])
app.include_router(tasks.router, prefix="/api/tasks", tags=["任务"])
app.include_router(reports.router, prefix="/api/reports", tags=["报告"])
app.include_router(settings_api.router, prefix="/api/settings", tags=["配置"])
app.include_router(users.router, prefix="/api/users", tags=["用户管理"])
app.include_router(ws.router, prefix="/api", tags=["WebSocket"])
app.include_router(audit.router, prefix="/api/audit", tags=["审计日志"])
app.include_router(system_info.router, prefix="/api/system", tags=["系统信息"])
app.include_router(tools_status.router, prefix="/api/tools", tags=["工具状态"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["仪表盘"])
app.include_router(notifications.router, prefix="/api/notifications", tags=["通知"])

# 引擎数据展示
app.include_router(engine_api.router, prefix="/api/engine", tags=["引擎"])
app.include_router(analyst.router, prefix="/api", tags=["AI分析"])
app.include_router(report_download.router, prefix="/api", tags=["报告下载"])


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": app.version}
