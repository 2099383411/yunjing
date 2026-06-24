"""FastAPI 依赖注入：JWT 认证 + RBAC"""
from jose import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)
ALGORITHM = "HS256"


def create_access_token(user_id: str, role: str = "analyst") -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)
    payload = {"sub": user_id, "role": role, "exp": expire}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User | None:
    if not credentials:
        if settings.AUTH_ENABLED:
            raise HTTPException(status_code=401, detail="未登录")
        return None
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[ALGORITHM])
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        async with AsyncSessionLocal() as sess:
            result = await sess.execute(select(User).where(User.id == payload["sub"]))
            user = result.scalar_one_or_none()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="用户不存在或已禁用")
            return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token 已过期")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="无效 Token")


async def optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User | None:
    if not credentials:
        return None
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET, algorithms=[ALGORITHM])
        async with AsyncSessionLocal() as sess:
            result = await sess.execute(select(User).where(User.id == payload["sub"]))
            return result.scalar_one_or_none()
    except Exception:
        return None


async def require_admin(user: User = Depends(get_current_user)) -> User:
    """检查当前用户是否为管理员"""
    if not user:
        raise HTTPException(status_code=401, detail="需要登录")
    # 检查用户是否有 admin 角色
    if user.roles:
        for r in user.roles:
            if r.name in ("超级管理员", "admin"):
                return user
    # 兼容旧版 role 字段
    if user.role and user.role.value in ("admin",):
        return user
    raise HTTPException(status_code=403, detail="需要管理员权限")
