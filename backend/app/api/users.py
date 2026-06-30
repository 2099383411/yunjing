"""用户管理 API（需管理员权限）"""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, or_, func
from passlib.hash import bcrypt
from app.database import AsyncSessionLocal
from app.models.user import User
from app.models.role import Role, user_roles
from app.api.deps import get_current_user, require_admin

router = APIRouter(dependencies=[Depends(require_admin)])

# ── 当前用户自助服务（无需 admin） ──
self_router = APIRouter()


@self_router.put("/me/password")
async def change_my_password(data: dict, user: User = Depends(get_current_user)):
    """当前用户修改自己的密码"""
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")
    confirm_pw = data.get("confirm_password", "")

    async with AsyncSessionLocal() as db:
        db_user = await db.get(User, user.id)
        if not db_user or not bcrypt.verify(old_pw, db_user.password_hash):
            return {"status": "error", "message": "旧密码不正确"}
        if new_pw != confirm_pw:
            return {"status": "error", "message": "两次新密码不一致"}
        if len(new_pw) < 8:
            return {"status": "error", "message": "密码长度至少8位"}
        db_user.password_hash = bcrypt.hash(new_pw)
        await db.commit()
    return {"status": "ok", "message": "密码已修改"}


class CreateUserReq(BaseModel):
    username: str
    password: str
    display_name: str = ""
    role_ids: list[str] = []


class UpdateUserReq(BaseModel):
    display_name: str | None = None
    is_active: bool | None = None
    password: str | None = None


@router.get("/")
async def list_users(page: int = 1, size: int = 20, search: str = ""):
    async with AsyncSessionLocal() as sess:
        q = select(User)
        if search:
            q = q.where(or_(User.username.ilike(f"%{search}%"), User.display_name.ilike(f"%{search}%")))
        total = await sess.scalar(select(func.count()).select_from(q.subquery()))
        q = q.order_by(User.created_at.desc()).offset((page - 1) * size).limit(size)
        rows = (await sess.execute(q)).scalars().all()
        # Load roles
        result = []
        for u in rows:
            rls = [{"id": r.id, "name": r.name} for r in u.roles] if u.roles else []
            result.append({
                "id": u.id, "username": u.username, "display_name": u.display_name,
                "is_active": u.is_active, "role": u.role.value if u.role else "",
                "roles": rls, "created_at": u.created_at.isoformat() if u.created_at else "",
            })
    return {"items": result, "total": total, "page": page, "size": size}


@router.post("/")
async def create_user(req: CreateUserReq):
    async with AsyncSessionLocal() as sess:
        existing = await sess.execute(select(User).where(User.username == req.username))
        if existing.scalar_one_or_none():
            raise HTTPException(400, "用户名已存在")
        user = User(
            id=str(uuid.uuid4()), username=req.username,
            password_hash=bcrypt.hash(req.password),
            display_name=req.display_name or req.username,
        )
        sess.add(user)
        await sess.flush()
        # 分配角色
        if req.role_ids:
            roles = (await sess.execute(select(Role).where(Role.id.in_(req.role_ids)))).scalars().all()
            user.roles = roles
        await sess.commit()
    return {"id": user.id, "username": user.username, "display_name": user.display_name}


@router.get("/{user_id}")
async def get_user(user_id: str):
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        rls = [{"id": r.id, "name": r.name} for r in user.roles] if user.roles else []
    return {
        "id": user.id, "username": user.username, "display_name": user.display_name,
        "is_active": user.is_active, "role": user.role.value if user.role else "",
        "roles": rls, "created_at": user.created_at.isoformat() if user.created_at else "",
    }


@router.put("/{user_id}")
async def update_user(user_id: str, req: UpdateUserReq):
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        if req.display_name is not None:
            user.display_name = req.display_name
        if req.is_active is not None:
            user.is_active = req.is_active
        if req.password:
            user.password_hash = bcrypt.hash(req.password)
        await sess.commit()
    return {"ok": True}


@router.delete("/{user_id}")
async def delete_user(user_id: str):
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        await sess.delete(user)
        await sess.commit()
    return {"ok": True}


@router.put("/{user_id}/toggle-active")
async def toggle_active(user_id: str):
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        user.is_active = not user.is_active
        await sess.commit()
    return {"id": user_id, "is_active": user.is_active}


@router.put("/{user_id}/roles")
async def set_user_roles(user_id: str, data: dict):
    role_ids = data.get("role_ids", [])
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        roles = (await sess.execute(select(Role).where(Role.id.in_(role_ids)))).scalars().all()
        user.roles = roles
        await sess.commit()
    return {"ok": True, "roles": [r.name for r in roles]}


@router.put("/{user_id}/reset-password")
async def reset_password(user_id: str, data: dict):
    new_pw = data.get("password", "")
    async with AsyncSessionLocal() as sess:
        user = await sess.get(User, user_id)
        if not user:
            raise HTTPException(404, "用户不存在")
        user.password_hash = bcrypt.hash(new_pw)
        await sess.commit()
    return {"ok": True, "new_password": new_pw}
