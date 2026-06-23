"""认证 API：注册、登录、当前用户"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from passlib.hash import bcrypt
from app.models.user import User, UserRole
from app.database import AsyncSessionLocal
from sqlalchemy import select
from app.api.deps import create_access_token, get_current_user

router = APIRouter()

class RegisterRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

@router.post("/register")
async def register(req: RegisterRequest):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(User).where(User.username == req.username))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="用户名已存在")
        user = User(
            id=str(uuid.uuid4()),
            username=req.username,
            password_hash=bcrypt.hash(req.password),
            display_name=req.display_name or req.username,
            role=UserRole.ANALYST,
            created_at=datetime.utcnow(),
        )
        sess.add(user)
        await sess.commit()
        await sess.refresh(user)
    return {"message": "注册成功", "user_id": user.id}

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(User).where(User.username == req.username))
        user = result.scalar_one_or_none()
        if not user or not bcrypt.verify(req.password, user.password_hash):
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="用户已禁用")
        token = create_access_token(user.id, user.role.value)
    return TokenResponse(
        access_token=token,
        user={"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role.value},
    )

@router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    return {
        "id": user.id, "username": user.username, "display_name": user.display_name,
        "role": user.role.value, "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else "",
    }

@router.post("/setup", response_model=TokenResponse)
async def first_setup(req: RegisterRequest):
    """首次安装 - 创建 admin 用户"""
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(User))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="已有用户，请使用登录")
        user = User(
            id=str(uuid.uuid4()), username=req.username,
            password_hash=bcrypt.hash(req.password),
            display_name=req.display_name or req.username,
            role=UserRole.ADMIN, created_at=datetime.utcnow(),
        )
        sess.add(user)
        await sess.commit()
        await sess.refresh(user)
    token = create_access_token(user.id, user.role.value)
    return TokenResponse(
        access_token=token,
        user={"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role.value},
    )

@router.put("/me")
async def update_me(data: dict, user: User = Depends(get_current_user)):
    """当前用户修改个人信息"""
    async with AsyncSessionLocal() as sess:
        db_user = await sess.get(User, user.id)
        if not db_user:
            raise HTTPException(status_code=404, detail="用户不存在")
        if data.get("display_name"):
            db_user.display_name = data["display_name"]
        if data.get("password"):
            from passlib.hash import bcrypt
            db_user.password_hash = bcrypt.hash(data["password"])
        await sess.commit()
    return {"ok": True, "display_name": db_user.display_name}
