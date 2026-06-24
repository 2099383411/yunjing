"""角色权限管理 API"""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from app.database import AsyncSessionLocal
from app.models.role import Role, Permission, RolePermission, SEED_PERMISSIONS
from app.api.deps import require_admin

router = APIRouter(dependencies=[Depends(require_admin)])


class CreateRoleReq(BaseModel):
    name: str
    description: str = ""
    permission_ids: list[str] = []


@router.get("/roles")
async def list_roles():
    async with AsyncSessionLocal() as sess:
        rows = (await sess.execute(select(Role).order_by(Role.created_at))).scalars().all()
    return [{
        "id": r.id, "name": r.name, "description": r.description,
        "is_system": r.is_system,
        "created_at": r.created_at.isoformat() if r.created_at else "",
    } for r in rows]


@router.post("/roles")
async def create_role(req: CreateRoleReq):
    async with AsyncSessionLocal() as sess:
        existing = await sess.execute(select(Role).where(Role.name == req.name))
        if existing.scalar_one_or_none():
            raise HTTPException(400, "角色名已存在")
        role = Role(id=str(uuid.uuid4()), name=req.name, description=req.description)
        sess.add(role)
        await sess.flush()
        if req.permission_ids:
            perms = (await sess.execute(
                select(Permission).where(Permission.id.in_(req.permission_ids))
            )).scalars().all()
            for p in perms:
                sess.add(RolePermission(role_id=role.id, permission_id=p.id))
        await sess.commit()
    return {"id": role.id, "name": role.name}


@router.get("/roles/{role_id}")
async def get_role(role_id: str):
    async with AsyncSessionLocal() as sess:
        role = await sess.get(Role, role_id)
        if not role:
            raise HTTPException(404, "角色不存在")
        perms = (await sess.execute(
            select(Permission).join(RolePermission).where(RolePermission.role_id == role_id)
        )).scalars().all()
    return {
        "id": role.id, "name": role.name, "description": role.description,
        "is_system": role.is_system,
        "permissions": [{"id": p.id, "resource": p.resource, "action": p.action} for p in perms],
    }


@router.put("/roles/{role_id}")
async def update_role(role_id: str, data: dict):
    async with AsyncSessionLocal() as sess:
        role = await sess.get(Role, role_id)
        if not role:
            raise HTTPException(404, "角色不存在")
        if "name" in data:
            role.name = data["name"]
        if "description" in data:
            role.description = data["description"]
        await sess.commit()
    return {"ok": True}


@router.delete("/roles/{role_id}")
async def delete_role(role_id: str):
    async with AsyncSessionLocal() as sess:
        role = await sess.get(Role, role_id)
        if not role:
            raise HTTPException(404, "角色不存在")
        if role.is_system:
            raise HTTPException(400, "系统角色不可删除")
        await sess.delete(role)
        await sess.commit()
    return {"ok": True}


@router.put("/roles/{role_id}/permissions")
async def set_role_permissions(role_id: str, data: dict):
    permission_ids = data.get("permission_ids", [])
    async with AsyncSessionLocal() as sess:
        role = await sess.get(Role, role_id)
        if not role:
            raise HTTPException(404, "角色不存在")
        # 清空原有权限
        await sess.execute(delete(RolePermission).where(RolePermission.role_id == role_id))
        # 添加新权限
        perms = (await sess.execute(
            select(Permission).where(Permission.id.in_(permission_ids))
        )).scalars().all()
        for p in perms:
            sess.add(RolePermission(role_id=role.id, permission_id=p.id))
        await sess.commit()
    return {"ok": True, "permissions_count": len(permission_ids)}


@router.get("/permissions")
async def list_permissions():
    async with AsyncSessionLocal() as sess:
        rows = (await sess.execute(select(Permission).order_by(Permission.resource, Permission.action))).scalars().all()
    return [{
        "id": p.id, "resource": p.resource, "action": p.action, "description": p.description,
    } for p in rows]
