"""技能导入 API — 上传zip → 安全检测 → 安装"""
import os, re, io, json, uuid, zipfile, tempfile, shutil, logging
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.scan_skill import ScanSkill
from app.models.user import User
from app.api.deps import get_current_user
from app.services.skill_security import SkillSecurityScanner

router = APIRouter(tags=["技能导入"])
logger = logging.getLogger(__name__)

SKILLS_DIR = "/app/data/skills"
AGENT_URL = "http://agent:8001"


def _read_skill_meta(skill_dir):
    md_path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(md_path):
        return {}
    try:
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()
        if not content.startswith("---"):
            return {}
        parts = content.split("---", 2)
        if len(parts) < 3:
            return {}
        meta = {}
        for line in parts[1].split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip().lower()] = v.strip()
        return meta
    except Exception:
        return {}


async def _notify_agent_reload():
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{AGENT_URL}/skills/reload")
            if resp.status_code == 200:
                logger.info("Agent 技能已自动重载")
    except Exception as e:
        logger.warning(f"Agent reload failed: {e}")


@router.post("/api/skills/import")
async def import_skill(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    """导入技能包（zip），含安全检测"""
    task_id = str(uuid.uuid4())[:8]
    temp_root = f"/tmp/skill_import_{task_id}"

    try:
        if not file.filename or not file.filename.endswith(".zip"):
            raise HTTPException(400, detail="仅支持 .zip 格式的技能包")

        content = await file.read()
        if len(content) > 20 * 1024 * 1024:
            raise HTTPException(400, detail="技能包过大（最大 20MB）")

        os.makedirs(temp_root, exist_ok=True)
        zip_path = os.path.join(temp_root, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(content)

        extract_dir = os.path.join(temp_root, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if ".." in name or name.startswith("/"):
                    shutil.rmtree(temp_root, ignore_errors=True)
                    raise HTTPException(400, detail=f"非法路径: {name}")
            zf.extractall(extract_dir)

        # 安全检测
        scanner = SkillSecurityScanner(extract_dir)
        scan_result = scanner.scan()

        if not scan_result.passed:
            shutil.rmtree(temp_root, ignore_errors=True)
            return {
                "status": "rejected",
                "task_id": task_id,
                "message": "安全检测未通过",
                "issues": [i.to_dict() for i in scan_result.issues],
                "scan_result": scan_result.to_dict(),
            }

        # 确定技能 ID
        items = os.listdir(extract_dir)
        subdirs = [d for d in items if os.path.isdir(os.path.join(extract_dir, d))]
        skill_id = subdirs[0] if subdirs else Path(file.filename).stem.replace(".zip", "")
        skill_id = re.sub(r"[^a-z0-9\-]", "", skill_id.lower().replace(" ", "-"))
        if not skill_id:
            skill_id = f"custom-{task_id}"

        meta = _read_skill_meta(extract_dir)
        skill_name = meta.get("name", skill_id.replace("-", " ").title())
        category = meta.get("category", "自定义")
        severity = meta.get("severity", "medium")
        phase = meta.get("phase", "")
        raw_types = meta.get("target_types", '["*"]')
        try:
            target_types = json.loads(raw_types) if isinstance(raw_types, str) else raw_types
        except json.JSONDecodeError:
            target_types = ["*"]

        # 检查是否已存在
        async with AsyncSessionLocal() as sess:
            existing = await sess.execute(select(ScanSkill).where(ScanSkill.id == skill_id))
            if existing.scalar_one_or_none():
                shutil.rmtree(temp_root, ignore_errors=True)
                raise HTTPException(409, detail=f"技能 '{skill_id}' 已存在")

        # 安装
        target_dir = os.path.join(SKILLS_DIR, skill_id)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
        shutil.copytree(extract_dir, target_dir)

        # DB 写入（未启用）
        async with AsyncSessionLocal() as sess:
            s = ScanSkill(
                id=skill_id, name=skill_name, category=category,
                severity=severity, enabled=False, phase=phase,
                target_types=json.dumps(target_types, ensure_ascii=False),
                description=meta.get("description", f"导入技能: {skill_name}"),
                sort_order=999, tool_path=f"data/skills/{skill_id}/", is_custom=True,
            )
            sess.add(s)
            await sess.commit()
            await sess.refresh(s)

        shutil.rmtree(temp_root, ignore_errors=True)

        # 通知 Agent
        await _notify_agent_reload()

        return {
            "status": "imported",
            "task_id": task_id,
            "message": f"技能 '{skill_name}' 导入成功，启用后可生效",
            "skill": s.to_dict(),
            "scan_result": scan_result.to_dict(),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"导入失败: {e}")
        shutil.rmtree(temp_root, ignore_errors=True)
        raise HTTPException(500, detail=f"导入失败: {str(e)}")
