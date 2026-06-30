"""技能管理 API - 技能的CRUD与启动同步"""
import os
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.scan_skill import ScanSkill
from app.models.user import User
from app.api.deps import get_current_user

router = APIRouter(tags=["技能管理"])

SKILLS_DATA_DIR = "/app/data/skills"

# ── 18个内置技能定义 ──────────────────────────────────────────
BUILTIN_SKILLS = [
    {"id": "security-scanner", "layer": "perception", "name": "综合安全检测", "category": "综合", "severity": "critical",
     "description": "综合渗透测试入口，覆盖端口/漏洞/Web/AD域/API/认证等18个模块", "sort_order": 0},
    {"id": "net-vuln-scan", "layer": "perception", "name": "网络安全漏洞检测", "category": "扫描", "severity": "high",
     "description": "开放端口检测、弱密码、SSL/TLS证书、网络配置安全检查", "sort_order": 1},
    {"id": "nmap-pentest-scans", "layer": "perception", "name": "Nmap渗透扫描", "category": "扫描", "severity": "high",
     "description": "Nmap主机发现/端口扫描/服务枚举/NSE脚本探测/OS指纹识别", "sort_order": 2},
    {"id": "pentest-workbench", "layer": "perception", "name": "渗透测试工作台", "category": "综合", "severity": "high",
     "description": "信息收集→Web测试→暴力破解→漏洞利用→后渗透", "sort_order": 3},
    {"id": "pentest-active-directory", "layer": "execution", "name": "AD域渗透", "category": "内网", "severity": "critical",
     "description": "Kerberos攻击(AS-REP/Kerberoasting)/中继攻击/委派滥用/ACL滥用", "sort_order": 4},
    {"id": "pentest-api-attacker", "layer": "execution", "name": "API安全测试", "category": "Web", "severity": "high",
     "description": "OWASP API Top 10：发现/认证/注入/速率限制/GraphQL", "sort_order": 5},
    {"id": "pentest-auth-bypass", "layer": "execution", "name": "认证绕过测试", "category": "Web", "severity": "high",
     "description": "JWT攻击/算法混淆/OAuth滥用/Session攻击/2FA绕过", "sort_order": 6},
    {"id": "pentest-c2-operator", "layer": "execution", "name": "C2后渗透操作", "category": "后渗透", "severity": "critical",
     "description": "C2通信/后渗透操作/横向移动/权限维持/检测规避", "sort_order": 7},
    {"id": "pentest-commands", "layer": "execution", "name": "渗透命令速查", "category": "工具", "severity": "medium",
     "description": "nmap/MSF/hydra/john/nikto/gobuster常用命令参考", "sort_order": 8},
    {"id": "client-side-pentest", "layer": "execution", "name": "客户端渗透测试", "category": "Web", "severity": "high",
     "description": "DOM XSS/CSRF/CSP/点击劫持/WebSocket/PostMessage检测", "sort_order": 9},
    {"id": "hexstrike", "layer": "execution", "name": "高级渗透技术", "category": "综合", "severity": "critical",
     "description": "Web漏洞利用/密码分析/Pwn/取证/逆向/免杀", "sort_order": 10},
    {"id": "awesome-pentest", "layer": "deduction", "name": "渗透测试资源", "category": "资源", "severity": "info",
     "description": "CVE查询/PoC收集/工具导航/CTF平台/学习资源", "sort_order": 11},
    {"id": "security-reviewer", "layer": "execution", "name": "安全代码审查", "category": "开发", "severity": "high",
     "description": "SAST静态分析/依赖扫描/密钥检测/IaC安全/架构评审", "sort_order": 12},
    {"id": "senior-security", "layer": "deduction", "name": "高级安全架构", "category": "架构", "severity": "high",
     "description": "零信任/SOC/Red Team/合规治理/DevSecOps", "sort_order": 13},
    {"id": "prts-sandbox", "layer": "execution", "name": "Kali沙箱环境", "category": "工具", "severity": "medium",
     "description": "隔离沙箱(yunjing-kali)运行渗透工具，含14种扫描工具", "sort_order": 14},
    {"id": "s3-pentest-commands", "layer": "execution", "name": "S3云存储测试", "category": "云安全", "severity": "high",
     "description": "AWS S3公开桶/权限枚举/策略审计/安全配置检查", "sort_order": 15},
    {"id": "shannon-pentest", "layer": "deduction", "name": "Shannon渗透框架", "category": "综合", "severity": "medium",
     "description": "Shannon方法论：侦查/合规/基线/风险量化", "sort_order": 16},
    {"id": "penetration-tester", "layer": "deduction", "name": "渗透测试方法论", "category": "方法论", "severity": "medium",
     "description": "伦理黑客五阶段：侦查→扫描→利用→后渗透→报告", "sort_order": 17},
]

def _load_md_preview(skill_id: str) -> str:
    path = os.path.join(SKILLS_DATA_DIR, skill_id, "SKILL.md")
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()[:300]
        except Exception:
            pass
    return ""

async def sync_builtin_skills():
    """启动时自动同步内置技能到数据库"""
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSkill))
        existing = {s.id: s for s in result.scalars().all()}
        for sdef in BUILTIN_SKILLS:
            sid = sdef["id"]
            tool_path = f"data/skills/{sid}/"
            if sid in existing:
                s = existing[sid]
                s.name = sdef["name"]
                s.category = sdef["category"]
                s.severity = sdef["severity"]
                s.description = sdef["description"]
                s.sort_order = sdef["sort_order"]
                s.tool_path = tool_path
            else:
                s = ScanSkill(
                    id=sid, name=sdef["name"], category=sdef["category"],
                    severity=sdef["severity"], enabled=True,
                    description=sdef["description"], sort_order=sdef["sort_order"],
                    tool_path=tool_path, is_custom=False,
                )
                sess.add(s)
        await sess.commit()

# ── API 端点 ──────────────────────────────────────────────────

@router.get("/api/skills/")
async def list_skills(current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSkill).order_by(ScanSkill.sort_order))
        skills = result.scalars().all()
        data = []
        for s in skills:
            d = s.to_dict()
            md = _load_md_preview(s.id)
            if md:
                d["md_preview"] = md
            data.append(d)
    return {"skills": data}

@router.put("/api/skills/{skill_id}/")
async def update_skill(skill_id: str, body: dict,
                       current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSkill).where(ScanSkill.id == skill_id))
        skill = result.scalar_one_or_none()
        if not skill:
            raise HTTPException(status_code=404, detail="技能不存在")
        allowed = {"name", "category", "severity", "enabled", "description"}
        for k, v in body.items():
            if k in allowed:
                setattr(skill, k, v)
        skill.updated_at = datetime.utcnow()
        await sess.commit()
        await sess.refresh(skill)
        d = skill.to_dict()
    return {"skill": d, "message": "技能已更新"}

@router.post("/api/skills/")
async def create_custom_skill(body: dict,
                              current_user: User = Depends(get_current_user)):
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="技能名称不能为空")
    async with AsyncSessionLocal() as sess:
        skill = ScanSkill(
            id=f"custom-{uuid.uuid4().hex[:8]}",
            name=name, category=body.get("category", "自定义"),
            severity=body.get("severity", "medium"), enabled=True,
            description=body.get("description", ""), is_custom=True, sort_order=99,
        )
        sess.add(skill)
        await sess.commit()
        await sess.refresh(skill)
        d = skill.to_dict()
    return {"skill": d, "message": "自定义技能已创建"}

@router.delete("/api/skills/{skill_id}/")
async def delete_skill(skill_id: str,
                       current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as sess:
        result = await sess.execute(select(ScanSkill).where(ScanSkill.id == skill_id))
        skill = result.scalar_one_or_none()
        if not skill:
            raise HTTPException(status_code=404, detail="技能不存在")
        if not skill.is_custom:
            raise HTTPException(status_code=403, detail="内置技能不可删除")
        await sess.delete(skill)
        await sess.commit()
    return {"message": "技能已删除"}

@router.post("/api/skills/import")
async def import_skill(file: UploadFile = File(...),
                       current_user: User = Depends(get_current_user)):
    """导入自定义技能包（ZIP格式）"""
    import zipfile, io, tempfile, shutil

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="仅支持ZIP格式的技能包")

    content = await file.read()
    total_size = len(content)

    # 安全检查：验证ZIP结构
    issues = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            names = zf.namelist()
            total_files = len(names)

            # 基本安全检查
            dangerous_exts = {".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".ps1"}
            for n in names:
                ext = os.path.splitext(n)[1].lower()
                if ext in dangerous_exts:
                    issues.append(f"危险文件类型: {n}")

            # 需要SKILL.md
            has_skill_md = any("SKILL.md" in n for n in names)
            if not has_skill_md:
                issues.append("缺少 SKILL.md 文件")

            if issues:
                return {
                    "status": "rejected",
                    "message": "技能包安全检查未通过",
                    "issues": issues[:5],
                    "scan_result": {"total_files": total_files, "total_size": total_size},
                }

            # 解压到技能目录
            skill_name = os.path.splitext(file.filename)[0]
            target_dir = os.path.join(SKILLS_DATA_DIR, skill_name)
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            os.makedirs(target_dir, exist_ok=True)
            zf.extractall(target_dir)

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的ZIP文件")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导入失败: {str(e)}")

    # 注册到数据库
    async with AsyncSessionLocal() as sess:
        existing = (await sess.execute(
            select(ScanSkill).where(ScanSkill.id == skill_name)
        )).scalar_one_or_none()
        if existing:
            existing.enabled = False
        else:
            skill = ScanSkill(
                id=skill_name,
                name=skill_name,
                category="自定义",
                severity="medium",
                enabled=False,
                description=f"从 {file.filename} 导入的自定义技能",
                is_custom=True,
                sort_order=99,
            )
            sess.add(skill)
        await sess.commit()

    return {
        "status": "imported",
        "skill": {"id": skill_name, "name": skill_name, "enabled": False},
        "message": f"技能包已导入到 {target_dir}",
        "scan_result": {"total_files": total_files, "total_size": total_size},
    }
