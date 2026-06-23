"""更新管理系统 — 使用 Docker SDK 操作沙箱"""
import json, os, uuid, asyncio, urllib.request, urllib.parse, tempfile, zipfile, docker
from datetime import datetime
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from sqlalchemy import create_engine, text

router = APIRouter()
from app.config import settings; DB = settings.DATABASE_URL.replace("+asyncpg", "")
NVD_API_KEY = "72a2582f-5cc3-4b10-ba0a-c493732f91b6"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _get_sbx():
    return docker.from_env().containers.get("yunjing-sbx")

def _sh(cmd: str, timeout: int = 30) -> tuple[int, str]:
    try:
        rc, out = _get_sbx().exec_run(["sh", "-c", cmd])
        return rc, (out.decode() if isinstance(out, bytes) else str(out)).strip()
    except Exception as e:
        return -1, str(e)

class UpdateConfig(BaseModel):
    nuclei_enabled: bool = True; nuclei_url: str = ""; nuclei_frequency: str = "weekly"
    exploitdb_enabled: bool = True; exploitdb_url: str = ""; exploitdb_frequency: str = "weekly"
    msf_enabled: bool = True; msf_frequency: str = "weekly"; msf_sources_url: str = ""
    cve_enabled: bool = True; cve_frequency: str = "weekly"

async def _nuclei_status() -> dict:
    _, ver = _sh("nuclei -version 2>&1 | head -1", 15)
    _, cnt = _sh('find /root/nuclei-templates/ -name "*.yaml" 2>/dev/null | wc -l', 10)
    try: t = int(cnt.strip())
    except: t = 0
    return {"version": ver[:100], "templates": t, "last_update": "unknown"}

async def _exploitdb_status() -> dict:
    _, ver = _sh("dpkg -l exploitdb 2>/dev/null | tail -1 | awk '{print $3}'", 10)
    _, cnt = _sh("ls /usr/share/exploitdb/exploits/ 2>/dev/null | wc -l", 10)
    try: e = int(cnt.strip())
    except: e = 0
    return {"version": ver[:60] or "未安装", "exploits": e, "last_update": "unknown"}

async def _metasploit_status() -> dict:
    _, ver = _sh("msfconsole --version 2>&1 | head -1", 15)
    _, cnt = _sh("ls /usr/share/metasploit-framework/modules/ 2>/dev/null | wc -l", 10)
    _, sz = _sh("du -sh /usr/share/metasploit-framework/ 2>/dev/null | cut -f1", 10)
    try: m = int(cnt.strip())
    except: m = 0
    return {"version": ver[:80] or "未安装", "modules": m, "size": sz.strip() or "未知", "last_update": "unknown"}

async def _cve_status() -> dict:
    try:
        eng = create_engine(DB)
        with eng.begin() as conn:
            r = conn.execute(text("SELECT COUNT(*) FROM cve_database"))
            total = r.fetchone()[0]
            r2 = conn.execute(text("SELECT MIN(last_updated), MAX(last_updated) FROM cve_database WHERE last_updated IS NOT NULL"))
            row2 = r2.fetchone()
            dmin = str(row2[0])[:10] if row2 and row2[0] else "N/A"
            dmax = str(row2[1])[:10] if row2 and row2[1] else "N/A"
        eng.dispose()
    except:
        total, dmin, dmax = 0, "N/A", "N/A"
    return {"total_cves": total, "date_range": f"{dmin} ~ {dmax}", "last_update": datetime.utcnow().strftime("%Y-%m-%d %H:%M")}

# ──── API ────

@router.get("/status")
async def get_status():
    n, e, m, c = await asyncio.gather(
        _nuclei_status(), _exploitdb_status(), _metasploit_status(), _cve_status())
    return {"nuclei": n, "exploitdb": e, "metasploit": m, "cve": c}

@router.get("/config")
async def get_config():
    return UpdateConfig().model_dump()

@router.put("/config")
async def save_config(cfg: UpdateConfig):
    return cfg.model_dump()

@router.post("/trigger")
async def trigger_update(target: str = Query(...)):
    if target == "nuclei":
        rc, out = _sh("nuclei -update-templates 2>&1", 120)
        if rc != 0: raise HTTPException(500, f"更新失败: {out[:500]}")
        s = await _nuclei_status()
        return {"nuclei": {"status": "updated", "templates": s["templates"]}}

    elif target == "exploitdb":
        rc, out = _sh("cd /usr/share/exploitdb && git pull 2>&1 || (apt-get update -qq && apt-get install -y exploitdb -qq 2>&1)", 120)
        if rc != 0: raise HTTPException(500, f"更新失败: {out[:500]}")
        s = await _exploitdb_status()
        return {"exploitdb": {"status": "updated", "exploits": s["exploits"]}}

    elif target == "metasploit":
        rc, out = _sh("msfupdate --force 2>&1 || (apt-get update -qq && apt-get install --only-upgrade metasploit-framework -y 2>&1)", 180)
        if rc != 0: raise HTTPException(500, f"更新失败: {out[:500]}")
        s = await _metasploit_status()
        return {"metasploit": {"status": "updated", "version": s["version"]}}

    elif target == "cve":
        try:
            now = datetime.utcnow()
            start = now.strftime("%Y-%m-%dT00:00:00.000")
            end = now.strftime("%Y-%m-%dT23:59:59.999")
            params = urllib.parse.urlencode({"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 100})
            req = urllib.request.Request(NVD_URL + "?" + params, headers={"User-Agent": "Yunjing/1.0", "apiKey": NVD_API_KEY})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
            if data.get("vulnerabilities"):
                with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
                    json.dump(data, tmp); tmp_path = tmp.name
                import importlib
                import_nvd = importlib.import_module("app.grounding.import_nvd")
                eng = create_engine(DB)
                imported = import_nvd.import_file(tmp_path, eng)
                os.unlink(tmp_path); eng.dispose()
                return {"cve": {"status": "updated", "imported": imported, "date": start[:10]}}
            return {"cve": {"status": "no_data", "note": f"{start[:10]} 无新 CVE"}}
        except Exception as e:
            import traceback
            raise HTTPException(500, f"CVE 更新失败: {str(e)}\n{traceback.format_exc()}")

    raise HTTPException(400, f"未知目标: {target}")

@router.post("/upload")
async def upload_package(file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(400, "仅支持 ZIP 文件")

    content = await file.read()
    results = {}
    sbx = _get_sbx()

    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(content); tmppath = tmp.name

    try:
        with zipfile.ZipFile(tmppath, "r") as zf:
            names = zf.namelist()
            has_nuclei = any(n.endswith(".yaml") for n in names)
            has_cve = any(n.endswith(".json") for n in names)
            has_edb = any("exploit" in n.lower() for n in names)

            if has_nuclei:
                import tarfile, io
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w") as tar:
                    for n in names:
                        if n.endswith(".yaml"):
                            info = tarfile.TarInfo(name=f"nuclei-templates/{n.split('/')[-1]}")
                            data = zf.read(n)
                            info.size = len(data)
                            tar.addfile(info, io.BytesIO(data))
                buf.seek(0)
                sbx.put_archive("/root/", buf)
                _sh("cp -r /root/nuclei-templates/* /root/nuclei-templates/ 2>/dev/null; true")
                s = await _nuclei_status()
                results["nuclei"] = {"templates": s["templates"]}

            if has_edb:
                import tarfile, io
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w") as tar:
                    for n in names:
                        if "exploit" in n.lower():
                            info = tarfile.TarInfo(name=f"edb/{n.split('/')[-1]}")
                            data = zf.read(n)
                            info.size = len(data)
                            tar.addfile(info, io.BytesIO(data))
                buf.seek(0)
                sbx.put_archive("/tmp/", buf)
                _sh("cp /tmp/edb/* /usr/share/exploitdb/exploits/ 2>/dev/null; true")
                s = await _exploitdb_status()
                results["exploitdb"] = {"exploits": s["exploits"]}

            if has_cve:
                import importlib
                import_nvd = importlib.import_module("app.grounding.import_nvd")
                eng = create_engine(DB)
                imported = 0
                for n in names:
                    if n.endswith(".json"):
                        data = json.loads(zf.read(n))
                        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
                            json.dump(data, f); fpath = f.name
                        imported += import_nvd.import_file(fpath, eng)
                        os.unlink(fpath)
                eng.dispose()
                results["cve"] = {"imported": imported}

            # fallback: 没有匹配类型时尝试 JSON 作为 CVE
            if not any([has_nuclei, has_edb, has_cve]):
                import importlib
                import_nvd = importlib.import_module("app.grounding.import_nvd")
                eng = create_engine(DB)
                imported = 0
                for n in names:
                    if n.endswith(".json"):
                        data = json.loads(zf.read(n))
                        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
                            json.dump(data, f); fpath = f.name
                        imported += import_nvd.import_file(fpath, eng)
                        os.unlink(fpath)
                eng.dispose()
                results["cve"] = {"imported": imported}
    finally:
        os.unlink(tmppath)
    return {"status": "processed", "results": results}

# 兼容旧端点
@router.get("/check")
async def check_update():
    s = await _nuclei_status()
    return {"nuclei_version": s["version"], "templates_count": s["templates"], "update_available": False}

@router.post("/update")
async def update_templates():
    return await trigger_update(target="nuclei")
