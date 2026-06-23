"""CVE-to-Exploit 执行引擎
将推演层的结果 → 在沙箱中找到并执行利用 → 捕获证据"""
import json, re, asyncio, subprocess
from typing import Optional
from datetime import datetime

SANDBOX_CONTAINER = "yunjing-sbx"
OUTPUT_DIR = "/data/exploit-output"


def _sandbox_exec(cmd: str, timeout: int = 120) -> dict:
    """在沙箱容器中执行命令，返回 stdout/stderr/returncode"""
    try:
        r = subprocess.run(
            ["docker", "exec", SANDBOX_CONTAINER, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return {
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
            "returncode": r.returncode,
            "success": r.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "TIME_OUT", "returncode": -1, "success": False}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "success": False}


def _ensure_output_dir():
    """确保沙箱中有输出目录"""
    _sandbox_exec(f"mkdir -p {OUTPUT_DIR}")


# ── 工具映射 ─────────────────────────────────────────────
EXPLOIT_TOOLS = {
    "searchsploit": {
        "check": lambda cve_id: _sandbox_exec(
            f"searchsploit --cve {cve_id} 2>/dev/null | grep -v 'Exploit Title\\|-----\\|^$'"
        ),
        "exploit": lambda cve_id, target: _searchsploit_run(cve_id, target),
    },
    "nuclei": {
        "check": lambda cve_id: _sandbox_exec(
            f"nuclei -silent -id {cve_id.replace('-', '_')} -tl 2>/dev/null | head -5"
        ),
        "exploit": lambda cve_id, target: _nuclei_run(cve_id, target),
    },
    "metasploit": {
        "check": lambda cve_id: _sandbox_exec(
            f"msfconsole -q -x 'search cve:{cve_id}; exit' 2>/dev/null | grep -i exploit | head -5"
        ),
        "exploit": lambda cve_id, target: _metasploit_run(cve_id, target),
    },
}


def _searchsploit_run(cve_id: str, target: str) -> dict:
    """通过 searchsploit 搜索并尝试获取 PoC 信息"""
    result = _sandbox_exec(f"searchsploit --cve {cve_id} 2>/dev/null")
    evidence = {
        "tool": "searchsploit",
        "cve_id": cve_id,
        "target": target,
        "search_result": result.get("stdout", "No results"),
    }
    
    # 提取 exploitdb ID
    lines = result["stdout"].split("\n")
    exploit_ids = []
    for line in lines:
        parts = line.strip().split()
        for p in parts:
            if p.isdigit() and len(p) >= 4:
                exploit_ids.append(p)
    
    evidence["exploitdb_ids"] = exploit_ids
    
    # 如果有 PoC 命令，尝试执行
    poc_output = ""
    from app.database import AsyncSessionLocal
    from app.models.cve_entry import CveEntry
    from sqlalchemy import select
    import asyncio
    
    async def _get_poc():
        async with AsyncSessionLocal() as sess:
            r = await sess.execute(
                select(CveEntry).where(CveEntry.cve_id == cve_id)
            )
            entry = r.scalar_one_or_none()
            if entry and entry.poc_command:
                poc_result = _sandbox_exec(
                    f"cd {OUTPUT_DIR} && {entry.poc_command}",
                    timeout=60
                )
                return poc_result.get("stdout", "")[:2000]
            return ""
    
    try:
        poc_output = asyncio.run(_get_poc())
    except Exception:
        pass
    
    evidence["poc_output"] = poc_output[:2000]
    evidence["full_output"] = result["stdout"]
    return evidence


def _nuclei_run(cve_id: str, target: str) -> dict:
    """用 Nuclei 模板验证 CVE"""
    template_id = cve_id.replace("-", "_").lower()
    cmd = f"nuclei -u {target} -id {template_id} -json -silent -timeout 30 2>/dev/null"
    result = _sandbox_exec(cmd, timeout=60)
    
    evidence = {
        "tool": "nuclei",
        "cve_id": cve_id,
        "target": target,
        "template_id": template_id,
        "found": bool(result["stdout"] and result["success"]),
    }
    
    # 解析 JSON 输出
    findings = []
    for line in result["stdout"].split("\n"):
        line = line.strip()
        if line:
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    
    evidence["findings"] = findings
    evidence["full_output"] = result["stdout"][:2000]
    evidence["success"] = len(findings) > 0
    return evidence


def _metasploit_run(cve_id: str, target: str) -> dict:
    """搜索 Metasploit 模块（不自动执行，仅搜索）"""
    result = _sandbox_exec(
        f"msfconsole -q -x 'search cve:{cve_id}; exit' -o {OUTPUT_DIR}/msf_{cve_id}.txt 2>/dev/null"
    )
    evidence = {
        "tool": "metasploit",
        "cve_id": cve_id,
        "target": target,
        "success": result["success"],
    }
    
    # 尝试读取输出文件
    file_result = _sandbox_exec(f"cat {OUTPUT_DIR}/msf_{cve_id}.txt 2>/dev/null")
    evidence["search_result"] = file_result.get("stdout", result.get("stdout", ""))[:2000]
    evidence["full_output"] = result["stdout"]
    return evidence


# ── 主入口 ───────────────────────────────────────────────
def exploit_cve(cve_id: str, target: str, poc_command: str = "") -> dict:
    """主入口：对指定 CVE + 目标执行利用验证"""
    _ensure_output_dir()
    
    result = {
        "cve_id": cve_id,
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "tools_tried": [],
        "exploit_found": False,
        "evidence": [],
        "summary": "",
    }
    
    # 1. searchsploit (总是执行)
    ss = _searchsploit_run(cve_id, target)
    result["tools_tried"].append("searchsploit")
    result["evidence"].append(ss)
    
    # 2. Nuclei (如果有模板)
    nuc = _nuclei_run(cve_id, target)
    result["tools_tried"].append("nuclei")
    result["evidence"].append(nuc)
    result["exploit_found"] = result["exploit_found"] or nuc.get("found", False)
    
    # 3. Metasploit
    msf = _metasploit_run(cve_id, target)
    result["tools_tried"].append("metasploit")
    result["evidence"].append(msf)
    
    # 如果有 PoC 命令直接执行
    if poc_command:
        poc = _sandbox_exec(f"cd {OUTPUT_DIR} && {poc_command}", timeout=60)
        result["evidence"].append({
            "tool": "poc_command",
            "cve_id": cve_id,
            "output": poc.get("stdout", "")[:2000],
            "success": poc["success"],
        })
        result["exploit_found"] = result["exploit_found"] or poc["success"]
    
    # 摘要
    exploit_count = sum(1 for e in result["evidence"] if e.get("success") or e.get("found"))
    result["exploit_count"] = exploit_count
    result["exploit_found"] = exploit_count > 0
    
    if exploit_count > 0:
        result["summary"] = f"找到 {exploit_count} 个可利用途径"
    else:
        # 检查是否有 searchsploit 结果（信息但非利用）
        ss_results = ss.get("search_result", "")
        if ss_results and "Exploit Title" not in ss_results:
            result["summary"] = f"searchsploit 返回了 {len(ss.get('exploitdb_ids', []))} 个 exploit"
        else:
            result["summary"] = "未找到可直接利用的 PoC，建议手动验证"
    
    return result


def batch_exploit(cve_targets: list[dict]) -> list[dict]:
    """批量执行 CVE 利用
    
    cve_targets: [{"cve_id": "CVE-2025-xxx", "target": "http://example.com", "poc_command": ""}, ...]
    """
    results = []
    for item in cve_targets:
        r = exploit_cve(
            item["cve_id"],
            item.get("target", ""),
            item.get("poc_command", ""),
        )
        results.append(r)
    return results


# ── 与 vulnerability 记录联动 ─────────────────────────
def update_vuln_with_exploit(vuln_id: str, exploit_result: dict) -> dict:
    """将利用结果更新到 vulnerability 表中"""
    import uuid
    from app.database import AsyncSessionLocal
    from sqlalchemy import text
    import asyncio
    
    evidence = exploit_result.get("evidence", [])
    exploit_found = exploit_result.get("exploit_found", False)
    
    async def _update():
        async with AsyncSessionLocal() as sess:
            # 更新证据字段
            await sess.execute(
                text("""
                    UPDATE vulnerabilities 
                    SET exploit_evidence = :evidence,
                        exploit_verified = :verified,
                        updated_at = NOW()
                    WHERE id = :vuln_id
                """),
                {
                    "evidence": json.dumps(evidence, ensure_ascii=False, default=str)[:5000],
                    "verified": exploit_found,
                    "vuln_id": vuln_id,
                }
            )
            await sess.commit()
            return {"status": "updated", "exploit_verified": exploit_found}
    
    return asyncio.run(_update())
