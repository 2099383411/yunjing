"""技能安全检测器 — 导入前检查恶意代码、路径穿越、格式完整性"""
import os
import re
import json
from pathlib import Path
from typing import List, Tuple


class SecurityIssue:
    def __init__(self, level: str, file: str, line: int, msg: str):
        self.level = level
        self.file = file
        self.line = line
        self.message = msg

    def to_dict(self):
        return {"level": self.level, "file": self.file, "line": self.line, "message": self.message}


class ScanResult:
    def __init__(self):
        self.passed = True
        self.issues: List[SecurityIssue] = []
        self.skill_id = ""
        self.skill_name = ""
        self.total_files = 0
        self.total_size = 0

    def fail(self, issue: SecurityIssue):
        self.passed = False
        self.issues.append(issue)

    def warn(self, issue: SecurityIssue):
        self.issues.append(issue)

    def to_dict(self):
        return {
            "passed": self.passed,
            "skill_id": self.skill_id,
            "skill_name": self.skill_name,
            "total_files": self.total_files,
            "total_size": self.total_size,
            "issues": [i.to_dict() for i in self.issues],
        }


class SkillSecurityScanner:
    SUSPICIOUS_PATTERNS: List[Tuple[str, str, str]] = [
        (r"rm\s+-rf\s+/", "error", "破坏性删除操作（rm -rf /）"),
        (r"mkfs\.\w+", "error", "格式化磁盘操作"),
        (r"dd\s+if=/dev/zero", "error", "磁盘覆写操作"),
        (r">\s*/dev/sd[a-z]", "error", "直接写入磁盘设备"),
        (r"chmod\s+777\s+/", "error", "危险权限修改（根目录777）"),
        (r"bash\s+-[ic]\s+.*[<>].*/dev/tcp", "error", "反弹Shell连接"),
        (r"base64\s+-d\s*\|", "warning", "Base64解码后执行"),
        (r"wget\s+.*\|\s*(bash|sh)", "warning", "管道执行下载脚本"),
        (r"curl\s+.*\|\s*(bash|sh)", "warning", "管道执行下载脚本"),
        (r"subprocess\.(call|Popen|run)\s*\(", "warning", "子进程调用"),
        (r"os\.system\s*\(", "warning", "系统命令执行"),
        (r"eval\s*\(", "warning", "动态代码执行"),
        (r"(password|passwd|secret|token|api_key)\s*=\s*['\"](?!<)", "warning", "硬编码凭据嫌疑"),
    ]

    UNSAFE_PATHS = [r"\.\./", r"\.\.\\", r"/etc/", r"/proc/", r"/sys/", r"/root/"]
    ALLOWED_EXTENSIONS = {".md", ".py", ".sh", ".yaml", ".yml", ".json", ".txt",
                         ".conf", ".toml", ".cfg", ".xml", ".html", ".js", ".css",
                         ".png", ".jpg", ".gif", ".svg"}
    BLOCKED_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".msi", ".apk", ".deb", ".rpm", ".ko"}
    MAX_FILE_SIZE = 2 * 1024 * 1024
    MAX_TOTAL_SIZE = 20 * 1024 * 1024
    MAX_FILES = 100

    def __init__(self, extract_dir: str):
        self.extract_dir = extract_dir

    def scan(self) -> ScanResult:
        result = ScanResult()
        all_files = list(Path(self.extract_dir).rglob("*"))

        result.total_files = len(all_files)
        if result.total_files > self.MAX_FILES:
            result.fail(SecurityIssue("error", "", 0, f"文件数量过多（{result.total_files} > {self.MAX_FILES}）"))
            return result

        for f in all_files:
            if f.is_file():
                result.total_size += f.stat().st_size
        if result.total_size > self.MAX_TOTAL_SIZE:
            result.fail(SecurityIssue("error", "", 0, f"总大小超限"))
            return result

        has_skilled = False
        for f in all_files:
            if not f.is_file():
                continue
            rel_path = str(f.relative_to(self.extract_dir))
            ext = f.suffix.lower()

            if ext in self.BLOCKED_EXTENSIONS:
                result.fail(SecurityIssue("error", rel_path, 0, f"禁止的可执行文件类型（{ext}）"))
                continue

            if ext not in self.ALLOWED_EXTENSIONS and f.name != "SKILL.md":
                result.fail(SecurityIssue("error", rel_path, 0, f"不允许的文件类型（{ext}）"))
                continue

            if f.stat().st_size > self.MAX_FILE_SIZE:
                result.fail(SecurityIssue("error", rel_path, 0, f"文件过大（{f.stat().st_size//1024}KB）"))
                continue

            for unsafe in self.UNSAFE_PATHS:
                if unsafe in rel_path:
                    result.fail(SecurityIssue("error", rel_path, 0, f"路径穿越嫌疑"))
                    break

            if f.name == "SKILL.md":
                has_skilled = True
                try:
                    content = f.read_text("utf-8")
                    if not content.startswith("---"):
                        result.fail(SecurityIssue("error", rel_path, 0, "SKILL.md 缺少 YAML frontmatter"))
                    else:
                        parts = content.split("---", 2)
                        if len(parts) >= 3:
                            meta = {}
                            for line in parts[1].split("\n"):
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    meta[k.strip().lower()] = v.strip()
                            result.skill_name = meta.get("name", "")
                except Exception as e:
                    result.fail(SecurityIssue("error", rel_path, 0, f"SKILL.md 读取失败: {e}"))

            if ext in {".py", ".sh", ".js"}:
                try:
                    lines = f.read_text("utf-8", errors="replace").split("\n")
                    for lineno, line in enumerate(lines, 1):
                        for pattern, level, msg in self.SUSPICIOUS_PATTERNS:
                            if re.search(pattern, line, re.IGNORECASE):
                                issue = SecurityIssue(level, rel_path, lineno, msg)
                                if level == "error":
                                    result.fail(issue)
                                else:
                                    result.warn(issue)
                except Exception:
                    pass

        if not has_skilled:
            result.fail(SecurityIssue("error", "", 0, "技能包必须包含 SKILL.md 文件"))

        return result
