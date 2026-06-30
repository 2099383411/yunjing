"""Kali 工具元数据抽取 + Qdrant 向量索引写入脚本

用法:
    # 从 Kali 容器抽取 + 写入 Qdrant
    python -m tasks.scan_kali_index

    # 仅用内置数据写入 Qdrant（不依赖容器）
    python -m tasks.scan_kali_index --builtin-only

    # 强制重建索引
    python -m tasks.scan_kali_index --force
"""

import json
import logging
import os
import re
import subprocess
import sys
import time
from typing import Optional

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

#  ── 配置 ────────────────────────────────────────────────
KALI_CONTAINER = "yunjing-kali"  # Kali 容器名称
QDRANT_URL = os.environ.get("QDRANT_URL", "http://yunjing-qdrant:6333")
COLLECTION_NAME = "kali_tools"
EMBED_DIM = 1024
BGE_URL = os.environ.get("BGE_URL", "http://yunjing-bge:8000")
TOP_TOOLS_COUNT = 200  # 取前 200 个最大工具
BATCH_SIZE = 100

#  ── 辅助函数 ────────────────────────────────────────────


def _exec_in_kali(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """在 Kali 容器中执行命令（SSH 或本地 docker exec）"""
    # 尝试本地 docker
    try:
        r = subprocess.run(
            ["docker", "exec", KALI_CONTAINER, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning(f"本地 docker 执行失败: {e}")
    return -1, "", ""


def _ssh_exec(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """通过 SSH 在服务器上执行 docker exec"""
    ssh_host = os.environ.get("KALI_SSH_HOST", "")
    if not ssh_host:
        return -1, "", ""
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", ssh_host,
               f"docker exec {KALI_CONTAINER} bash -c '{cmd}'"]
    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        logger.warning(f"SSH 执行失败: {e}")
        return -1, "", ""


def _run(cmd: str, timeout: int = 60) -> tuple[int, str, str]:
    """多模式命令执行: 本地 docker → SSH → 失败"""
    code, out, err = _exec_in_kali(cmd, timeout)
    if code == 0:
        return code, out, err
    code, out, err = _ssh_exec(cmd, timeout)
    return code, out, err


def _get_bge_embedding(text: str) -> Optional[list[float]]:
    """通过 BGE 服务获取 embedding"""
    import httpx
    try:
        with httpx.Client(timeout=30) as client:
            resp = client.post(
                f"{BGE_URL}/embed",
                json={"text": text, "normalize": True},
            )
            resp.raise_for_status()
            return resp.json().get("vector")
    except Exception as e:
        logger.warning(f"BGE embedding 获取失败: {e}")
        return None


#  ── 步骤 1: 抽取 Kali 工具元数据 ─────────────────────


def extract_tool_metadata() -> list[dict]:
    """从 Kali 容器抽取所有已安装工具的元数据

    策略:
      1. 获取所有通过 apt 安装的包（按大小排序取 TOP_TOOLS_COUNT 个）
      2. 对每个包:
         - apt-cache show → 获取描述
         - dpkg -L → 找可执行文件
         - whatis → 获取简短命令描述
         - --help → 获取用法示例
    """
    logger.info("开始抽取 Kali 工具元数据...")

    # 检查容器可达性
    code, out, err = _run("which apt dpkg 2>/dev/null && echo 'KALI_OK'")
    if "KALI_OK" not in out:
        logger.warning("Kali 容器不可达, 回退到内置数据")
        return _load_builtin_tools()

    # ── 1. 获取所有已安装包（按 Installed-Size 降序）──
    code, out, err = _run(
        "dpkg-query -W -f='${Package}|${Installed-Size}|${Section}\\n' "
        "2>/dev/null | sort -t'|' -k2 -rn | head -{}".format(TOP_TOOLS_COUNT + 200)
    )
    if code != 0 or not out.strip():
        logger.warning("dpkg-query 失败, 回退到内置数据")
        return _load_builtin_tools()

    packages = []
    seen_names = set()
    for line in out.strip().split("\n"):
        parts = line.split("|")
        if len(parts) >= 2:
            name = parts[0].strip()
            size = parts[1].strip() if len(parts) > 1 else "0"
            section = parts[2].strip() if len(parts) > 2 else "unknown"
            # 过滤掉库文件、开发包等非工具包
            if name not in seen_names and not name.startswith("lib"):
                seen_names.add(name)
                packages.append({"name": name, "size": size, "section": section})

    logger.info(f"获取到 {len(packages)} 个工具包, 开始抽取详细信息...")

    # ── 2. 对每个包抽取详细信息 ──
    tools = []
    for i, pkg in enumerate(packages[:TOP_TOOLS_COUNT]):
        name = pkg["name"]
        if i % 50 == 0:
            logger.info(f"  进度: {i}/{min(len(packages), TOP_TOOLS_COUNT)}")

        tool = {
            "name": name,
            "description": "",
            "category": pkg["section"],
            "command": name,
            "usage": "",
        }

        # 获取 apt-cache 描述
        code, out, err = _run(f"apt-cache show {name} 2>/dev/null | grep -E '^(Description|Description-md5):' | head -1", timeout=10)
        if out.strip():
            desc = out.strip()
            if ":" in desc:
                tool["description"] = desc.split(":", 1)[1].strip()

        # 查找可执行文件
        code, out, err = _run(
            f"dpkg -L {name} 2>/dev/null | grep -E '/usr/bin/|/usr/sbin/|/usr/local/bin/' | head -3",
            timeout=10,
        )
        commands = [c.strip() for c in out.strip().split("\n") if c.strip()]
        if commands:
            # 取 basename 作为 command
            cmd_name = commands[0].split("/")[-1]
            tool["command"] = cmd_name

            # 获取 whatis 信息
            code, out, err = _run(f"whatis {cmd_name} 2>/dev/null | head -1", timeout=5)
            if out.strip() and not tool["description"]:
                tool["description"] = out.strip()

            # 获取 --help 的第一段
            code, out, err = _run(
                f"{cmd_name} --help 2>/dev/null | head -20", timeout=10
            )
            if out.strip():
                lines = [l.strip() for l in out.split("\n") if l.strip() and not l.strip().startswith("Usage:") and not l.strip().startswith("usage:")]
                # 取第一段有意义的文字
                usage_lines = []
                for line in lines:
                    if line and len(line) > 10:
                        usage_lines.append(line)
                        if len(usage_lines) >= 3:
                            break
                if usage_lines:
                    tool["usage"] = " ".join(usage_lines)[:300]

        # 类别映射: 将 apt section 映射到更有意义的分类名
        tool["category"] = _map_category(pkg["section"], name, tool.get("description", ""))

        # 清理描述
        desc = tool.get("description", "")
        if len(desc) > 300:
            tool["description"] = desc[:300]
        if not tool["description"]:
            tool["description"] = f"Kali Linux 工具: {name}"

        tools.append(tool)

    logger.info(f"抽取完成: {len(tools)} 个工具")
    return tools


def _map_category(section: str, name: str, description: str) -> str:
    """将 apt section 映射为更合理的分类名"""
    section_lower = section.lower()
    desc_lower = description.lower()

    mapping = {
        "net": "网络工具/通用",
        "admin": "管理工具/系统",
        "utils": "辅助工具/通用",
        "devel": "开发工具/编程",
        "web": "Web扫描/综合",
        "text": "文本工具/处理",
        "libs": "库文件/开发",
        "shells": "Shell/终端",
        "comm": "通信工具/网络",
        "interpreters": "解释器/编程",
        "security": "安全工具/渗透",
        "misc": "辅助工具/通用",
        "doc": "文档/帮助",
        "database": "数据库工具/通用",
        "oldlibs": "兼容库/旧版",
        "non-free": "专有工具/非自由",
        "contrib": "社区工具/贡献",
        "kernel": "内核模块/驱动",
        "x11": "图形工具/桌面",
        "gnome": "桌面环境/GNOME",
        "sound": "音频工具/多媒体",
        "video": "视频工具/多媒体",
        "games": "游戏/娱乐",
        "editors": "编辑器/文字",
        "electronics": "电子/硬件",
        "hamradio": "无线电/业余",
        "embedded": "嵌入式/开发",
    }

    # 尝试直接映射 section
    for key, val in mapping.items():
        if key in section_lower:
            return val

    # 根据名称和描述推断
    if any(kw in desc_lower for kw in ["扫描", "scan", "nmap", "port"]):
        return "信息收集/端口扫描"
    if any(kw in desc_lower for kw in ["破解", "brute", "crack", "密码", "password"]):
        return "暴力破解/在线"
    if any(kw in desc_lower for kw in ["注入", "injection", "sql"]):
        return "Web扫描/SQL注入"
    if any(kw in desc_lower for kw in ["web", "http", "cms", "wordpress"]):
        return "Web扫描/综合"
    if any(kw in desc_lower for kw in ["网络", "network", "dns", "proxy"]):
        return "网络工具/通用"
    if any(kw in desc_lower for kw in ["利用", "exploit", "payload", "shell"]):
        return "漏洞利用/通用"
    if any(kw in desc_lower for kw in ["取证", "forensic", "foremost"]):
        return "取证/通用"
    if any(kw in desc_lower for kw in ["无线", "wifi", "wireless", "aircrack"]):
        return "无线/综合"
    if any(kw in desc_lower for kw in ["逆向", "reverse", "debug", "disassem"]):
        return "逆向工程/通用"

    return section.capitalize() if section else "安全工具/通用"


def _load_builtin_tools() -> list[dict]:
    """从 scan_tools_search 模块加载内置工具数据"""
    try:
        from tasks.scan_tools_search import KALI_TOOLS
        logger.info(f"加载内置工具数据: {len(KALI_TOOLS)} 条")
        return KALI_TOOLS
    except ImportError:
        logger.error("无法加载内置工具数据")
        return []


#  ── 步骤 2: 写入 Qdrant ────────────────────────────────


def write_to_qdrant(tools: list[dict], force: bool = False) -> bool:
    """将工具元数据写入 Qdrant kali_tools 集合

    Args:
        tools: 工具元数据列表
        force: 是否强制重建

    Returns:
        bool: 是否成功
    """
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.http import models as qmodels
    except ImportError:
        logger.error("qdrant-client 未安装, 跳过 Qdrant 写入")
        return False

    logger.info(f"开始写入 Qdrant ({len(tools)} 条)...")

    try:
        client = QdrantClient(url=QDRANT_URL)

        # 检查/创建集合
        collections = client.get_collections().collections
        exists = any(c.name == COLLECTION_NAME for c in collections)

        if force and exists:
            client.delete_collection(collection_name=COLLECTION_NAME)
            exists = False
            logger.info("删除旧集合")

        if not exists:
            client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=qmodels.VectorParams(
                    size=EMBED_DIM,
                    distance=qmodels.Distance.COSINE,
                ),
            )
            logger.info(f"创建集合 {COLLECTION_NAME}")
        else:
            count = client.count(collection_name=COLLECTION_NAME)
            if count.count > 0 and not force:
                logger.info(f"集合已有 {count.count} 条, 跳过 (加 --force 重建)")
                return True

        # 构建 points
        points = []
        for i, tool in enumerate(tools):
            text = f"{tool['name']}: {tool['description']} 类别: {tool.get('category', '')}"
            point_id = (hash(tool["name"]) & 0x7FFFFFFFFFFFFFFF)

            vector = _get_bge_embedding(text)
            if vector is None:
                vector = [0.0] * EMBED_DIM

            points.append(qmodels.PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "category": tool.get("category", ""),
                    "command": tool.get("command", tool["name"]),
                    "usage": tool.get("usage", ""),
                    "text": text,
                },
            ))

            if len(points) >= BATCH_SIZE:
                client.upsert(
                    collection_name=COLLECTION_NAME,
                    points=points,
                    wait=True,
                )
                logger.info(f"  已写入 {i+1}/{len(tools)} 条")
                points = []

        # 写入剩余
        if points:
            client.upsert(
                collection_name=COLLECTION_NAME,
                points=points,
                wait=True,
            )

        # 创建全文索引
        try:
            client.create_payload_index(
                collection_name=COLLECTION_NAME,
                field_name="text",
                field_schema=qmodels.PayloadSchemaType.TEXT,
            )
        except Exception:
            pass

        logger.info(f"✅ 完成: {len(tools)} 条工具数据写入 {COLLECTION_NAME}")
        return True

    except Exception as e:
        logger.error(f"Qdrant 写入失败: {e}")
        return False


#  ── 主入口 ──────────────────────────────────────────────


def main():
    """主函数: 抽取工具元数据 → 写入 Qdrant"""
    import argparse

    parser = argparse.ArgumentParser(description="Kali 工具索引构建工具")
    parser.add_argument("--builtin-only", action="store_true",
                        help="仅使用内置数据（不依赖容器）")
    parser.add_argument("--force", action="store_true",
                        help="强制重建索引")
    parser.add_argument("--output", type=str, default="",
                        help="将工具元数据保存到 JSON 文件（调试用）")
    args = parser.parse_args()

    # 步骤 1: 抽取
    if args.builtin_only:
        tools = _load_builtin_tools()
    else:
        tools = extract_tool_metadata()

    if not tools:
        logger.error("未获取到工具数据")
        sys.exit(1)

    # 可选: 保存到 JSON
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(tools, f, ensure_ascii=False, indent=2)
        logger.info(f"工具元数据已保存到: {args.output}")

    # 步骤 2: 写入 Qdrant
    success = write_to_qdrant(tools, force=args.force)
    if not success:
        logger.warning("Qdrant 写入失败, 工具数据仍可使用内置搜索")
        logger.info(f"内置搜索: from tasks.scan_tools_search import search_kali_tools")


if __name__ == "__main__":
    main()
