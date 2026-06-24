"""云镜推理引擎 — 知识库查询引擎

核心能力：在推理过程中动态查询知识库文档，获取原理支撑和攻击面推导。

不是向量数据库，也不依赖外部服务。通过解析 45+ 份 Markdown 文档的
结构化内容（标题、表格、列表、内联代码），建立轻量级索引。
"""
from __future__ import annotations
import os
import re
import glob
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# RAG semantic search
try:
    from app.engine.vector_store import RAGEngine
    _RAG_AVAILABLE = True
    logger.info("[KB] RAG loaded")
except Exception:
    _RAG_AVAILABLE = False
    logger.warning("[KB] RAG unavailable")
# ============================================================
# 文档解析结果的数据结构
# ============================================================

@dataclass
class DocSection:
    """文档中的一节"""
    title: str                    # 节的标题
    level: int                    # 标题层级 (1=#, 2=##, 3=###)
    content: str                  # 节的完整内容
    keywords: list[str] = field(default_factory=list)  # 提取的关键词

    def snippet(self, max_len: int = 300) -> str:
        """截取前 n 字符作为摘要"""
        if len(self.content) <= max_len:
            return self.content
        return self.content[:max_len] + "..."
@dataclass
class AttackSurfaceEntry:
    """攻击面条目（从 Level 1 文档的表格中提取）"""
    attack_direction: str         # 攻击方向
    derivation_logic: str         # 推导逻辑
    actual_technique: str         # 实际攻击技术
    section_title: str = ""       # 所属章节
    doc_path: str = ""            # 文档路径
    score: float = 0.0            # 与查询的匹配度
    inferred_protocol: str = ""   # 推断的协议/领域名

    @property
    def port_numbers(self) -> list[int]:
        """根据 inferred_protocol 返回关联端口"""
        proto = self.inferred_protocol.lower()
        port_map = {
            "http": [80, 443, 8080, 8443, 8000, 13577],
            "https": [443, 8443], "tls": [443, 8443], "ssl": [443, 8443],
            "ssh": [22], "smb": [445, 139], "dns": [53],
            "redis": [6379], "mysql": [3306],
            "tcp": [], "ip": [], "dns": [53],
            "ldap": [389, 636], "kerberos": [88, 464],
            "rdp": [3389], "smtp": [25, 465, 587],
            "ftp": [21], "telnet": [23],
            "docker": [2375, 2376], "container": [],
            "browser": [], "password": [], "crypto": [], "kernel": [],
            "everything": [13577], "ztna": [], "nsg": [443],
            "proxmox": [8006], "api": [80, 443, 8080, 3000, 5000, 9000],
        }
        for key, ports in port_map.items():
            if key in proto:
                return ports
        return []

    def __str__(self) -> str:
        return f"[{self.section_title}]({self.inferred_protocol}) {self.attack_direction[:40]}"
@dataclass
class KnowledgeQueryResult:
    """知识库查询结果"""
    sections: list[DocSection] = field(default_factory=list)
    attack_surface_entries: list[AttackSurfaceEntry] = field(default_factory=list)
    total_matches: int = 0

    def to_dict(self) -> dict:
        return {
            "sections": [
                {"title": s.title, "level": s.level, "snippet": s.snippet()}
                for s in self.sections[:5]
            ],
            "attack_surfaces": [
                {
                    "direction": a.attack_direction,
                    "derivation": a.derivation_logic,
                    "technique": a.actual_technique,
                }
                for a in self.attack_surface_entries[:8]
            ],
            "total_matches": self.total_matches,
        }
# ============================================================
# 文档解析器
# ============================================================

class DocumentParser:
    """解析 Markdown 文档为结构化数据"""

    @staticmethod
    def parse_document(filepath: str) -> tuple[str, list[DocSection], list[AttackSurfaceEntry]]:
        """
        解析一个 .md 文件

        Returns:
            (title, sections, attack_surface_entries)
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
        except (IOError, UnicodeDecodeError) as e:
            logger.warning(f"[知识库] 文件读取失败 {filepath}: {e}")
            return "", [], []

        title = DocumentParser._extract_title(content)
        sections = DocumentParser._split_sections(content)
        attack_entries = DocumentParser._extract_attack_surface_tables(content, filepath)

        # 设置 section_title + 推断协议
        for entry in attack_entries:
            parent_section = ""
            for sec in sections:
                if entry.derivation_logic in sec.content or entry.attack_direction in sec.content:
                    parent_section = sec.title
                    break
            entry.section_title = parent_section or title
            entry.inferred_protocol = DocumentParser._infer_protocol(
                parent_section or title
            )

            # 将协议推断的端口号注入到关联章节的关键词
            if entry.inferred_protocol:
                for sec in sections:
                    if sec.title == entry.section_title:
                        for p in entry.port_numbers:
                            if p > 0:
                                kw = f"port-{p}"
                                if kw not in sec.keywords:
                                    sec.keywords.append(kw)
                        if entry.inferred_protocol not in sec.keywords:
                            sec.keywords.append(entry.inferred_protocol)
                        break

        return title, sections, attack_entries

    @staticmethod
    def _infer_protocol(section_title: str) -> str:
        """从章节标题推断协议/领域名"""
        title_lower = section_title.lower()
        proto_patterns = [
            (["tcp", "ip", "tcp/ip", "传输层", "网络层"], "tcp_ip"),
            (["http", "web", "hypertext", "浏览器", "同源", "xss", "csrf", "cors"], "http"),
            (["tls", "ssl", "https", "certificate", "证书"], "tls"),
            (["ssh", "secure shell"], "ssh"),
            (["smb", "samba", "cifs", "netbios", "445"], "smb"),
            (["dns", "域名"], "dns"),
            (["redis", "key-value", "缓存"], "redis"),
            (["mysql", "数据库", "sql"], "mysql"),
            (["docker", "容器", "container"], "docker"),
            (["kdbx", "keepass", "密码库", "kdb", "vault", "密码存储"], "password"),
            (["everything", "文件系统暴露", "文件读取"], "everything"),
            (["ztna", "零信任", "zero trust", "headscale", "authentik"], "ztna"),
            (["nsg", "防火墙", "vfw", "下一代防火墙"], "nsg"),
            (["proxmox", "虚拟机", "hypervisor", "pve"], "proxmox"),
            (["身份认证", "auth", "jwt", "oauth", "token", "凭据", "credential"], "auth"),
            (["密钥", "key", "证书", "加密", "哈希"], "crypto"),
            (["kernel", "内核", "驱动", "syscall", "系统调用"], "kernel"),
            (["开发", "dev", "git", "ci", "cd", "dockerfile"], "dev"),
            (["api", "rest", "graphql", "grpc", "接口"], "api"),
            (["网络", "network", "protocol", "协议"], "network"),
            (["浏览器", "browser", "客户端", "client side", "dom"], "browser"),
        ]
        for keywords, proto in proto_patterns:
            if any(kw in title_lower for kw in keywords):
                return proto
        return ""

    @staticmethod
    def _extract_title(content: str) -> str:
        """提取文档标题 (# 开头)"""
        m = re.search(r"^#\s+(.+)", content, re.MULTILINE)
        if m:
            title = m.group(1).strip()
            # 去掉末尾的「— xxx」或「—— xxx」
            title = re.sub(r"\s*[—\-]+\s*.*", "", title).strip()
            return title
        return ""

    @staticmethod
    def _split_sections(content: str) -> list[DocSection]:
        """按标题分割文档为节"""
        sections = []

        # 找所有标题行
        pattern = r"^(#{1,4})\s+(.+)$"
        matches = list(re.finditer(pattern, content, re.MULTILINE))

        for i, m in enumerate(matches):
            level = len(m.group(1))
            title = m.group(2).strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            section_content = content[start:end].strip()

            # 提取关键词
            keywords = DocumentParser._extract_keywords(title, section_content)

            sections.append(DocSection(
                title=title,
                level=level,
                content=section_content,
                keywords=keywords,
            ))

        return sections

    @staticmethod
    def _extract_keywords(title: str, content: str) -> list[str]:
        """从标题和内容中提取关键词"""
        words = set()
        
        # 从标题提取
        title_lower = title.lower()
        # 去掉标点和分隔符
        title_clean = re.sub(r"[^\w\s]", " ", title_lower)
        for w in title_clean.split():
            if len(w) > 2:
                words.add(w)

        # 从内容中提取：代码块中的技术术语、加粗文本、端口号
        # 内联代码
        for match in re.finditer(r"`([^`]+)`", content):
            code = match.group(1).lower().strip()
            if len(code) > 2 and " " not in code:
                words.add(code)
        
        # 端口号（多种格式）
        for match in re.finditer(r"端口\s*(\d+)", content):
            words.add(f"port-{match.group(1)}")
            words.add(match.group(1))  # 裸端口号
        for match in re.finditer(r"(?:port|PORT)\s+(\d+)", content):
            words.add(f"port-{match.group(1)}")
            words.add(match.group(1))
        # "XXX 6379/tcp" 或 "XXXX:6379"
        for match in re.finditer(r"\b(\d{4,5})/(?:tcp|udp)", content):
            words.add(f"port-{match.group(1)}")
            words.add(match.group(1))
        for match in re.finditer(r":(\d{4,5})\b", content):
            words.add(f"port-{match.group(1)}")
            words.add(match.group(1))
        # "端口号 6379" 单独出现在行中
        for match in re.finditer(r"\b(6379|6380|3306|5432|22|80|443|445|139|13577|8080|8443|9090|1433|1521|2222|3389|8000|9000|10000)\b", content):
            words.add(f"port-{match.group(1)}")
            words.add(match.group(1))
        
        # 协议名/服务名（含常见非协议名）
        for match in re.finditer(
            r"\b(TCP|UDP|HTTP|HTTPS|SSH|FTP|SMB|Redis|MySQL|DNS|TLS|SSL|RDP|"
            r"LDAP|NFS|SMTP|POP3|IMAP|SNMP|DHCP|Docker|Kubernetes|nginx|"
            r"Apache|Nuclei|Nmap|Sqlmap|Hydra|Curl|AD|Kerberos|NTLM)\b",
            content, re.IGNORECASE
        ):
            words.add(match.group(1).lower())

        return sorted(words)

    @staticmethod
    def _extract_attack_surface_tables(content: str, filepath: str) -> list[AttackSurfaceEntry]:
        """从 Markdown 表格中提取攻击面条目（Level 1 格式）

        支持两种表格格式:
        Format A (level1-attack-surface-derivation.md):
            | # | 攻击方向 | 推导逻辑 | 实际攻击技术 |
        Format B (level1-{network,web,crypto,...}-attack-surface.md):
            | 突破方式 | 推导的攻击 | 实际案例 |

        限制: 仅从 Level 1 文档解析（文件名含 level1 或目录为 attack-surface）
        """
        entries = []
        filename = os.path.basename(filepath)
        dirname = os.path.basename(os.path.dirname(filepath))

        # 文件过滤: 仅 Level 1 文档
        if "level1" not in filename and "level1" not in dirname:
            return entries

        # ------------ Format A: 编号表格 ------------
        for match in re.finditer(r"^\|\s*\d+\s*\|(.+?)\|(.+?)\|(.+?)\|", content, re.MULTILINE):
            direction = match.group(1).strip()
            logic = match.group(2).strip()
            technique = match.group(3).strip()

            if "攻击方向" in direction or "---" in direction:
                continue
            if not DocumentParser._is_valid_entry(direction, logic):
                continue

            entries.append(AttackSurfaceEntry(
                attack_direction=direction,
                derivation_logic=logic,
                actual_technique=technique,
                doc_path=filepath,
            ))

        # ------------ Format B: 3列表格（无编号） ------------
        lines = content.split("\n")
        in_table = False
        for i, line in enumerate(lines):
            stripped = line.strip()

            # 检测分隔行
            if re.match(r"^\|[-| ]+\|$", stripped) and "|" in stripped:
                in_table = True
                continue

            if in_table and stripped.startswith("|"):
                if re.match(r"^\|\s*\d+\s*\|", stripped):
                    continue

                cells = [c.strip() for c in stripped.split("|")]
                cells = [c for c in cells if c]

                if len(cells) < 2:
                    continue

                # 跳过表头行
                header_keywords = ["突破方式", "攻击方向", "攻击方式", "---", "威胁建模"]
                if any(kw in cells[0] for kw in header_keywords):
                    continue
                # 短行也跳过（不是真实数据）
                if len(cells[0]) < 4 and len(cells) < 3:
                    continue

                break_method = cells[0]
                derived_attack = cells[1]
                real_case = cells[2] if len(cells) > 2 else ""

                if not DocumentParser._is_valid_entry(derived_attack, break_method):
                    continue

                entries.append(AttackSurfaceEntry(
                    attack_direction=derived_attack,
                    derivation_logic=break_method,
                    actual_technique=derived_attack,
                    doc_path=filepath,
                ))

            if in_table and not stripped.startswith("|"):
                in_table = False

        # 去重
        seen = set()
        unique = []
        for e in entries:
            key = e.attack_direction + e.derivation_logic
            if key not in seen:
                seen.add(key)
                unique.append(e)
            elif key in seen:
                # 保留短的那个（可能更精确）
                pass

        logger.info(f"[解析] {filename}: {len(unique)} 攻击面条目")
        return unique

    @staticmethod
    def _is_valid_entry(direction: str, logic: str = "") -> bool:
        """检查攻击面条目的有效性"""
        # 过短
        if len(direction) < 4 and len(logic) < 4:
            return False
        # 纯数字/符号
        if direction.replace(" ", "").replace("-", "").replace("_", "").isdigit():
            return False
        # 常见无效行
        invalid_direction = [
            "--", "|", "...", "如", "例", "备", "注", "说明",
            "Windows 95", "Windows NT", "Windows Vista", "Windows 7",
            "Windows 8", "Windows 10", "Server", "Client",
        ]
        for inv in invalid_direction:
            if direction.strip().startswith(inv):
                return False
        # 纯代码/命令（不含解释）
        code_chars = sum(1 for c in direction if c in '`/\\[]{}')
        if code_chars > len(direction) * 0.4:
            return False
        return True

        logger.info(f"[解析] {filename}: {len(entries)} 攻击面条目 (Format A + B)")
        return entries
# ============================================================
# 知识库索引
# ============================================================
DEFAULT_KB_PATH = os.environ.get("KB_PATH", os.path.join("/app/app/data/knowledge-base"))


class KnowledgeBaseIndex:
    """知识库索引 — 支持关键词查询的轻量级全文索引"""

    def __init__(self, kb_path: str = ""):
        self._kb_path = kb_path or DEFAULT_KB_PATH
        
        # 索引数据结构
        self._documents: dict[str, str] = {}           # path → title
        self._sections: dict[str, list[DocSection]] = {}  # path → sections
        self._attack_entries: dict[str, list[AttackSurfaceEntry]] = {}  # path → entries
        self._keyword_index: dict[str, list[tuple[str, int]]] = {}  # keyword → [(path, section_idx)]

        self._initialized = False
        self._rag_engine = None

    def _get_rag(self):
        """Lazy init RAG engine"""
        if self._rag_engine is None and _RAG_AVAILABLE:
            try:
                self._rag_engine = RAGEngine()
                logger.info("[KB] RAG init OK")
            except Exception as e:
                logger.warning(f"[KB] RAG init failed: {e}")
        return self._rag_engine

    def initialize(self, force_rebuild: bool = False):
        """扫描并索引知识库"""
        if self._initialized and not force_rebuild:
            return

        start = __import__("time").time()
        md_files = glob.glob(os.path.join(self._kb_path, "**/*.md"), recursive=True)
        # 过滤 INDEX.md 和 SUMMARY.md
        md_files = [f for f in md_files if not f.endswith(("INDEX.md", "SUMMARY.md"))]
        
        logger.info(f"[知识库索引] 扫描 {len(md_files)} 个文档...")

        total_sections = 0
        total_entries = 0

        for filepath in md_files:
            rel_path = os.path.relpath(filepath, self._kb_path)
            title, sections, entries = DocumentParser.parse_document(filepath)

            self._documents[rel_path] = title
            self._sections[rel_path] = sections
            self._attack_entries[rel_path] = entries
            total_sections += len(sections)
            total_entries += len(entries)

            # 建立关键词索引
            for idx, section in enumerate(sections):
                for keyword in section.keywords:
                    if keyword not in self._keyword_index:
                        self._keyword_index[keyword] = []
                    self._keyword_index[keyword].append((rel_path, idx))

        elapsed = __import__("time").time() - start
        self._initialized = True

        logger.info(
            f"[知识库索引] ✅ 完成: {len(md_files)} 文档, "
            f"{total_sections} 节, {total_entries} 攻击面条目, "
            f"{len(self._keyword_index)} 关键词, "
            f"耗时 {elapsed:.1f}s"
        )

    # ============================================================
    # 查询接口
    # ============================================================

    def query(self, keywords: list[str], query: str = "",
              top_k: int = 5) -> KnowledgeQueryResult:
        """知识库查询 — RAG语义搜索为主通道，关键词索引为降级Fallback

        Args:
            keywords: 搜索关键词列表（降级时使用）
            query: 原始查询文本（RAG主通道使用）
            top_k: 返回 top-k 结果

        Returns:
            KnowledgeQueryResult 包含匹配的章节
        """
        if not self._initialized:
            self.initialize()

        result = KnowledgeQueryResult()
        seen_docs: set[str] = set()

        # 1. RAG 语义搜索（主通道）
        rag = self._get_rag()
        if rag:
            try:
                semantic_results = rag.search(
                    query or " ".join(keywords),
                    top_k=top_k,
                )
                for sr in semantic_results:
                    src = sr.get("source", "")
                    text = sr.get("text", "")
                    if src and text:
                        rscore = sr.get("rscore", sr.get("score", 0))
                        section = DocSection(
                            title=sr.get("metadata", {}).get("title", src),
                            level=3,
                            content=text,
                            keywords=[f"rag:{rscore:.3f}"],
                        )
                        doc_key = src.split("/")[0]
                        if doc_key not in seen_docs:
                            result.sections.append(section)
                            seen_docs.add(doc_key)
            except Exception as e:
                logger.warning(f"[KB] RAG search failed, fallback to keyword: {e}")

        # 2. 关键词索引 Fallback（RAG 不可用或结果不够时）
        if len(result.sections) < top_k and self._keyword_index:
            matched_sections: dict[str, float] = {}
            for keyword in keywords:
                kw_lower = keyword.lower()
                if kw_lower in self._keyword_index:
                    for rel_path, sec_idx in self._keyword_index[kw_lower]:
                        key = f"{rel_path}:{sec_idx}"
                        matched_sections[key] = matched_sections.get(key, 0) + 1.0

            sorted_matches = sorted(matched_sections.items(), key=lambda x: x[1], reverse=True)
            for key, score in sorted_matches:
                rel_path, sec_idx = key.split(":")
                sec_idx = int(sec_idx)
                sections = self._sections.get(rel_path, [])
                if sec_idx < len(sections):
                    section = sections[sec_idx]
                    doc_key = rel_path.split("/")[0]
                    if doc_key not in seen_docs or len(result.sections) < 3:
                        result.sections.append(section)
                        seen_docs.add(doc_key)
                if len(result.sections) >= top_k:
                    break

        # 3. 匹配攻击面条目（含协议推断+端口映射）
        matched_entries: list[tuple[AttackSurfaceEntry, float]] = []
        query_port = None
        for kw in keywords:
            if kw.isdigit() and 1 <= int(kw) <= 65535:
                query_port = int(kw)
                break

        for rel_path, entries in self._attack_entries.items():
            for entry in entries:
                score = 0.0
                entry_text = (entry.derivation_logic + entry.attack_direction +
                              entry.inferred_protocol).lower()
                for kw in keywords:
                    if kw.lower() in entry_text:
                        score += 1.0
                    # 部分匹配
                    if any(kw.lower() in word for word in entry_text.split()):
                        score += 0.3

                # 端口匹配（通过协议推断的 port_numbers）
                if query_port and query_port in entry.port_numbers:
                    score += 2.0  # 端口匹配权重更高

                # 协议名匹配
                if query_port and not entry.inferred_protocol:
                    pass  # 没有推断到协议，跳过

                if score > 0:
                    entry.score = score
                    matched_entries.append((entry, score))

        matched_entries.sort(key=lambda x: x[1], reverse=True)
        result.attack_surface_entries = [e for e, s in matched_entries[:top_k * 2]]
        result.total_matches = len(result.sections) + len(matched_entries)

        return result

    def query_by_port(self, port: int) -> KnowledgeQueryResult:
        """按端口查询"""
        return self.query([f"port-{port}", str(port)])

    def query_by_service(self, service: str) -> KnowledgeQueryResult:
        """按服务名查询"""
        svc = service.lower().replace(" ", "-")
        return self.query([svc, service.lower()])

    def query_by_env(self, env_hint: str) -> KnowledgeQueryResult:
        """按环境类型查询"""
        env_keywords = {
            "container": ["docker", "container", "namespace"],
            "windows": ["windows", "ntfs", "win32"],
            "linux": ["linux", "kernel"],
            "web": ["http", "web", "browser"],
            "network": ["tcp", "ip", "network", "protocol"],
            "crypto": ["cipher", "encryption", "tls", "ssl"],
        }
        keywords = env_keywords.get(env_hint.lower(), [env_hint])
        return self.query(keywords)

    def query_attack_surface(
        self, port: int = 0, service: str = "",
        env: str = "", extra_keywords: list[str] = None
    ) -> KnowledgeQueryResult:
        """综合查询：端口+服务+环境+额外关键词

        这是推理引擎调用的主入口。
        """
        keywords = []

        if port:
            keywords.append(f"port-{port}")
            keywords.append(str(port))
        if service:
            keywords.append(service.lower())
        if env:
            keywords.append(env.lower())
        if extra_keywords:
            keywords.extend(extra_keywords)

        return self.query(keywords)

    def get_stats(self) -> dict:
        """获取索引统计"""
        if not self._initialized:
            self.initialize()

        doc_count = len(self._documents)
        section_count = sum(len(s) for s in self._sections.values())
        entry_count = sum(len(e) for e in self._attack_entries.values())
        keyword_count = len(self._keyword_index)

        # 按领域分组
        domains: dict[str, int] = {}
        for rel_path in self._documents:
            domain = rel_path.split("/")[0]
            domains[domain] = domains.get(domain, 0) + 1

        return {
            "documents": doc_count,
            "sections": section_count,
            "attack_surface_entries": entry_count,
            "keywords": keyword_count,
            "domains": domains,
        }
# ============================================================
# 全局实例（延迟初始化）
# ============================================================

_kb_index: Optional[KnowledgeBaseIndex] = None
def get_kb_index() -> KnowledgeBaseIndex:
    """获取全局知识库索引实例"""
    global _kb_index
    if _kb_index is None:
        _kb_index = KnowledgeBaseIndex()
        _kb_index.initialize()
    return _kb_index
