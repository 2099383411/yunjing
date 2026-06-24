"""CVE 数据库模型 — 接地层核心"""
from datetime import datetime
from sqlalchemy import Column, String, Float, DateTime, JSON, Text, Boolean
from app.models.task import Base


class CveEntry(Base):
    """CVE 条目：接地层知识库"""
    __tablename__ = "cve_database"

    id = Column(String(36), primary_key=True)
    cve_id = Column(String(20), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    severity = Column(String(20), nullable=True)
    affected_versions = Column(JSON, default=list)         # [{product: Apache, version: 2.4.49}]
    fixed_in_versions = Column(JSON, default=list)         # [{product: Apache, version: 2.4.50}]
    vuln_type = Column(String(50), nullable=True)           # path_traversal, rce, sql_injection...
    poc_available = Column(Boolean, default=False)
    poc_path = Column(String(512), nullable=True)           # 本地 PoC 路径或命令
    poc_command = Column(String(1024), nullable=True)       # 示例验证命令
    notes = Column(Text, nullable=True)                     # 注意事项 (如 需开启mod_cgi)
    references = Column(JSON, default=list)                 # 外部参考链接
    source = Column(String(20), default="NVD")             # 数据来源: NVD/CNVD/GitHub
    coverage_note = Column(String(256), nullable=True)      # 覆盖范围标注 (如 不含CNVD未公开)
    last_updated = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class CveVerificationResult(Base):
    """CVE 校验结果缓存 — 避免重复查询"""
    __tablename__ = "cve_verification_cache"

    id = Column(String(36), primary_key=True)
    cve_id = Column(String(20), nullable=False, index=True)
    product = Column(String(100), nullable=False)
    version = Column(String(50), nullable=False)
    is_affected = Column(Boolean, nullable=False)            # True=受影响, False=不受影响, None=未知
    confidence = Column(Float, default=0.0)                  # 校验置信度
    notes = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
