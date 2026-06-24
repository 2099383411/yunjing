"""负向验证记录 — 记录已验证不存在的漏洞/攻击面"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text
from app.models.task import Base


class NegativeResult(Base):
    """负向结果：验证了不存在的攻击面"""
    __tablename__ = "negative_results"

    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)
    target = Column(String(512), nullable=False)

    vuln_id = Column(String(50), nullable=True)              # CVE ID 或内部编号
    vuln_name = Column(String(256), nullable=False)          # 漏洞名称/描述
    verification_method = Column(String(128), nullable=False) # curl/nmap/nuclei/手动
    verification_detail = Column(Text, nullable=True)        # 验证过程描述
    status = Column(String(20), default="confirmed_safe")   # confirmed_safe, unable_to_verify
    reason = Column(String(256), nullable=True)              # 无法确认的原因
    suggestion = Column(Text, nullable=True)                 # 对客户的建议
    verified_at = Column(DateTime, default=datetime.utcnow)
