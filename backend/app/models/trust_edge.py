"""信任关系模型 — 多目标间凭证传递 + 跳板攻击路径"""
from datetime import datetime
from sqlalchemy import Column, String, DateTime, JSON, Text
from app.models.task import Base


class TrustEdge(Base):
    """信任关系：记录已控制资产间的凭证传递和跳板路径"""
    __tablename__ = "trust_edges"

    id = Column(String(36), primary_key=True)
    task_id = Column(String(36), nullable=False, index=True)

    from_host = Column(String(256), nullable=False)          # 源资产
    to_host = Column(String(256), nullable=False)            # 目标资产
    edge_type = Column(String(32), nullable=False)           # credential_access, network_access, shell_relay
    credential = Column(JSON, nullable=True)                 # {user, pass, service, type}
    route = Column(String(128), nullable=True)               # reverse_shell, ssh_tunnel, proxy
    status = Column(String(20), default="available")        # available, used, expired, closed
    discovered_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)             # NULL=不过期, 其他=过期时间
    notes = Column(Text, nullable=True)
