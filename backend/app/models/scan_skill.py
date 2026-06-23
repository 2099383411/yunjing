"""ScanSkill 模型 - 云镜技能体系"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Text, DateTime, Integer
from app.models.task import Base


class ScanSkill(Base):
    __tablename__ = "scan_skills"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False, comment="技能名称")
    category = Column(String(50), nullable=False, default="综合", comment="分类")
    severity = Column(String(20), nullable=False, default="medium", comment="风险等级")
    enabled = Column(Boolean, nullable=False, default=True, comment="是否启用")
    description = Column(Text, nullable=False, default="", comment="技能描述")
    tool_path = Column(String(200), nullable=True, comment="对应工具路径")
    is_custom = Column(Boolean, nullable=False, default=False, comment="是否自定义")
    sort_order = Column(Integer, nullable=False, default=0, comment="排序")
    phase = Column(String(50), nullable=True, default="", comment="关联PTES阶段")
    target_types = Column(Text, nullable=True, default="[]", comment="兼容目标类型JSON数组")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "severity": self.severity, "enabled": self.enabled,
            "description": self.description, "tool_path": self.tool_path,
            "is_custom": self.is_custom, "sort_order": self.sort_order,
            "phase": self.phase or "",
            "target_types": self.target_types or "[]",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
