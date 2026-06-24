"""对话 / 消息持久化模型"""
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, JSON, Integer, ForeignKey
from app.models.task import Base
import uuid

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    title = Column(String(256), default="新对话")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    conversation_id = Column(String(36), ForeignKey("conversations.id"), nullable=False, index=True)
    role = Column(String(32), nullable=False)
    content = Column(Text, default="")
    tool_calls = Column(JSON, default=list)
    tool_call_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
