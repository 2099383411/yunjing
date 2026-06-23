"""数据库模型"""
from app.models.task import Base, ScanTask, TaskStatus
from app.models.vulnerability import Vulnerability
from app.models.report import Report
from app.models.user import User, UserRole, AuthorizationLog
from app.models.scan_skill import ScanSkill
from app.models.conversation import Conversation, Message
from app.models.setting import SystemSetting
from app.models.role import Role, Permission, RolePermission, SEED_PERMISSIONS, SEED_ROLES
from app.models.llm_provider import LLMProvider
from app.models.api_key import ApiKey
from app.models.scan_schedule import ScanSchedule
from app.models.webhook import Webhook

# v0.4 新模型
from app.models.cve_entry import CveEntry, CveVerificationResult
from app.models.execution_step import ExecutionStep
from app.models.trust_edge import TrustEdge
from app.models.negative_result import NegativeResult
from app.models.trace_audit import TraceAudit, AuditSummary
