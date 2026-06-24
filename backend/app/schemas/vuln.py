from datetime import datetime
from pydantic import BaseModel

class VulnerabilityResponse(BaseModel):
    id: str
    title: str
    severity: str
    cve_id: str | None
    cvss_score: float | None
    target: str
    description: str | None
    remediation: str | None
    tool_source: str | None
    discovered_at: datetime
