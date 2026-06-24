from datetime import datetime
from pydantic import BaseModel

class TaskCreate(BaseModel):
    target: str
    scan_type: str = "full"

class TaskResponse(BaseModel):
    id: str
    target: str
    status: str
    progress: int
    created_at: datetime
