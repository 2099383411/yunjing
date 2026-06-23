from pydantic import BaseModel

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str
    history: list[ChatMessage] = []

class ChatResponse(BaseModel):
    session_id: str
    reply: str
    tool_calls: list[dict] = []
