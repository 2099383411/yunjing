import httpx
from app.config import settings

class AgentService:
    def __init__(self):
        self.base_url = settings.AGENT_SERVICE_URL

    async def chat(self, session_id: str, message: str, history: list[dict] = None):
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{self.base_url}/chat", json={
                "session_id": session_id, "message": message, "history": history or []
            })
            return resp.json()

    async def chat_stream(self, session_id: str, message: str, history: list[dict] = None):
        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream("POST", f"{self.base_url}/chat/stream", json={
                "session_id": session_id, "message": message, "history": history or []
            }) as resp:
                async for chunk in resp.aiter_bytes():
                    yield chunk

agent_service = AgentService()
