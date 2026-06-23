"""LLM 统一适配器（支持从 DB 动态读取 API Key）"""
from openai import AsyncOpenAI
from app.config import settings

class LLMAdapter:
    def __init__(self):
        self._client = None
        self._api_key = settings.LLM_API_KEY
        self._base_url = settings.LLM_API_BASE
        self._model = settings.LLM_MODEL

    async def _ensure_client(self):
        """从 DB 加载 API Key，确保 client 最新"""
        try:
            from sqlalchemy import select
            from app.database import AsyncSessionLocal
            from app.models.setting import SystemSetting
            async with AsyncSessionLocal() as sess:
                result = await sess.execute(
                    select(SystemSetting).where(SystemSetting.key == "llm_api_key")
                )
                row = result.scalar_one_or_none()
                if row and row.value:
                    self._api_key = row.value
                result2 = await sess.execute(
                    select(SystemSetting).where(SystemSetting.key == "llm_api_base")
                )
                row2 = result2.scalar_one_or_none()
                if row2 and row2.value:
                    self._base_url = row2.value
                result3 = await sess.execute(
                    select(SystemSetting).where(SystemSetting.key == "llm_model")
                )
                row3 = result3.scalar_one_or_none()
                if row3 and row3.value:
                    self._model = row3.value
        except Exception:
            pass  # Fall back to env defaults

        if not self._client or self._client.api_key != self._api_key:
            self._client = AsyncOpenAI(api_key=self._api_key, base_url=self._base_url)

    @property
    def model(self):
        return self._model

    async def chat(self, messages: list[dict], tools: list[dict] | None = None,
                   temperature: float | None = None, max_tokens: int | None = None) -> dict:
        await self._ensure_client()
        kwargs = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature or settings.LLM_TEMPERATURE,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
        }
        if tools:
            kwargs["tools"] = tools
        response = await self._client.chat.completions.create(**kwargs)
        return response.model_dump()

    async def chat_stream(self, messages: list[dict], tools: list[dict] | None = None,
                          temperature: float | None = None, max_tokens: int | None = None):
        await self._ensure_client()
        kwargs = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature or settings.LLM_TEMPERATURE,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
            "stream": True,
        }
        if tools:
            kwargs["tools"] = tools
        stream = await self._client.chat.completions.create(**kwargs)
        async for chunk in stream:
            yield chunk.model_dump()

llm_adapter = LLMAdapter()
