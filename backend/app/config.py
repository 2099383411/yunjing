"""应用配置管理"""
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "云镜·安全检测助手"
    APP_VERSION: str = "0.1.0"
<<<<<<< HEAD
    DEBUG: bool = True
    DATABASE_URL: str = "postgresql+asyncpg://yunjing:yunjing_dev_2026@postgres:5432/yunjing"
    REDIS_URL: str = "redis://redis:6379/0"
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
=======
    DEBUG: bool = False
    DATABASE_URL: str = ""  # 必须从 .env 环境变量读取
    REDIS_URL: str = "redis://redis:6379/0"
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = ""
    MINIO_SECRET_KEY: str = ""
>>>>>>> server/master
    MINIO_BUCKET: str = "reports"
    LLM_PROVIDER: str = "deepseek"
    LLM_API_KEY: str = ""
    LLM_API_BASE: str = "https://api.deepseek.com/v1"
    LLM_MODEL: str = "deepseek-chat"
    LLM_MAX_TOKENS: int = 4096
    LLM_TEMPERATURE: float = 0.1
    AGENT_SERVICE_URL: str = "http://agent:8001"
    MAX_CONCURRENT_SCANS: int = 3
    SCAN_TIMEOUT: int = 3600
<<<<<<< HEAD
    CORS_ORIGINS: list[str] = ["*"]
    AUTH_ENABLED: bool = True
    JWT_SECRET: str = "yunjing-jwt-secret-2026-ai"
    JWT_EXPIRE_HOURS: int = 72
=======
    CORS_ORIGINS: list[str] = ["http://localhost", "http://127.0.0.1"]
    AUTH_ENABLED: bool = True
    JWT_SECRET: str = ""
    JWT_EXPIRE_HOURS: int = 4
>>>>>>> server/master
    model_config = {"env_file": ".env", "extra": "allow"}

settings = Settings()
