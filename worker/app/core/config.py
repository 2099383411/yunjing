"""Worker 配置模块 — 硬编码治理"""
from pydantic_settings import BaseSettings


class TargetSettings(BaseSettings):
    """目标/网络配置，从 .env 读取（前缀 YJ_）"""
    DEFAULT_SUBNET: str = "192.168.1.0/24"
    ROOT_USERNAME: str = "root"
    ROOT_PASSWORD: str = "123456"

    model_config = {"env_prefix": "YJ_", "env_file": ".env", "extra": "allow"}


targets = TargetSettings()
