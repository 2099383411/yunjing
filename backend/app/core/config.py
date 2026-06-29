"""云镜项目配置 — 所有 IP、端口、密码等默认值统一管理"""

import os
from typing import List


class TargetDefaults:
    """渗透测试目标和服务器的默认配置

    所有值优先从环境变量读取，不存在则使用代码内置默认值。
    部署时通过 .env 或 docker-compose environment 注入。
    """

    # ── 本地渗透测试目标 ──
    DEFAULT_TARGET_HOST: str = os.getenv("YJ_TARGET_HOST", "192.168.1.180")
    DEFAULT_TARGET_PORT: int = int(os.getenv("YJ_TARGET_PORT", "8080"))
    DEFAULT_TARGET_URL: str = f"http://{DEFAULT_TARGET_HOST}:{DEFAULT_TARGET_PORT}"

    # ── 本机网络 ──
    LOCAL_IPS: list[str] = os.getenv("YJ_LOCAL_IPS", "192.168.1.180").split(",")
    DEFAULT_SUBNET: str = os.getenv("YJ_SUBNET", "192.168.1.0/24")

    # ── 回连监听 ──
    CALLBACK_HOST: str = os.getenv("YJ_CALLBACK_HOST", DEFAULT_TARGET_HOST)
    CALLBACK_PORT: int = int(os.getenv("YJ_CALLBACK_PORT", "4444"))

    # ── 钓鱼服务器 ──
    PHISHING_BASE_URL: str = os.getenv("YJ_PHISHING_URL", f"https://{DEFAULT_TARGET_HOST}:3333")

    # ── 默认凭据猜测 ──
    DEFAULT_USERNAMES: list[str] = os.getenv("YJ_USERNAMES",
                                            "root,admin,administrator,user,test").split(",")
    DEFAULT_PASSWORDS: list[str] = os.getenv("YJ_PASSWORDS",
                                              "123456,admin,password,root,test,admin123").split(",")

    # ── 默认 root 凭据（内网常见默认值） ──
    ROOT_USERNAME: str = os.getenv("YJ_ROOT_USER", "root")
    ROOT_PASSWORD: str = os.getenv("YJ_ROOT_PASS", "123456")


targets = TargetDefaults()
