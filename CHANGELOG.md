# Changelog

## v1.0 (2026-06-24)

安全加固 + 代码清理 + 功能修复 合并发布。

### 🔴 安全加固 (P0)
- 移除 nginx 容器的 Docker Socket 挂载（容器逃逸风险）
- JWT 密钥从 `.env` 环境变量读取（原硬编码弱密钥）
- 默认管理员密码改为环境变量（原 `yunjing123`）
- Debug 模式关闭（`DEBUG=True` → `False`）
- CORS 限制（`["*"]` → 具体域名）
- Agent 硬编码密码改为环境变量
- MinIO/DB/GoPhish 凭据全部外部化

### 🟠 功能修复 (P1)
- Redis URL 修正（指向 PostgreSQL 端口 → Redis 端口）
- Backend API 认证补充（execution/tasks/notifications/ws）
- Agent API 添加 Basic Auth
- Qdrant 外网端口关闭
- Agent 技能加载修复（模型名统一、DNS 竞争处理）
- Worker 数据库密码同步修复
- 管理员密码哈希同步

### 🟡 代码质量 (P2)
- 命令注入加固（28+ 处 `shell=True` → 参数化执行）
- `learning.py` 排序类型错误修复
- `engine_api.py` 方法名错误修复
- 前后端 API 参数对齐（分页参数统一）
- `except: pass` 清理（部分）
- 死代码/空文件/孤立数字清理

### 🟢 环境清理 (P3)
- 36 个 `fix_*.py` 调试脚本删除
- 11 个 deploy 备份 tar.gz 删除
- 3 份前端目录合并（省 860MB）
- 16 个 macOS `._*` 残留文件删除
- `__pycache__` 全量清理
- `.gitignore` 配置
- Git 初始化

## v0.9-original (2026-05)
云镜AI渗透测试系统初始版本（qwenpaw/大哥 构建）。
