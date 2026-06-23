# 云镜 (YunJing) — AI 驱动的渗透测试系统

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/react-18-blue.svg)](https://reactjs.org)

> **AI-Powered Penetration Testing Engine** — 让 LLM 像渗透测试工程师一样思考、决策、行动。

云镜是一个基于大语言模型（LLM）的自动化渗透测试系统。它不只是一个"调用工具的脚本"，而是实现了完整的**感知→推理→决策→执行→复盘**闭环，让 AI 真正充当渗透测试工程师的角色。

## 🎯 它做了什么

传统安全扫描工具（Nmap、Nuclei、SQLMap）各有各的强项，但需要**人来串联**——先扫什么、再查什么、某个端口开了下一步做什么——这些决策依赖经验。云镜做的事就是**把人的经验交给 AI**：

1. **感知层** — 全端口扫描 + 服务版本探测，摸清目标全貌
2. **推理引擎** — LLM 根据当前状态决定下一步执行什么（不是写死的 if-else）
3. **决策执行** — 调用真实安全工具（sqlmap、hydra、nikto、nuclei 等 20+ 种）
4. **经验回流** — 每次执行结果自动蒸馏，存入经验库，下次遇到类似场景直接命中
5. **报告生成** — 一键输出 Word / Excel / HTML / PDF 四种格式

## 🏗 架构

```
┌──────────────────────────────────────────── ───┐
│                   前端 (React)                    │
│    ChatPage | Dashboard | 推理引擎 | 攻击面       │
└──────────────────┬──────────────────────────── ──┘
                   │ WebSocket + REST API
┌──────────────────▼──────────────────────────────┐
│                后端 (FastAPI)                     │
│  任务调度 | RAG 检索引擎 | WebSocket 推送 | 报告  │
└──────────────────┬──────────────────────────────┘
                   │ Celery + Redis
┌──────────────────▼──────────────────────────────┐
│               Worker (Celery)                     │
│  PTES 7 阶段执行 | 工具调用 | 经验蒸馏 | 复盘     │
└──────────────────┬──────────────────────────────┘
                   │ Docker
┌──────────────────▼──────────────────────────────┐
│              工具容器 (Sandbox)                    │
│  nmap | sqlmap | hydra | nuclei | nikto | ...    │
└─────────────────────────────────────────────────┘

知识库层（双库架构）:
┌──────────────────┐  ┌──────────────────┐
│   知识库 (静态)    │  │  经验库 (动态)     │
│  OWASP / CVE /   │  │  扫描记录自动蒸馏   │
│  Payloads / Wiki │  │  越用越聪明        │
└──────────────────┘  └──────────────────┘
         │                      │
         └──────┬───────────────┘
                ▼
         Qdrant / BGE 向量检索
```

## ✨ 核心特性

| 模块 | 说明 |
|:-----|:-----|
| 🔍 **感知层** | Nmap 全端口 TCP 扫描 + 服务版本探测 |
| 🧠 **推理引擎** | LLM 驱动决策循环，非固定流程 |
| ⚔️ **工具编排** | 动态调用 20+ 种渗透工具，按需选择 |
| 🗄️ **双库 RAG** | 知识库（OWASP/CVE/Payload）+ 经验库（自动蒸馏） |
| 🔁 **经验回流** | 扫描结果自动提取可复用经验 |
| 📊 **四格式报告** | Word / Excel / HTML / PDF 一键导出 |
| 💬 **Chat 界面** | 左对话 + 右攻击进度可视化 |
| 🐳 **Docker 部署** | 全容器化，docker-compose up 一键启动 |

## 🚀 快速开始

### 环境要求
- Docker & Docker Compose
- 16GB+ 内存（含 LLM 推荐 32GB）
- 可选：GPU（用于本地 BGE 向量模型推理）

### 1. 克隆项目
```bash
git clone https://github.com/weijingyu/yunjing.git
cd yunjing
```

### 2. 配置 LLM
```bash
cp .env.example .env
# 编辑 .env，填入 DeepSeek / OpenAI API Key
```

### 3. 下载知识库（可选）
```bash
bash build.sh --download-kb  # 下载 OWASP / PayloadsAllTheThings 等知识库
```

### 4. 启动
```bash
docker-compose up -d
```

访问 `http://localhost` 进入 Web 界面，默认账号 `admin / admin123`。

## 🛠 技术栈

| 层 | 技术 |
|:---|:-----|
| **前端** | React 18 + Ant Design + TypeScript |
| **后端** | Python 3.12 + FastAPI + SQLAlchemy Async |
| **Worker** | Celery + Redis |
| **数据库** | PostgreSQL + Qdrant（向量） |
| **嵌入模型** | BGE-M3 / BGE-Large-ZH |
| **LLM** | DeepSeek / OpenAI / 本地 Ollama |
| **渗透工具** | Nmap, SQLMap, Hydra, Nuclei, Nikto, Gobuster, FFUF, John, Metasploit... |
| **部署** | Docker Compose + Nginx |

## 📁 项目结构

```
yunjing/
├── backend/           # FastAPI 后端
│   ├── app/
│   │   ├── api/       # REST API（任务、推理、报告、WS）
│   │   ├── engine/    # RAG 检索引擎 + 经验蒸馏
│   │   ├── grounding/ # 感知层（被动信息收集）
│   │   ├── models/    # SQLAlchemy 模型
│   │   └── services/  # 工具调用 + 扫描编排
│   └── alembic/       # 数据库迁移
├── frontend/          # React 前端
│   └── src/pages/     # 页面（Chat、Dashboard、推理引擎等）
├── worker/            # Celery Worker
│   └── app/tasks/     # 扫描任务 + 经验蒸馏
├── agent/             # 辅助 Agent
├── nginx/             # Nginx 配置
└── docker-compose.yml # 容器编排
```

## 🤝 贡献

这是一个**半成品项目**，能跑通，但很多地方还很粗糙。非常欢迎任何形式的贡献：

- 🐛 修复 Bug
- ✨ 添加新功能（新的渗透测试阶段、新的工具集成）
- 📖 完善文档
- 🎨 优化前端界面
- 🧪 增强稳定性

### 贡献流程
1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## ⚠️ 声明

**本工具仅用于授权的安全测试。使用者需自行承担法律责任。作者不对任何未授权使用造成的后果负责。**

## 📄 许可证

MIT License — 详见 [LICENSE](LICENSE)

## 👤 作者

**信安云科（北京）科技有限责任公司**

- 创始人：魏敬宇
- 项目定位：让 AI 渗透测试从概念走向实用
- 联系邮箱：2099383411@qq.com

---

⭐ 如果这个项目对你有帮助，请给一个 Star！
