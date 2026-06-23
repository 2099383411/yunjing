# 贡献指南

感谢你对云镜项目的关注！这是一个**半成品项目**，核心流程能跑通，但很多地方还需要打磨。以下是当前最需要帮助的方向：

## 🎯 最需要帮助的方向

### 高优先级
| 优先级 | 模块 | 具体问题 |
|:--:|:-----|:-----|
| 🔴 | **经验库** | 经验蒸馏逻辑粗糙，需要更好的经验聚合/去重/泛化算法 |
| 🔴 | **推理决策** | LLM 决策循环偶有重复/摇摆，需要更好的 prompt 工程或状态管理 |
| 🔴 | **测试覆盖** | 几乎没有自动化测试，需要加单元测试和集成测试 |
| 🟡 | **报告生成** | 报告模板不够专业，需要更好的排版和数据可视化 |
| 🟡 | **Session 管理** | 后渗透 Session 生命周期管理不完善 |
| 🟡 | **前端体验** | 部分页面有 loading 状态处理问题，暗色模式不完整 |

### 功能增强
| 方向 | 说明 |
|:-----|:-----|
| 🔧 **更多工具集成** | 支持 Burp Suite 联动、Dirb、WPScan 等 |
| 📱 **移动端适配** | ChatPage 在手机端体验差 |
| 🌐 **国际化** | 当前只有中文，需要英文支持 |
| 📊 **Dashboard** | 增加扫描统计、趋势图表 |
| 🔒 **多租户** | 支持多用户隔离 |

## 🚀 开发环境搭建

```bash
# 后端
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 前端
cd frontend
npm install
npm run dev  # 开发模式

# Worker
cd worker
pip install -r requirements.txt
celery -A app.celery_app worker --loglevel=info
```

## 📝 代码规范

- Python: 遵循 PEP 8，类型标注
- TypeScript: 使用项目已有的 ESLint 配置
- 提交信息: 使用中文，格式 `[模块] 简短描述`
- PR 需要在描述中说明改了什么、为什么这样改

## 🤝 行为准则

- 友善讨论，不人身攻击
- PR Review 对事不对人
- 新手友好，欢迎提问
