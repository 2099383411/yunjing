# 云镜 2.0 — 剩余任务规划

## 完成情况更新

### ✅ 已完成的
- Phase 1 + Phase 2 全部 5 个任务
- Phase 3: Monitor Agent（任务 6）
- 前端精简 + 页面清理
- gophish 等无用容器清理

### ❌ 未完成的
| # | 任务 | 说明 |
|:-:|:-----|:------|
| 7 | 安全约束层 | Expert/Verify/Scanner/Assault 四种模式的操作边界 |
| 8 | 经验库 + RAG 接入对话 | Qdrant 检索注入 LLM 上下文 |
| 9 | 系统设置完善 | 系统配置 + 个人中心 + 大模型配置 |

---

## 任务 7：安全约束层

**后端改动** — `backend/app/core/config.py`
- 定义一个安全策略字典，约束每种模式能调什么工具

```python
MODE_CONSTRAINTS = {
    "expert": {"allow_tools": False, "prompt": "expert.md"},
    "verify": {"allow_tools": True, "block_payload": True, "confirm_required": False, "prompt": "verify.md"},
    "scanner": {"allow_tools": True, "block_payload": True, "confirm_required": True, "prompt": "scanner.md"},
    "assault": {"allow_tools": True, "block_payload": False, "confirm_required": True, "prompt": "assault.md"},
}
```

**前端联动**
- 当前 chat_stream.py 已按 mode 加载不同的 system prompt
- 安全约束通过 prompt 内容约束 LLM 行为（Expert 模式提示词里写了"你不动任何目标系统"）
- 需要确认 chat_stream.py 中是否根据 mode 过滤了工具调用

**验收标准：**
- [ ] Expert 模式下 LLM 不会调用任何扫描工具
- [ ] Verify 模式只允许轻量探测
- [ ] Scanner 模式高危操作需要确认
- [ ] Assault 模式全量放开

---

## 任务 8：经验库 + RAG

**后端改动** — `backend/app/api/chat_stream.py`
- 每次 LLM 调用前，从 Qdrant 检索相关经验/知识
- 把检索结果注入 system prompt 或 user message 的上下文

```python
# 在 chat_stream() 中，构建 messages 前：
from app.engine.vector_store import RAGEngine
rag = RAGEngine()
experience = rag.search("经验", user_message, limit=3)
knowledge = rag.search("知识库", user_message, limit=3)
if experience:
    context_extra = "基于历史经验：\n" + "\n".join(e["text"] for e in experience)
if knowledge:
    context_extra += "\n相关知识：\n" + "\n".join(k["text"] for k in knowledge)
```

**注意：** Qdrant 容器当前不可用（vector_store.py 有 Warning），需要先确认 RAGEngine 是否能正常工作。

**验收标准：**
- [ ] Qdrant 经验库可检索
- [ ] LLM 回复前自动检索相关知识
- [ ] 检索结果注入上下文
- [ ] 检索不影响响应速度

---

## 任务 9：系统设置完善

### 后端 API

**1. 修改密码**
`backend/app/api/users.py` 新增：
```python
@router.put("/me/password")
async def change_password(data: dict, user: User = Depends(get_current_user)):
    """修改当前用户密码：需要旧密码 + 新密码 × 2"""
    old_pw = data.get("old_password")
    new_pw = data.get("new_password")
    confirm_pw = data.get("confirm_password")
    # 验证旧密码
    # 验证新密码一致性
    # 验证密码复杂度
    # 更新密码
```

**2. 大模型配置**
`backend/app/api/settings_api.py` 新增：
```python
@router.get("/llm-config")
async def get_llm_config():
    """获取当前 LLM 配置"""

@router.put("/llm-config")
async def update_llm_config(data: dict):
    """更新 LLM 配置：provider、model、base_url、api_key"""
```

在 `backend/app/models/settings.py` 或直接在 `.env` 中管理 LLM 配置。

### 前端页面

`frontend/src/pages/SettingsPage.tsx` 改为 3 个 Tab：

**Tab 1：系统设置**
- 系统名称（修改后更新页面标题）
- 登录超时时间（分钟）
- 密码复杂度规则（大小写+数字+特殊字符）

**Tab 2：个人中心**
- 当前用户信息展示（用户名、角色、邮箱等）
- 修改密码表单：
  - 旧密码（input type=password）
  - 新密码（input type=password）
  - 确认新密码（input type=password）
  - 保存按钮

**Tab 3：大模型配置**
- 提供商选择：本地 / DeepSeek / 自定义 OpenAI
- 自定义时输入：base_url、api_key、model name
- 测试连接按钮
- 保存按钮

### 验收标准：
- [ ] 修改系统名称 → 页面标题更新
- [ ] 修改密码 → 旧密码验证、新密码一致性检查
- [ ] 大模型配置 → 可选本地/云端/自定义
- [ ] 所有数据真实写入后端 API，无 mock 数据

---

## 执行顺序

```
T7 安全约束层（0.5天） ← 可以先干，改动小
    ↓
T9 系统设置（1天）    ← 前后端一起
    ↓
T8 经验库+RAG（0.5天）← 需要 Qdrant 先确认可用
```

你审一下这个规划，没问题我就按顺序全部开工。
