# RedAmon 源码深度分析 — 取精华去糟粕

> 来源：https://github.com/samugit83/redamon (v4.14.0, 2k+ stars)
> 分析日期：2026-06-05

---

## 一、架构总览

### 1.1 RedAmon 的全貌

```
┌──────────────────────────────────────────────────────────────────┐
│    RedAmon 完整架构                                               │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  用户输入 (域名/IP)                                                │
│     │                                                             │
│     ▼                                                             │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              6阶段侦察管道 (Recon Pipeline)                │   │
│  │  子域名发现 → 端口扫描 → HTTP探测 → 资源枚举 → 漏洞扫描 → MITRE │   │
│  │  (Subfinder) (Naabu) (httpx) (Katana/GAU) (Nuclei)  富化  │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                         │
│                         ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │            Neo4j 攻击路径知识图谱 (Graph Database)          │   │
│  │  22+ 节点类型 · Domain→Subdomain→IP→Port→Service→Vuln→Exploit │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                         │
│                         ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │      AI Agent 编排器 (LangGraph 状态机)                   │   │
│  │                                                          │   │
│  │  initialize → think → execute_tool/execute_plan          │   │
│  │              → deploy_fireteam → fireteam_collect        │   │
│  │              → await_approval → generate_response        │   │
│  └──────────────────────┬───────────────────────────────────┘   │
│                         │                                         │
│                         ▼                                         │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │       CypherFix (自动修复管道)                             │   │
│  │   漏洞去重 → 排序 → 克隆代码 → 修复 → 提PR                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  支持: 400+ AI模型  ·  70+ 工具  ·  185k+ 检测规则                │
│        Ollama/vLLM/LM Studio 本地部署  ·  全Docker化              │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 目录结构（核心代码）

```
redamon/
├── agentic/               ← AI Agent 核心（我们要学的）
│   ├── orchestrator.py    ← 75KB, LangGraph状态机编排器
│   ├── state.py           ← AgentState 定义 + Pydantic 模型
│   ├── tools.py           ← 工具管理（MCP/Neo4j/WEB）
│   ├── prompts/           ← 提示词工程
│   ├── skills/            ← 46个技能参考文档（/skill ssrf 注入）
│   ├── community-skills/  ← 社区贡献技能
│   ├── orchestrator_helpers/ ← 各节点的实现函数
│   └── fireteam_member_graph.py ← 多Agent并行图
│
├── graph_db/              ← Neo4j 图数据库（我们最该学的）
│   ├── schema.py          ← 22+节点类型的约束定义
│   ├── neo4j_client.py    ← 客户端（多继承mixin模式）
│   └── mixins/
│       ├── base_mixin.py       ← 连接生命周期
│       ├── recon_mixin.py      ← 侦察子图（组合模式）
│       └── recon/
│           ├── domain_mixin.py  ← 域名发现
│           ├── port_mixin.py    ← 端口扫描
│           ├── http_mixin.py    ← HTTP探测
│           ├── vuln_mixin.py    ← 漏洞+CVE+Exploit
│           ├── resource_mixin.py← 资源枚举
│           └── user_input_mixin.py ← 用户输入
│
├── knowledge_base/        ← 知识库
│   ├── kb_orchestrator.py ← 知识库编排器
│   ├── document_store.py  ← 文档存储
│   ├── embedder.py        ← 向量嵌入
│   ├── faiss_indexer.py   ← FAISS向量索引
│   └── reranker.py        ← 重排序
│
├── recon/                 ← 侦察工具自动化
├── recon_orchestrator/    ← 侦察管道调度
├── webapp/                ← Web界面
└── mcp/                   ← MCP工具注册
```

---

## 二、精华部分（值得学的）

### 2.1 🥇 Neo4j 攻击路径图（直接可迁移）

RedAmon 的 Neo4j 设计是最大亮点。它的节点定义了完整的攻击路径：

```
节点类型（22+种）：
Domain → Subdomain → IP ↔ DNSRecord
    ↓          ↓        ↓
  Certificate   IP    Port → Service → Technology
                          ↓
                      BaseURL → Endpoint → Parameter / Header
                          ↓
                      Vulnerability → CVE → CWE → CAPEC → MitreData
                          ↓
                      Exploit → ExploitGvm

关系类型（关键路径）：
(Domain)-[:HAS_SUBDOMAIN]->(Subdomain)
(Subdomain)-[:RESOLVES_TO]->(IP)
(IP)-[:HAS_PORT]->(Port)
(Port)-[:RUNS_SERVICE]->(Service)
(Service)-[:HAS_URL]->(BaseURL)
(BaseURL)-[:HAS_ENDPOINT]->(Endpoint)
(Endpoint)-[:HAS_PARAMETER]->(Parameter)
(Vulnerability)-[:EXPLOITED_BY]->(Exploit)
(CVE)-[:HAS_CAPEC]->(Capec)
(Finding)-[:HAS_CVE]->(CVE)
```

**迁移到我们的价值**：这个图模型可以直接复用。我们只需要把 Domain→IP→Port→Service 这条轴换成我们更关注的 资产→端口→服务→漏洞 结构。

### 2.2 🥇 LangGraph 状态机模型

用 LangGraph 实现的状态驱动 Agent 编排：

```
状态节点（12个）：
initialize → think → execute_tool → execute_plan
                        → deploy_fireteam → fireteam_collect
                        → await_approval → process_approval
                        → await_question → process_answer
                        → await_tool_confirmation → process_tool_confirmation
                        → generate_response

状态转换逻辑：
think → 路由决策（根据LLM输出决定下一步）
execute_tool → 直接回 think（结果合并到思考节点）
execute_plan → 直接回 think
deploy_fireteam → fireteam_collect → think 或 await_tool_confirmation
```

**关键设计**：`execute_tool` 执行完后直接回到 `think`，工具结果和思考合并到一个节点。这避免了额外的LLM调用（省token）。

### 2.3 🥇 Fireteam 多Agent并行

```
deploy_fireteam:
  ┌── Agent 1 (Web侦察) ──┐
  ├── Agent 2 (端口扫描) ──┤  ← 并行执行
  ├── Agent 3 (凭据测试) ──┤
  └── Agent 4 (CVE匹配) ───┘
           ↓
fireteam_collect: 汇总结果
           ↓
process_fireteam_confirmation: 人工确认+转发
```

每个成员 Agent 跑同一个 `fireteam_member_graph`，但上下文不同。

### 2.4 🥇 多Mixin 的 Neo4j 客户端设计

```python
class Neo4jClient(BaseMixin, ReconMixin, GvmMixin, SecretMixin, OsintMixin, GraphQLMixin):
    pass  # 所有方法由 mixin 提供
```

**6 个 mixin 组合模式**，每个 mixin 负责一个领域的数据操作。比单一大类好维护。

### 2.5 ✅ 攻击路径分类策略

```
已知攻击路径: cve_exploit, brute_force_credential_guess, 
             phishing_social_engineering, sql_injection, xss, ssrf, rce...
             
未分类路径: "file_upload-unclassified", "xxe-unclassified"
```

允许新攻击类型出现时走 `-unclassified` 后缀，不至于系统崩溃。

---

## 三、糟粕部分（不该学的）

### 3.1 ❌ 过度依赖扫描工具

RedAmon 本质上是 **「用AI编排Nuclei+Naabu等工具」**，而不是「从原理推导脆弱性」。

```
我们的路径：理解原理 → 推导假设 → 验证 → 学习
RedAmon：  跑工具 → 看结果 → 跑下一个工具
```

RedAmon 的"智能"在调度，不在理解。这跟我们的核心哲学冲突。

### 3.2 ❌ 全自动化失去上下文

```
RedAmon: 扔IP进去 → 等结果出来 → 拿修复PR
我们: 对话引导 → LLM推理 → 人机协作 → 知识积累
```

渗透测试需要上下文理解、低概率事件的判断、和不完全信息的决策。全自动化会丢失这些。

### 3.3 ❌ 无知识库层次化

RedAmon 的 `knowledge_base` 只是文档向量库（skill注入），没有我们的 **Level 0→1→2 层次化知识体系**。

```
他们: 技能文档 → 向量化 → 注入到对话
我们: 底层原理 → 攻击面推导 → 案例融合 → 自学习
```

### 3.4 ❌ 无自学习机制

RedAmon 跑完一个项目后，Neo4j 数据可以留着查询，但 **不会从渗透中学习新知识**。每次渗透都是独立的。

```
他们: 数据保留在Neo4j，但不提炼成知识
我们: (设计) 每次渗透 → 复盘 → 提炼新模式 → 更新知识库
```

### 3.5 ❌ 英语优先 + 中文不友好

全英文文档、英文输出。对国内客户不友好。

### 3.6 ⚠️ LangGraph 锁定了 LangChain 生态

RedAmon 深度绑定 LangGraph/LangChain，换框架成本高。我们应该保持框架无关性。

---

## 四、我们能直接用的设计

### 4.1 Neo4j 图模型（迁移后）

```
我们版本的节点类型：

Asset (主机/Docker/VM)
  ├── Port (22/80/443/6379/13577)
  │   └── Service (SSH/HTTP/Redis/Everything)
  │       ├── Vulnerability (CVE/弱口令/信息泄露)
  │       └── Credential (user/pass/key)
  ├── Container (Docker/K8s)
  │   └── Image (名称/版本)
  │       └── PortMapping (宿主机:容器)
  └── Network (192.168.1.0/24 / 172.18.0.0/16 / 10.20.0.0/24)
      └── Route (默认路由/静态路由)
          └── Gateway (NSG/ZTE/MikroTik)

关系：
(Asset)-[:HAS_PORT]->(Port)
(Port)-[:RUNS_SERVICE]->(Service)
(Service)-[:HAS_VULN]->(Vulnerability)
(Service)-[:HAS_CRED]->(Credential)
(Credential)-[:RESUSED_ON]->(Asset)  ← 密码复用
(Asset)-[:INSIDE_NET]->(Network)
(Network)-[:ROUTES_TO]->(Network)    ← 网络拓扑关系
(Vulnerability)-[:LEADS_TO]->(AttackPath)  ← 攻击路径
(AttackPath)-[:USES]->(Asset)        ← 路径上的资产
```

### 4.2 状态机设计（可参考）

我们 v0.2 的树形状态机，可以结合 LangGraph 的 `StateGraph` 概念：

```
我们的四层推理链 → LangGraph状态

Layer 1 (感知):      Initialize → Discover → Map
Layer 2 (假设):       GenerateHypothesis → Prioritize
Layer 3 (验证):       TestHypothesis → Confirm/Refute → Refine
Layer 4 (路径组合):   CombinePaths → ExecuteChain → Report
```

### 4.3 Fireteam 概念的多Agent

我们可以在子任务上部署并行 Agent（如同时扫端口+扫Web+查凭据），而不是单线程执行。

---

## 五、最终结论

| 项目 | RedAmon | 我们 | 建议 |
|:----|:--------|:-----|:------|
| 核心理念 | 工具AI调度 | 从原理推导 | 各取所长 |
| Neo4j 图模型 | ✅ 22+节点 | ❌ 暂无 | **直接迁移** |
| LangGraph状态机 | ✅ 12节点 | ⚠️ v0.2设计 | 参考不照搬 |
| 自学习 | ❌ 无 | ✅ v0.2设计 | 我们领先 |
| 知识体系 | ❌ 平铺文档 | ✅ 三层结构 | 我们领先 |
| 多Agent | ✅ Fireteam | ❌ 单Agent | 借鉴实现 |
| 自动化程度 | 全自动 | 人机协作 | 保持差异 |
| 模型支持 | 400+ | 1个 | 学习其模型无关架构 |
| 自动修复 | ✅ 提PR | 仅报告 | 暂不需要 |
| 中文 | ❌ | ✅ | 保持优势 |
