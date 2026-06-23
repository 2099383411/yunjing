# 云镜推理引擎原型设计 — v0.2

> 基于 DVWA 靶场实战验证后的修正版
> 新增 9 个实战盲区修复 + 自学习机制章节

---

## 一、概述

### 1.1 设计目标

构建一套 AI 驱动的渗透测试推理引擎，能够从底层原理而非预设模板推导目标资产的脆弱性。

### 1.2 核心原则

- 不依赖 CVE 库/签名库
- 从信任假设推导攻击方向
- 实战验证修正理论盲区
- **自学习：每次渗透后复盘进化**

---

## 二、总体架构

```
┌────────────────────────────────────────────┐
│             推理引擎 (Inference Engine)       │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐   │
│  │ 感知层   │→│ 假设推导  │→│ 验证执行  │   │
│  │ Layer 1 │  │ Layer 2-3│  │ Layer 3  │   │
│  └─────────┘  └──────────┘  └──────────┘   │
│       │            │              │          │
│       ▼            ▼              ▼          │
│  ┌──────────────────────────────────────┐   │
│  │         攻击路径组合 (Layer 4)         │   │
│  └──────────────────────────────────────┘   │
│       │                                      │
│       ▼                                      │
│  ┌──────────────────────────────────────┐   │
│  │     自学习引擎 (复盘→模式提取→进化)    │   │  ← NEW
│  └──────────────────────────────────────┘   │
└────────────────────────────────────────────┘
```

---

## 三、四层推理链（实战修正版）

### 3.1 Layer 1: 目标感知层

**不变**：nmap + curl + gobuster + whatweb 等工具采集目标信息。

**【v0.2 新增】安全配置标识提取**
- 从侦察结果中主动提取：`security=low` cookie、php.ini 关键配置、debug 模式标记
- 提取的标识作为 Layer 2 所有假设置信度的调整因子
- 例如 `security=low` → 所有注入类假设置信度 +0.3
- 例如 `allow_url_fopen=On` → RFI 假设置信度 +0.4

**【v0.2 新增】备份文件自动检查**
- 自动检查常见备份后缀：`.bak`, `.old`, `.swp`, `~`, `.save`, `.dist`
- 备份文件暴露直接提升信息泄露假设置信度

**【v0.2 新增】关键配置文件自动提取**
- 自动检测并提取：`php.ini`, `config.inc.php`, `wp-config.php`, `.env`, `robots.txt`
- 提取的关键配置项自动注入到后续假设生成

### 3.2 Layer 2: 信任假设层

**不变**：从知识库 Level 1 文档提取信任假设。

**【v0.2 新增】环境感知适配**
- 根据目标环境（容器/Docker/物理机/虚拟机）调整假设参数
- 容器环境 → 路径遍历需要更多 `../`
- Docker → 自动加测容器逃逸假设

**【v0.2 修正】假设优先级排序（v0.1→v0.2）**

原算法：`w₁×confidence + w₂×impact - w₃×effort`

新算法：
```
S(H) = w₁×C₀ + w₂×I + w₃×D(H) - w₄×E(H) + w₅×U(H)
```

新增参数：
- `D(H)` = 前置依赖收益 — 该假设确认后能为多少后续假设解锁条件
- `U(H)` = 环境适配因子 — 当前环境对该假设的倾向度
- `C₀` 初始置信度，受安全配置标识调整

### 3.3 Layer 3: 攻击方向验证层

**【v0.2 重大修正】状态机从线性改为树形**

原状态机：
```
hypothesized → testing → confirmed | refuted
```

新状态机（v0.2）：
```
hypothesized
  ↓
[前置条件检查] ← NEW
  ├─ 需要前置条件? → 执行预处理步骤
  │   ├─ 需要CSRF token? → 获取token
  │   ├─ 需要已登录? → 执行H2（默认凭据）
  │   └─ 路径差异? → 执行路径探测
  └─ 无需前置条件? → 直接进入验证
  ↓
testing(变体1)
  ├─ confirmed ✅ → 记录证据，进入路径组合
  └─ refuted ❌ → testing(变体2) ← NEW
       ├─ confirmed ✅ → 记录证据
       └─ refuted ❌ → testing(变体3)
            └─ ... (直到所有变体耗尽)
  ↓
[审计追踪] ← NEW
  记录所有尝试过的变体 + 结果 + 证据
```

**【v0.2 新增】验证变体优先级**

每个攻击方向有多个验证变体，按以下优先级执行：

| 优先级 | 变体 | 示例 |
|-------|------|------|
| 1 | 标准形式 | `../etc/passwd` |
| 2 | 编码形式 | `php://filter/convert.base64-encode/resource=` |
| 3 | 变形 | `..%252f..%252f` (双重编码) |
| 4 | 协议切换 | `file:///etc/passwd` |
| 5 | 桩函数 | 特定工具支持的其他变体 |

### 3.4 Layer 4: 攻击路径组合层

**不变**：将已确认的假设按依赖关系组合为攻击路径。

**【v0.2 新增】路径置信度计算**

```
P(path) = Π C(Hᵢ) × f(dependency_depth)
```

- `C(Hᵢ)` = 路径中每个假设的置信度
- `f(dependency_depth)` = 路径越深，整体置信度适当衰减

**【v0.2 新增】暴露点交叉关联**
- 检查已确认的假设之间是否存在「协同效应」
- LFI + Command Injection = Log Poisoning RCE
- CSRF + XSS Stored = 会话劫持
- SQLi + 文件写入 = WebShell 写入

---

## 四、状态机详细设计（v0.2）

### 4.1 状态定义

| 状态 | 说明 | v0.1→v0.2变更 |
|------|------|--------------|
| `hypothesized` | 假设已生成，待验证 | - |
| `preprocessing` | **NEW**：执行前置条件检查 + 预处理 | 新增 |
| `testing` | 正在验证 | - |
| `testing_variant` | **NEW**：正在验证第N个变体 | 原 testing 细化 |
| `confirmed` | 假设验证成功 | - |
| `refuted` | 所有变体均失败 | 语义变更：一个变体失败≠全方向失败 |
| `blocked` | 无法验证（权限/工具不足） | - |
| `integrated` | **NEW**：已验证假设被整合进攻击路径 | 新增 |

### 4.2 状态转换规则

```
hypothesized
  → preprocessing (自动，新增)
  → blocked (前置条件无法满足)

preprocessing
  → testing (前置条件满足)
  → blocked (前置条件不可达)

testing
  → confirmed (变体成功)
  → testing_variant (变体失败，下一个)
  → blocked (所有工具均不可用)

testing_variant
  → confirmed (当前变体成功)
  → testing_variant (当前变体失败，还有未试变体)
  → refuted (所有变体均失败)

confirmed
  → integrated (自动，进入路径组合)
  → reevaluating (**NEW**：新证据影响该假设)

refuted
  → reevaluating (新环境/新工具使假设复活)

integrated
  → archived (路径已固定)
```

---

## 五、知识库映射改进

**【v0.2 新增】配置 → 假设映射**

Layer 1 提取的关键配置项直接映射到信任假设：

| 配置项 | 值 | 影响的假设 | 置信度调整 |
|--------|-----|-----------|-----------|
| `magic_quotes_gpc` | Off | TA-WEB-08 (SQL注入) | +0.3 |
| `allow_url_include` | On | TA-PHP-01 (RFI) | +0.5 |
| `disable_functions` | 无限制 | TA-PHP-02 (RCE) | +0.4 |
| `security` cookie | low | 所有注入类 | +0.3 |
| `.bak` 文件存在 | Yes | 信息泄露 | +0.4 |
| Directory Listing | On | 信息泄露 | +0.3 |

---

## 六、自学习机制（全新章节）

> 这是将云镜从「静态推理引擎」升级为「进化型AI渗透助理」的关键设计

### 6.1 自学习循环

```
渗透完成
  ↓
复盘分析 (Post-Mortem Analysis)
  ├─ 回顾: 哪些假设成功了? 哪些失败了? 为什么?
  ├─ 提取: 关键证据、环境特征、工具表现
  └─ 记录: 攻击路径、耗时、误报率
  ↓
模式提取 (Pattern Mining)
  ├─ 新发现的环境特征映射
  ├─ 新的攻击模式
  └─ 暴露点交叉利用记录
  ↓
置信度更新 (Confidence Update)
  ├─ 成功假设: 置信度提升
  ├─ 失败假设: 置信度降低
  └─ 新发现假设: 置信度初始化
  ↓
知识库更新 (Knowledge Base Update)
  ├─ Level 2 案例库添加新案例
  ├─ 模式库更新
  └─ 经验规则沉淀
```

### 6.2 案例库结构

每次渗透完成后，自动生成一个结构化案例：

```yaml
case:
  id: "CASE-2026-06-04-001"
  target:
    type: web_application
    os: "Debian 9 (Docker)"
    web_server: "Apache 2.4.25"
    runtime: "PHP 7.0.30"
    database: "MariaDB 10.1 (MySQL)"
    framework: "DVWA v1.10"
  hypotheses:
    confirmed:
      - id: "H1"  # SQL注入
        confidence: 1.0
        evidence: "UNION SELECT user(),database() → app@localhost"
        impact: "critical"
      - id: "H5"  # 命令注入
        confidence: 1.0
        evidence: "WebShell at /shell.php, uid=www-data"
        impact: "critical"
      # ... 其余17个确认假设
    refuted:
      - id: "H1-LOGIN"  # 登录SQLi
        reason: "CSRF token pre-checks blocked direct injection"
    partial:
      - id: "H4"  # File Upload
        reason: "CSRF protection, needs multi-step bypass"
  patterns:
    - pattern_id: "P-HPID"  # PHP信息泄露模式
      trigger: "php.ini exposed + .bak file + directory listing"
      recommendations: ["auto-increase config-exposure checks"]
  attack_paths:
    main: "admin/password → CMD Injection → WebShell → MySQL dump"
    alternative: "admin/password → SQLi → user table dump → MD5 crack"
  stats:
    total_hypotheses: 19
    confirmed: 11
    refuted: 6
    partial: 2
    hit_rate: 57.9%
    time_spent_min: 20
```

### 6.3 置信度自适应算法

初始置信度基于理论知识库计算。每完成一次渗透，自动调整：

```
C(H, n+1) = C(H, n) + α × (R - C(H, n))

其中：
- C(H, n) = 假设H在第n次渗透时的置信度
- α = 学习率 (0.1～0.3，根据案例质量)
- R = 本次结果 (1=成功, 0=失败, 0.5=部分成功)
```

**学习率衰退机制**：
- 前 10 次案例：α = 0.3（快速学习）
- 10～50 次案例：α = 0.1（稳定收敛）
- 50+ 次案例：α = 0.05（微调）

### 6.4 模式库（自动提炼）

模式是从多个案例中自动提取的通用攻击模式：

| 模式ID | 模式名称 | 触发条件 | 动作 | 来源案例数 |
|--------|---------|---------|------|-----------|
| P-01 | PHP 信息泄露组合 | php.ini暴露 + directory listing + .bak | 自动提取所有配置+凭据 | 1 |
| P-02 | 容器双网卡横向 | Docket多网络接口 + RCE | 自动扫描邻接网络 | 1 |
| P-03 | LFI + CMD Injection | LFI已确认 + CMD已确认 | 推荐Log Poisoning RCE | 1 |

### 6.5 暴露点交叉利用率

记录哪些暴露点组合产生了有效攻击路径：

```
交叉利用率矩阵 (Cross Utilization Heatmap):

             默认凭据  SQL注入  命令注入  LFI   CSRF   XSS
  默认凭据       -      0.8     0.9    0.7    0.6    0.5
  SQL注入      0.8       -     0.7    0.5    0.3    0.2
  命令注入     0.9     0.7       -    0.8    0.4    0.3
  LFI          0.7     0.5     0.8      -    0.2    0.1
  CSRF         0.6     0.3     0.4    0.2      -    0.7
  XSS          0.5     0.2     0.3    0.1    0.7      -
```

- 值越高表示这两个暴露点组合攻击的效率越高
- 默认凭据 → 命令注入 = 0.9（常配合使用）
- CSRF → XSS = 0.7（会话劫持常见）

### 6.6 知识库自动扩展

自学习机制最终会更新知识库：

- **成功案例** → 自动写入 Level 2 案例库
- **新模式** → 如果 3 次以上复现，升级为 Level 1 攻击面文档更新
- **失败假设** → 标记为「低效路径」，后续排序降低优先级
- **新攻击方向** → 若多次成功，建立新的知识库映射

---

## 七、实战验证总结（基于 DVWA 测试）

### 7.1 验证结果

| 指标 | v0.1 预期 | v0.2 实际 | 差距 |
|------|-----------|-----------|------|
| 入侵点发现 | 未定义 | 45 个 | - |
| 假设命中率 | 未定义 | 57.9% (11/19) | 基线值 |
| 最高权限 | 未定义 | RCE (www-data) | 基线值 |
| Layer 1→4 可行性 | 理论可行 | ✅ 全部验证通过 | - |

### 7.2 v0.1→v0.2 新增/修正内容总览

| 变化 | 类型 | 来源 |
|------|------|------|
| 安全配置标识提取 | 新增 | 实战发现：php.ini + security cookie |
| 备份文件自动检查 | 新增 | 实战发现：config.inc.php.bak 泄露凭据 |
| 关键配置文件自动提取 | 新增 | 实战发现：php.ini 暴露关键配置 |
| 前置条件检查 | 修正 | 实战发现：CSRF token 阻止直接注入 |
| 假设排序算法扩展 | 修正 | 实战发现：H2登录应优先解锁后续 |
| 状态机树形化 | 修正 | 实战发现：php://filter 作为LFI变体 |
| 验证变体优先级 | 新增 | 实战发现：分号注入>管道>后台执行 |
| 路径置信度计算 | 新增 | 实战发现：多路径组合需量化可信度 |
| 暴露点交叉关联 | 新增 | 实战发现：LFI+CMD=Log Poisoning RCE |
| 环境感知适配 | 新增 | 实战发现：容器路径差异 |
| 自学习机制 | 全新章节 | 老板需求：越渗透越聪明 |

### 7.3 仍需验证的领域

| 领域 | 验证状态 | 计划 |
|------|---------|------|
| 多网卡横向移动 | ⚠️ 待验证 | 本次继续渗透中验证 |
| 容器逃逸 | ⚠️ 待验证 | 本次继续渗透中验证 |
| 提权到 root | ⚠️ 待验证 | 本次继续渗透中验证 |
| 自学习循环实现 | ❌ 未验证 | 需要多个渗透案例积累 |
