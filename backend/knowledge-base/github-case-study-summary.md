# GitHub 案例仓库深度分析总结报告

> Level 1: 攻击面 / 学习总结
> 日期：2026-06-05
> 来源：htb-writeups / Offensive-Resources / PayloadsAllTheThings / RedAmon / LLM4Pentest

---

## 一、各仓库核心内容总结

### 1. htb-writeups — 500+ HTB 机器 writeup 大全

**[momenbasel/htb-writeups](https://github.com/momenbasel/htb-writeups)** — 2k+ stars

**内容概览：**

| 类别 | 数量 | 说明 |
|:-----|:----:|:------|
| HTB Machines | **500+** | 覆盖全部活跃+退役机器 |
| Challenges | **400+** | Web/Pwn/Rev/Crypto/Forensics |
| ProLabs | 完整 | Dante/Zephyr/Offshore/Rastalabs/APT |
| Sherlocks (DFIR) | 100+ | 蓝队取证与事件响应 |
| Attack Path Diagrams | 每台都有 | 可视化攻击链，类似我们的攻击面图 |
| Skill Trees | 完整 | 技能树按难度递增排列 |

**最值得学习的分类（按类型）：**

```
Windows 机器 (~150台):
  → AD渗透、Kerberos攻击、Privilege Escalation
  → SMB/RDP/WinRM 横向移动
  → 典型案例：Active/Bastion/Cascade/Sauna

Linux 机器 (~200台):
  → Web漏洞利用、sudo提权、SUID
  → LXD/LXC容器、Docker、Capabilities
  → 典型案例：Traverxec/OpenAdmin/Tabby

Web 挑战 (~200个):
  → SQLi/XSS/SSTI/LFI/SSRF/Deserialization
  → 真实场景中的绕过技巧

AD 专区 (~80台):
  → AS-REP Roasting/Kerberoasting
  → ACL滥用、ACEs、DCSync
  → Resource-Based Constrained Delegation
```

**对我们的价值：**

```
✅ 攻击路径图格式 → 可参考设计我们推理引擎的可视化输出
✅ 多种绕过思路 → 补充我们的 Level 2 案例库
✅ AD渗透路线 → 我们缺乏的域环境经验（未来必用）
```

---

### 2. Offensive-Resources — 30+领域攻击性安全资源大全

**[Zeyad-Azima/Offensive-Resources](https://github.com/Zeyad-Azima/Offensive-Resources)** — 1.1k+ stars

**覆盖的30+领域（按对我们优先级排序）：**

| 优先级 | 领域 | 包含内容 |
|:------:|:------|:---------|
| 🥇 | **Active Directory** | AD攻击、攻击路径、域控攻防、ACLs、Kerberos |
| 🥇 | **Web 安全** | OWASP Top 10、WAF绕过、Payloads、Burp扩展 |
| 🥇 | **网络渗透** | Nmap技巧、端口扫描、服务利用、中间人攻击 |
| 🥇 | **容器安全** | Docker逃逸、K8s渗透、容器运行时安全 |
| 🥇 | **云安全** | AWS/Azure/GCP渗透、IAM滥用、元数据攻击 |
| 🥇 | **红队基础设施** | C2框架(Metasploit/CobaltStrike/Havoc)、域前置 |
| 🥈 | **AI/LLM 安全** | Prompt注入、LLM Jailbreak、RAG安全 |
| 🥈 | **移动安全** | Android/iOS渗透、Frida/Xposed |
| 🥈 | **Wi-Fi/BT 安全** | 无线攻击、蓝牙漏洞 |
| 🥈 | **社会工程** | 钓鱼框架、GoPhish、EvilGinx |
| 🥉 | **OT/ICS 安全** | 工控系统、PLC攻击、SCADA |
| 🥉 | **车联网安全** | CAN总线、车机渗透 |
| 🥉 | **区块链安全** | 智能合约审计、DeFi漏洞 |
| 🥉 | **卫星安全** | 卫星通信、GPS欺骗 |

**Key Takeaway：** 我们的知识库目前覆盖了 Web/网络/Docker/密码学 ≈ 5个领域。还有 **10+个我们不熟悉的领域**，尤其是 AD、云安全、红队C2 这些对渗透测试至关重要。

---

### 3. PayloadsAllTheThings — Web 渗透 Payload 终极手册

**[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** — **62,000+ stars**，2185 commits

**覆盖 60+ 漏洞类别，每个类别包含：**
1. 漏洞原理说明
2. 利用方法
3. Payloads（按场景组织）
4. 绕过技巧
5. 工具推荐
6. 参考链接

**与我们有直接相关的核心类别：**

| 类别 | 我们的知识库 | PAT 提供的额外价值 |
|:------|:-----------|:----------------|
| **SQL Injection** | ✅ Level 0 有 | 更多注入语法（PostgreSQL/MySQL/MSSQL/Oracle/NoSQL） |
| **XSS Injection** | ✅ Level 0 有 | CSP 绕过技巧、WAF 绕过、DOM clobbering |
| **Command Injection** | ✅ 实战验证 | 多种 OS 的绕过字符集 |
| **File Inclusion (LFI/RFI)** | ✅ 实战验证 | php://filter 链构造、日志污染、远程包含 |
| **SSRF** | ✅ 知识库有 | 云元数据攻击、SSRF 链、协议限制绕过 |
| **JWT** | ✅ 知识库有 | JWK 注入、kid 注入、算法混淆最新技巧 |
| **Deserialization** | ✅ 知识库有 | PHP/Python/Java/Node.js 全语言覆盖 |
| ✨ **CVE Exploits** | ❌ 没有 | 包含常用 CVE 的 PoC/exp 索引 |
| ✨ **API Key Leaks** | ❌ 没有 | 90+ 种 API key 的正则模式 |
| ✨ **Race Condition** | ❌ 没有 | HTTP 并发竞争、TOCTOU |
| ✨ **GraphQL Injection** | ❌ 没有 | GraphQL introspection、batching |
| ✨ **NoSQL Injection** | ❌ 没有 | MongoDB 注入 |

**推荐立即整合到知识库的内容：**
1. API Key Leaks — 正则匹配模式（可直接用于自动化扫描）
2. SSRF 云元数据 — AWS/Azure/GCP 元数据端点大全
3. CVE Exploits — 我们 CVE 库（33226条）的利用方式映射

---

### 4. RedAmon — AI Agent 红队框架（我们的最大参考）

**[samugit83/redamon](https://github.com/samugit83/redamon)** — 2k+ stars, v4.14.0

**这是与我们的推理引擎目标最接近的项目。**

**架构对比：**

```
RedAmon                          |  云镜（我们的设计）
─────────────────────────────────┼──────────────────────────────
Pipeline: Recon→Exp→PostExp      |  四层推理链: 感知→假设→验证→路径
Multi-Agent (Fireteam)            |  单Agent+子Agent协作
LangGraph 编排                   |  DAG引擎编排
Neo4j 图数据库（攻击路径存储）    |  状态机+置信度矩阵
400+ AI模型（API+本地）           |  当前依赖云端LLM
70+ 安全工具                     |  20+工具（扫描沙箱）
266+ 配置项                      |  配置=引擎参数+知识库权重
黑盒扫描（IP/CIDR输入）          |  白盒+灰盒（对话交互）
CypherFix 自动修复 + PR提交流程  |  修复建议生成（报告级）
185k+ 检测规则（Nuclei/VulnDB）  |  CVE库33226条
```

**RedAmon 值得借鉴的核心特性：**

```
① Multi-Agent 并行化（Fireteam）
   多个 Specialist Agent 并行侦察不同方向

② 攻击路径图（Neo4j）
   节点=资产，边=漏洞/关系，路径=攻击链
   与我们 v0.2 设计的「暴露点交叉利用率矩阵」一致

③ 本地模型支持
   Ollama/vLLM/LM Studio → 本地运行7B/13B模型
   与我们"不依赖特定模型"的目标一致

④ RoE (Rules of Engagement) Guardrails
   攻击范围边界定义，防止越界
   对我们上补天接任务很有参考价值
```

**我们的 v0.2 设计 vs RedAmon：**

| 特性 | RedAmon | 云镜 v0.2 |
|:----|:-------:|:---------:|
| 全自动化 | ✅ 完全自动 | ⚠️ 半自动（需对话确认）|
| 攻击路径存储 | ✅ Neo4j | ⚠️ 状态机+矩阵 |
| 多Agent并行 | ✅ Fireteam | ❌ 单Agent |
| 本地模型 | ✅ 400+模型 | ❌ 云端模型 |
| 知识库整合 | ✅ knowledge_base 模块 | ✅ Level 0-2完整 |
| 自动修复 | ✅ CypherFix+PR | 仅报告级 |
| 推理能力 | LLM自主推理 | 知识库RAG+推理链 |

---

### 5. LLM4Pentest — AI 渗透测试论文合集

**[simon-p-j-r/LLM4Pentest](https://github.com/simon-p-j-r/LLM4Pentest)**

**收录的核心论文（按对我们价值排序）：**

| 论文 | 年份 | 核心理念 | 对我们的启发 |
|:-----|:----:|:---------|:------------|
| **RapidPen** | 2025 | IP to Shell 全自动渗透 | 自动化扫描→利用的端到端流程 |
| **AutoPentest** | 2025 | LLM Agent 自动化漏洞管理 | 漏洞发现的置信度评估 |
| **ARACNE** | 2025 | 自主 Shell 渗透 Agent | 类似我们的渗透测试对话 |
| **RedAmon** | 2025 | Multi-Agent 红队 | 并行Agent设计 |
| **PentestGPT** | 2023 | GPT 引导渗透测试 | 对话式渗透向导 |
| **HackMentor** | 2024 | LLM 辅助的渗透教学 | 渗透知识蒸馏 |

**趋势判断：** 2025年是AI渗透测试爆发年，RapidPen/AutoPentest/ARACNE/RedAmon 全部在一年内出现。我们的方向完全正确。

---

## 二、与我们的对比 — 差距与优势

### 2.1 差距（我们需要补的）

| 差距 | 严重程度 | 弥补计划 |
|:-----|:--------:|:---------|
| **AD渗透经验不足** | 🔴 严重 | 部署AD靶场练习 |
| **云安全（AWS/Azure/GCP）** | 🟡 中等 | 搭建云安全实验环境 |
| **C2框架经验** | 🟡 中等 | 研究CobaltStrike/Havoc/Sliver |
| **红队基础设施** | 🟢 低 | 先关注渗透测试核心能力 |
| **移动安全** | 🟢 低 | 暂不投入 |
| **NoSQL/GraphQL 注入知识** | 🟡 中等 | 补充到知识库 Level 0 |

### 2.2 优势（我们比这些仓库强的）

| 优势 | 说明 |
|:-----|:------|
| **从原理推导（Level 0→1→2）** | 没有仓库做到这种层次化知识体系 |
| **实战验证的数据** | 我们真实的渗透经验，不是CTF/靶场 |
| **推理引擎设计** | v0.2 设计的自学习机制 RedAmon也没有 |
| **中文+中国环境** | 国内才有的税控UKey/NSG/ZTNA/ZTE等场景 |
| **信任假设分析法** | 我们的核心方法论，仓库没有 |

---

## 三、立即可以用的行动项

### 从 PayloadsAllTheThings 直接摘取

```python
# API Key 正则匹配模式（可用于自动化扫描）
API_KEY_PATTERNS = {
    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitLab Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    # ... 90+ 种
}
```

### 从 Offensive-Resources 补充知识库

| 待补充领域 | 知识库位置 |
|:----------|:-----------|
| AD 渗透进阶 | 新增 `protocols/08-kerberos-security.md` |
| 云元数据SSRF | 补充到 `web-security/02-xss-and-injection-security.md` |
| 容器K8s安全 | 补充到 `network/03-docker-container-security.md` |

---

## 四、关于模型选择的回答

关于你的问题——**要不要下载DeepSeek 17B或Qwen 7B跑在Win10的12GB显卡上**。

我的建议很明确：

> **别训练自己的模型，也别绑定特定模型。**
> 框架设计成 **谁家的模型都能用** 就对了。

理由：

### 为什么不需要训练自己的模型

1. **成本不划算**
   - 训练一个基础模型：百万级人民币
   - 微调/RLHF：几十万人民币
   - 我们的知识库（38份文档~38KB）更适合做 RAG，不是训练

2. **模型迭代太快**
   - 去年最好的模型今年就过时了
   - 绑定一个模型=死路一条
   - 框架适配通用接口（OpenAI兼容API）=永不过时

3. **RedAmon 已经验证了这条路**
   - 支持 400+ AI 模型（Claude/GPT/Qwen/DeepSeek/Llama...）
   - 同一个框架，换模型就能升级能力
   - 本地模型跑 Ollama/GPT4all，云端用 API

### 要不要下载本地模型

**可以用，但目的是测试和离线兜底，不是主力：**

| 模型 | 大小(4bit) | 12GB VRAM | 建议 |
|:----|:----------:|:---------:|:------|
| Qwen2.5-7B | ~4.5GB | ✅ 流畅运行 | **推荐** — 最合适 |
| DeepSeek-7B | ~4.5GB | ✅ 流畅运行 | 备选 |
| DeepSeek-17B | ~10GB | ⚠️ 刚好塞下 | 有点紧，但可以跑 |
| Qwen2.5-14B | ~8GB | ✅ 可以 | 如果需要更大模型 |

**推荐的用法：**
- **日常渗透**：用云端强模型（Claude/GPT-4/Qwen-Max）
- **测试/研究**：在 Win10 跑 Qwen2.5-7B 本地体验
- **离线兜底**：本地模型作为网络不可用时的降级方案

### 核心结论

> **我们真正的护城河不是模型，而是：**
> 1. Level 0→1→2 的知识体系（38份文档）
> 2. 推理引擎的框架设计（v0.2 状态机+自学习）
> 3. 实战积累的14种攻击模式+5条攻击链
> 4. 模型无关的对接架构

所以：框架做模型无关 → 本地模型下不下都行，不影响工程架构。建议框架适配 OpenAI 兼容 API=一次适配，所有模型通吃。
