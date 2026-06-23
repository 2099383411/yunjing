# GitHub 渗透测试案例仓库精选指南

> Level 1: 攻击面 / 学习资源
> 目的：从优秀公开案例中学习渗透方法论、攻击链构建与文档写作

---

## 一、精选案例仓库

### 🌟 S级 — 必收藏

| 仓库 | Stars | 说明 | 推荐理由 |
|:-----|:-----:|:------|:---------|
| **[momenbasel/htb-writeups](https://github.com/momenbasel/htb-writeups)** | 2k+ | **500+** 台 HTB 机器 + **400+** 挑战题 writeup | 最完整的 HTB 解题库，含交互式知识图谱、技能树、攻击路径图 |
| **[Zeyad-Azima/Offensive-Resources](https://github.com/Zeyad-Azima/Offensive-Resources)** | 1.1k+ | 全球最全攻击性安全资源聚合 | 覆盖 Infrastructure → Wireless → IoT → Cloud → Blockchain → Car Hacking 等 **30+** 领域 |
| **[rix4uni/medium-writeups](https://github.com/rix4uni/medium-writeups)** | 500+ | **每10分钟自动更新** Medium 赏金猎人 writeup | 实时获取最新漏洞赏金案例，免翻墙看 Medium |

### 🔥 A级 — 强烈推荐

| 仓库 | 说明 | 推荐理由 |
|:-----|:------|:---------|
| **[shankarsharma507/Penetration-Testing-Report](https://github.com/shankarsharma507/Penetration-Testing-Report)** | 真实的黑盒 Web 渗透测试报告 | 学习标准报告格式：范围→方法→发现→PoC → 修复建议 |
| **[samugit83/redamon](https://github.com/samugit83/redamon)** | AI 驱动的红队 Agent（1.2k stars） | 了解我们的「推理引擎」方向——用 LangGraph + Metasploit + Neo4j 做自主渗透 |
| **[simon-p-j-r/LLM4Pentest](https://github.com/simon-p-j-r/LLM4Pentest)** | LLM 渗透测试论文合集 | 紧跟学术前沿：RapidPen / AutoPentest / ARACNE / RedAmon 全部收录 |
| **[swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)** | **62k+** stars | Web 渗透 Payload 大全，每个攻击类别有详细清单和利用方式 |
| **[nullenc0de/Web-Hacking-Playground](https://github.com/nullenc0de/Web-Hacking-Playground)** | 真实漏洞的 Docker 靶场 | 包含 SSRF/CORS/LFI/IDOR 等实际漏洞环境 |

### 📋 B级 — 有价值

| 仓库 | 说明 |
|:-----|:------|
| **[C4IROps/red](https://github.com/C4IROps/red)** | 48+ 真实世界攻击模拟场景 |
| **[Hack-with-Github/Awesome-Hacking](https://github.com/Hack-with-Github/Awesome-Hacking)** | 精选黑客工具集合 |
| **[infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)** | 红队资源大合集 |
| **[nixawk/pentest-wiki](https://github.com/nixawk/pentest-wiki)** | 渗透测试 Wiki（中文） |
| **[dafthack/SharpHound](https://github.com/dafthack/SharpHound)** | BloodHound AD 攻击路径收集器 |
| **[BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)** | AD 攻击路径可视化 |

---

## 二、推荐学习路径

### 路线 A：从实战案例学（推荐）

```
1. 先看我们的报告（复盘报告 + 知识库）
   ├── 理解攻击链构建方法
   ├── 理解推理链状态机
   └── 理解暴露点交叉利用
   
2. 看 htb-writeups 的交互式知识图谱
   ├── 选5台与我们环境相似的机器（Windows + Linux + Web）
   ├── 看攻击路径图 → 对比我们的攻击链
   └── 总结差异点
   
3. 看 medium-writeups 最新 Bug Bounty
   ├── 了解真实世界的最新攻击技巧
   ├── 补充我们知识库的时效性
   └── 丰富 Level 2 案例库
```

### 路线 B：从靶场实战（跳板到补天）

```
1. Hack The Box (100+ free machines)
   ├── 从 Easy 级别开始
   ├── 对比 htb-writeups 的解题思路
   └── 练习多平台（Linux/Windows/AD）渗透

2. OWASP Juice Shop / DVWA (已部署)
   ├── Web 渗透全类别练习
   └── 验证推理引擎的假设层

3. PortSwigger Web Security Academy
   ├── 免费 200+ 实验室
   └── 覆盖全部 Web 漏洞类别
```

---

## 三、我们的实战 vs GitHub 优秀案例对比

| 维度 | 我们的实战 | htb-writeups | medium-writeups |
|:----|:-----------|:-------------|:----------------|
| 环境类型 | 真实内部网络（多网段） | 靶机环境（单一/双机） | 真实网站（有 RT+WAF） |
| 攻击链长度 | 5条完整链（纵横5跳） | 通常2-3个节点 | 单点漏洞利用 |
| 文档质量 | ✅ 详细复盘 + 模式提炼 | ✅ 含攻击路径图 | ⚠️ 质量参差 |
| 覆盖漏洞类别 | 14种攻击模式 | 500+不同的漏洞 | 取决于最新发现 |
| 工具自动化 | 部分（DAG引擎+推理链） | 手动 | 手动+自动化扫描 |
| 知识库建设 | ✅ Level 0-2完整 | ❌ 无知识库 | ❌ 无知识库 |

---

## 四、从案例中学什么

### 4.1 攻击链构建

```
从 htb-writeups 我们可以学习：
1. 信息收集的完整性
   - 怎么不遗漏关键端口/服务
   - 怎么从一个小信息扩展到全盘控制

2. 漏洞利用的多样性
   - 同一类漏洞的不同利用方式
   - 不同场景下的 payload 选择

3. 提权/横向移动思路
   - 本地提权的多种技术
   - 在域环境中怎么横向移动
```

### 4.2 文档写作

```
从 shankarsharma507 的 Pentest Report 学习：
1. 报告结构：范围 → 方法论 → 发现 → 证据 → 建议
2. PoC 截图的组织方式
3. 技术语言和非技术语言的平衡

从我们的知识库学习：
1. 从原理推导脆弱性（Level 0 → Level 1 → Level 2）
2. 攻击模式提炼
3. 暴露点交叉利用分析
```

### 4.3 推理引擎启发

```
从 RedAmon / LLM4Pentest 论文学习：
1. 多层 Agent 架构：侦察Agent → 漏洞分析Agent → 利用Agent
2. 状态机管理：怎么组织渗透流程的状态流转
3. 经验回放：怎么从成功/失败案例中学习
4. Neo4j 图数据库：攻击路径图的可视化

这些与我们推理引擎 v0.2 的设计高度一致。
```

---

## 五、推荐立即阅读的案例

| 优先级 | 案例 | 来源 | 学习点 |
|:------:|:-----|:------|:-------|
| 🥇 | **Windows AD 横向移动** | htb-writeups > Active Directory 目录 | 域渗透技术（我们未来必用） |
| 🥇 | **Docker 容器逃逸** | htb-writeups > Container 类别 | 补充我们的逃逸技术栈 |
| 🥇 | **最新 Bug Bounty 技巧** | medium-writeups > 最近1周更新 | 跟上最新攻击技巧 |
| 🥈 | **真实 Web 渗透报告** | shankarsharma507 的报告 | 学习专业的报告格式 |
| 🥈 | **RedAmon 架构** | samugit83/redamon | 推理引擎架构参考 |
| 🥉 | **PayloadsAllTheThings** | swisskyrepo 仓库 | 补充我们的 payload 库 |

---

## 六、知识库联动

- **对 Level 1 更新**：从 htb-writeups 提取新的攻击方向补充到攻击面文档
- **对 Level 2 更新**：从 medium-writeups 提取新案例加入案例融合
- **对推理引擎**：从 RedAmon / LLM4Pentest 论文中提取架构设计参考
- **对报告格式**：从 shankarsharma507 学习专业渗透报告模板

---

## 参考链接

| 资源 | 链接 |
|:-----|:------|
| htb-writeups | https://github.com/momenbasel/htb-writeups |
| Offensive-Resources | https://github.com/Zeyad-Azima/Offensive-Resources |
| medium-writeups | https://github.com/rix4uni/medium-writeups |
| Pentest Report | https://github.com/shankarsharma507/Penetration-Testing-Report |
| RedAmon | https://github.com/samugit83/redamon |
| LLM4Pentest | https://github.com/simon-p-j-r/LLM4Pentest |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| Web Hacking Playground | https://github.com/nullenc0de/Web-Hacking-Playground |
