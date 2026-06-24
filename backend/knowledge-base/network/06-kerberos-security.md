# Kerberos 协议安全 — 票据、PAC 验证与域渗透攻击链

> Level 0: 基础原理 / 网络安全
> 适用场景：Active Directory 域渗透、Kerberos 协议攻击、票据伪造检测

---

## 一、Kerberos 协议架构

### 1.1 核心角色

```
┌─────────────────────────────────────────────────────────────┐
│                    Kerberos 协议架构                          │
│                                                             │
│     ┌──────────┐       ┌──────────┐       ┌──────────┐     │
│     │   KDC    │       │   KDC    │       │   KDC    │     │
│     │ (AS)     │       │ (TGS)    │       │ (KCM)    │     │
│     └────┬─────┘       └────┬─────┘       └────┬─────┘     │
│          │                  │                  │           │
│          │ ① AS-REQ        │ ③ TGS-REQ       │ ⑤         │
│          │ ② AS-REP(TGT)  │ ④ TGS-REP(ST)   │ AP-REQ    │
│          ▼                  ▼                  ▼           │
│     ┌─────────────────────────────────────────────────┐    │
│     │              客户端 (Client)                     │    │
│     │          ┌────────────────────┐                 │    │
│     │          │ TGT (TGT缓存)      │                 │    │
│     │          │ ST (Service Ticket)│                 │    │
│     │          └────────────────────┘                 │    │
│     └─────────────────────────────────────────────────┘    │
│                       │                                     │
│                       │ ⑥ AP-REQ (ST)                      │
│                       ▼                                     │
│     ┌─────────────────────────────────────────────────┐    │
│     │              服务端 (Server)                     │    │
│     └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 六步握手过程

| 步骤 | 消息对 | 发送方→接收方 | 核心内容 |
|:----:|:------|:-------------|:---------|
| ①-② | AS-REQ / AS-REP | Client → AS → Client | 用用户密码哈希加密的 TGT |
| ③-④ | TGS-REQ / TGS-REP | Client → TGS → Client | 用 TGT 换取服务票据 (ST) |
| ⑤-⑥ | AP-REQ / AP-REP | Client → Server → Client | 用 ST 访问具体服务 |

### 1.3 票据结构

**TGT (Ticket Granting Ticket)：**
```
TGT = KDC_TGT_SESSION_KEY + Pr PAC + ClientInfo + Timestamp
   ↑ 用 KRBTGT Hash 加密
```

**ST (Service Ticket)：**
```
ST = Service_Session_Key + Pr PAC + ClientInfo + Timestamp
   ↑ 用服务账户 NTLM Hash 加密
```

**Pr (PAC - Privilege Attribute Certificate)：**
```
PAC = ┌─────────────────────────────┐
      │ Logon Info (RID)           │ ← 用户SID、组SID
      │ Credential Info            │ ← 凭据类型、时间
      │ Server Checksum            │ ← 用服务账户Key签名
      │ KDC Checksum               │ ← 用KRBTGT Key签名
      │ Client Claims Info         │ ← Windows 2008+ 可选
      │ Device Claims Info         │
      └─────────────────────────────┘
```

**关键点：** PAC 由两层签名保护 — 服务账户 Key 和 KRBTGT Key。破解任一即可伪造。

---

## 二、Kerberos 安全机制

### 2.1 时间同步要求
- Kerberos 默认时钟偏移容差：**5 分钟**
- 超过则拒绝认证
- 攻击影响：迫使攻击者需同步时间

### 2.2 票据生命周期

| 票据类型 | 默认有效期 | 可续期至 |
|:--------|:---------|:---------|
| TGT | 10 小时 | 7 天 |
| 服务票据 | 取决于服务配置 | N/A |
| 续期 | — | 最多 7 天 |

### 2.3 PAC 验证
- Windows 2000 引入，初始强制验证
- 从 Windows 2000 SP4 开始变为**可禁用**
- 服务端必须在 DC 验证签名
- **漏洞：如果验证被禁用，PAC 可随意伪造**

### 2.4 加密类型

| 加密类型 | 标识符 | 安全性 | 当前状态 |
|:--------|:-----:|:-----:|:--------|
| RC4-HMAC | 0x17 | ❌ 弱 | 仍广泛使用 |
| AES128-CTS-HMAC-SHA1-96 | 0x11 | ✅ 中等 | 默认 |
| AES256-CTS-HMAC-SHA1-96 | 0x12 | ✅ 强 | 推荐 |
| DES (各种) | 0x01-0x03 | ❌ 极弱 | 默认已禁用 |

---

## 三、Kerberos 攻击面分析

### 3.1 AS-REP Roasting (无需密码)

**原理：** 用户账户设置了"不需要 Kerberos 预认证"（UF_DONT_REQUIRE_PREAUTH 标志）

```
正常流程：                 无预认证流程：
Client → AS：AS-REQ       Client → AS：AS-REQ (无 Authenticator)
         ↓                          ↓
AS：验证密码时间戳          AS：直接返回加密的 TGT
         ↓                          ↓
返回 TGT                    攻击者在离线破解 TGT 中的用户密码
```

**检测：**
- 域用户属性 `userAccountControl` 包含 `0x400000`（DONT_REQ_PREAUTH）
- 默认约 1-5% 的用户有此标志
- PowerShell：`Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`

### 3.2 Kerberoasting (任意域用户可做)

**原理：** 任何域用户均可请求任何服务账户的 TGS 票据，服务票据用服务账户 NTLM Hash 加密，可在离线破解

```
① 查询 SPN 服务账户
② 请求 TGS 票据
③ 获取加密的服务票据
④ 离线破解服务账户密码
```

**检测信号：**
- 事件 ID 4769 (Kerberos Service Ticket Operations)
- 短时间大量 TGS-REQ 请求
- 请求的加密类型是 RC4 (0x17) 而非 AES

### 3.3 黄金票据 (Golden Ticket)

**原理：** 获得 KRBTGT 账户的 NTLM Hash 后，可伪造任意 TGT

```
所需数据：
┌──────────────────────────────────────┐
│ KRBTGT NTLM Hash                     │ ← 需从 DC 获取
│ 目标域 SID                           │ ← 可枚举
│ 目标用户名和组 SID                   │ ← 任意伪造
└──────────────────────────────────────┘

结果：任何用户（包括非域用户）可访问域中任何资源
```

**关键特性：**
- KRBTGT 密码极少轮换
- 票据有效期由生成时的 TGT 生命周期决定
- 即使改了 KRBTGT 密码，旧票据仍有效至过期

### 3.4 白银票据 (Silver Ticket)

**原理：** 获得服务账户 NTLM Hash 后，伪造特定服务的 ST

```
所需数据：
┌──────────────────────────────────────┐
│ 服务账户 NTLM Hash                    │ ← 如 MSSQL$SRV、IIS、CIFS
│ 目标服务 SPN                          │
│ 域 SID + 用户名                       │
└──────────────────────────────────────┘

结果：可访问该特定服务（伪造的 PAC 不会被验证）
```

**与黄金票据区别：**
- 黄金票据：伪造 TGT，需要 KRBTGT Hash
- 白银票据：伪造 ST，需要服务账户 Hash
- 白银票据不联系 KDC，日志少，更难检测

### 3.5 DCSync

**原理：** 利用域复制协议（DRSUAPI）假装 DC，请求密码数据

```
攻击者 → 请求 REPL_STATE 和 REPL_SECRET
    ↓
DC → 返回所有账户的 NTLM Hash
    ↓
攻击者 = 域控
```

**所需权限：**
- `Replicating Directory Changes` (DS-Replication-Get-Changes)
- `Replicating Directory Changes All` (DS-Replication-Get-Changes-All)
- 默认 Domain Admins、Enterprise Admins、Domain Controllers 有

### 3.6 Kerberos 委派攻击

**委派类型对比：**

| 类型 | 描述 | 限制 |
|:----|:-----|:-----|
| **非约束委派** | 服务可模拟用户访问任何服务 | ❌ 最危险，所有来自身票据可被转发 |
| **约束委派 (S4U2Proxy)** | 服务仅可模拟用户到指定服务 | ✅ 受限，但可协议转换突破 |
| **基于资源的委派** | 由目标服务控制谁可委派给它 | ✅ 现代，更安全但有功能滥用 |
| **协议转换 (S4U2Self)** | 可将外部认证转换为 Kerberos | ⚠️ 需要 `TRUSTED_TO_AUTH_FOR_DELEGATION` |

**非约束委派攻击链：**
```
① 找到开启非约束委派的服务器
② 诱导域管理员访问该服务器（或等待自动认证）
③ 捕获管理员 TGT（存储在 LSASS 中）
④ 用管理员的 TGT 访问域控
```

---

## 四、利用链组合

### 4.1 从普通域用户到域控

```
┌───────────────────────────────────────────────────────┐
│ 普通域用户                                             │
│    ↓                                                   │
│  Kerberoasting → 获取服务账户密码                       │
│    ↓                                                   │
│  用服务账户登录服务器 → 检查委派配置                     │
│    ↓                                                   │
│  发现非约束委派服务器 → 等待/触发域管理员认证              │
│    ↓                                                   │
│  捕获管理员 TGT → DCSync → KRBTGT Hash                 │
│    ↓                                                   │
│  黄金票据 → 域控全权限                                  │
└───────────────────────────────────────────────────────┘
```

### 4.2 从无域账号到域控

```
┌───────────────────────────────────────────────────────┐
│ 无域账号                                               │
│    ↓                                                   │
│  LLMNR/NBT-NS 投毒 → 捕获 NTLMv2 Hash                 │
│    ↓                                                   │
│  破解 OR 中继 → 获得初始访问                            │
│    ↓                                                   │
│  BloodHound 枚举 → 找到攻击路径                         │
│    ↓                                                   │
│  ACL 滥用 → 权限提升 → DCSync                          │
└───────────────────────────────────────────────────────┘
```

---

## 五、检测与防御

| 攻击类型 | 检测方法 | 防御措施 |
|:---------|:--------|:---------|
| AS-REP Roasting | 监控无预认证的 AS-REP | 强制预认证；密码 ≥ 15 位 |
| Kerberoasting | 监控事件 4769 + 加密类型变化 | 服务账户用复杂密码；托管服务账户 (gMSA) |
| 黄金票据 | 监控 TGT 用户不存在/域 SID 不匹配 | 定期轮换 KRBTGT 密码；部署 PTA |
| 白银票据 | 服务日志中的认证异常 | 启用 PAC 验证；服务账户最小权限 |
| DCSync | 监控非 DC 的 DRSUAPI 调用 | 限制复制权限；监控事件 4662 |
| 非约束委派 | 发现 msDS-AllowedToDelegateTo 属性 | 禁用非约束委派；用资源委派替代 |

---

## 六、LLM 推理辅助

### 触发条件
当输入涉及以下关键词时激活 Kerberos 攻击面推理：
- "域渗透"、"AD"、"域控"、"Kerberos"、"票据"、"TGT"、"TGS"
- "黄金票据"、"白银票据"、"委派"、"DCSync"
- "kinit"、"klist"、"KRBTGT"、"SPN"

### 检测信号表
| 信号 | 含义 | 置信度 |
|:----|:-----|:------:|
| 事件 4768（Kerberos 认证）+ 加密类型 = RC4 | 可能正在 Kerberoasting | 中 |
| AS-REP 中用户 DONT_REQUIRE_PREAUTH | 可 AS-REP Roasting | 高 |
| TGT 中用户 SID 在域中不存在 | 黄金票据 | 极高 |
| 非 DC 服务器调用 DRSUAPI | DCSync 攻击 | 极高 |

### 验证步骤
1. 确认域版本 → Windows 2000+ 都易受攻击
2. 确认加密类型 → AES 比 RC4 更难破解
3. 确认服务账户密码策略 → 密码是否足够复杂
4. 确认委派配置 → 检查 TrustedForDelegation 和 TrustedToAuthForDelegation
5. 确认复制权限 → 检查谁有 DCSync 权限

### 利用链扩展
- AS-REP Roasting → 破解密码 → 登录 → BloodHound
- Kerberoasting → 破解服务密码 → 服务器访问 → 横向移动
- 黄金票据 → 任意资源访问 → 持久化
- DCSync → 全域凭据 → 完全控制

### 关联攻击面
- [NTLM 中继](02-http-protocol-security.md) → NTLM→Kerberos 转换
- [AD 域安全](未完成) → 域攻击路径完整分析
- [Windows 安全](未完成) → Token 操纵与票据窃取
- [网络栈安全](01-network-stack-security.md) → LLMNR/NBT-NS 投毒与 Kerberos 配合

### 常见误判
- 事件 4769 大量出现不一定是 Kerberoasting（需要检查加密类型）
- AS-REP Roasting 只对无预认证账户有效
- 有委派配置不一定是漏洞（需要结合权限使用场景判断）
- 非域控服务器上的 DCSync 调用一定是攻击
