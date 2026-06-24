# 06. SMB 协议安全深度分析

> 领域：网络协议安全
> 关联：05-ssh-protocol-security.md（远程访问协议对比）、AD 域渗透（SMB 是 AD 的核心传输协议）
> 学习路线：TCP/IP → HTTP → TLS → DNS → SSH → SMB（当前）

---

## 一、SMB 协议概述

SMB (Server Message Block) 是 Windows 网络的核心协议，用于文件共享、打印机共享、命名管道通信和远程管理。几乎所有 Windows 域环境（AD）的认证和通信都依赖 SMB。

### 1.1 协议栈中的位置

```
应用层 (文件资源管理器、打印服务、PowerShell Remoting)
    ↑
SMB 协议层 (SMB 2/3 — 命令、数据、命名管道)
    ↑
传输层 (TCP 445 — Direct SMB)  /  (NetBIOS TCP 139 — 遗留)
    ↑
网络层
```

**端口：**
- **TCP 445** — SMB over TCP（现代，Windows 2000+）
- **TCP 139** — SMB over NetBIOS（遗留，旧系统兼容）
- **UDP 137** — NetBIOS 名称服务
- **UDP 138** — NetBIOS 数据报服务

### 1.2 SMB 版本演变

| 版本 | 首发系统 | 特性 | 安全状态 |
|------|---------|------|---------|
| **SMB 1.0/CIFS** | Windows 95/NT | 兼容性优先，无加密，无签名 | **极度危险，已被废弃** |
| **SMB 2.0** | Windows Vista/2008 | 减少命令数量(100+→19)，管道化请求 | 有签名但默认不强制 |
| **SMB 2.1** | Windows 7/2008 R2 | 租借锁优化性能 | 同上 |
| **SMB 3.0** | Windows 8/2012 | **SMB Encryption、Multichannel、RDMA** | 支持端到端加密 |
| **SMB 3.0.2** | Windows 8.1/2012 R2 | 性能优化 | 同上 |
| **SMB 3.1.1** | Windows 10/2016 | **预认证完整性(SHA-512)、AES-128-GCM** | **最安全，强制安全协商** |

**关键安全转折点：** SMB 1.0 → SMB 2.0/3.0 → SMB 3.1.1 的演进，本质上是**从不安全（无加密、无签名、缓冲区溢出）到可选安全 → 再到强制安全**的路线。

### 1.3 SMB 1.0 的问题（为什么被废弃）

```
1. 命令数过多（100+ 不同命令）
   → 攻击面巨大，实现复杂，缓冲区溢出频发

2. 无签名（默认）
   → SMB Relay 攻击的温床

3. 无加密
   → 所有数据（含认证信息）明文传输

4. 非 Unicode
   → 代码路径复杂，编码错误多

5. 缓冲区溢出
   → EternalBlue (CVE-2017-0144) 利用 SMBv1 的缓冲区溢出
   → WannaCry (2017) 利用该漏洞感染 30 万+ 机器
```

---

## 二、SMB 2/3 握手流程

### 2.1 完整连接生命周期

```
客户端                                     服务端
  │──── TCP 连接 (445) ──────────────────►│
  │                                         │
  │──── SMB2 NEGOTIATE ──────────────────►│
  │     (支持的 dialects 列表)              │
  │◄──── SMB2 NEGOTIATE Response ──────────│
  │     (选定 dialect + 能力集)              │
  │                                         │
  │──── SMB2 SESSION_SETUP ───────────────►│
  │     (NTLM/Kerberos 认证)               │
  │◄──── SMB2 SESSION_SETUP Response ──────│
  │     (Session ID + 认证结果)             │
  │                                         │
  │──── SMB2 TREE_CONNECT ────────────────►│
  │     (\\SERVER\SHARE)                   │
  │◄──── SMB2 TREE_CONNECT Response ───────│
  │     (Tree ID = TID)                    │
  │                                         │
  │──── SMB2 CREATE ──────────────────────►│
  │     (打开文件/管道)                     │
  │◄──── SMB2 CREATE Response ─────────────│
  │     (File ID)                          │
  │                                         │
  │──── SMB2 READ/WRITE/IOCTL ────────────►│
  │◄──── SMB2 READ/WRITE Response ─────────│
  │                                         │
  │──── SMB2 CLOSE ───────────────────────►│
  │──── SMB2 TREE_DISCONNECT ─────────────►│
  │──── SMB2 LOGOFF ──────────────────────►│
```

### 2.2 Negotiate（协商）

```
客户端 → 服务端:
  SMB2 Negotiate Request
    StructureSize: 36
    Dialects: [SMB 2.0.2, SMB 2.1, SMB 3.0, SMB 3.1.1]
    SecurityMode: SIGNING_ENABLED
    Capabilities: ...

服务端 → 客户端:
  SMB2 Negotiate Response
    StructureSize: 65
    DialectRevision: 0x0311 (SMB 3.1.1)  ← 选择双方都支持的最高版本
    SecurityMode: SIGNING_ENABLED | SIGNING_REQUIRED
    ServerGuid: {guid}                    ← 服务器标识
    Capabilities: ...
    MaxTransactSize: 65536
    MaxReadSize: 65536
    MaxWriteSize: 65536
    SystemTime: ...
    SecurityBuffer: <NTLM/Kerberos 挑战>
```

**安全含义：**
- 双方协商使用**最高的共同 dialect**
- SMB 3.1.1 的 Negotiate 包含**预认证完整性**（SHA-512 哈希整个协商过程）
- `SIGNING_REQUIRED` 位决定是否需要签名 → SMB Relay 的关键检测指标
- ServerGuid 标识服务器身份（域控的 GUID 可用于识别 DC）

### 2.3 Session Setup（会话建立 / 认证）

```
通过 NTLM 或 Kerberos 认证:

步骤 1 (NTLM):
  客户端 → 服务端:
    SESSION_SETUP Request
      SecurityBuffer: NTLM_NEGOTIATE (版本标志 + 域信息)

步骤 2:
  服务端 → 客户端:
    SESSION_SETUP Response
      SecurityBuffer: NTLM_CHALLENGE (服务器生成的 8 字节随机挑战)

步骤 3:
  客户端 → 服务端:
    SESSION_SETUP Request
      SecurityBuffer: NTLM_AUTHENTICATE (加密响应)
      SessionFlags: ...

步骤 4:
  服务端验证响应 ✓
  服务端 → 客户端:
    SESSION_SETUP Response
      SessionFlags: SESSION_FLAG_IS_GUEST / SESSION_FLAG_IS_NULL
      ...

→ 服务端返回 Session ID，用于后续所有操作的认证
```

**安全含义：**
- NTLM 是**挑战-响应**协议：密码本身不传输，传输的是「用密码哈希加密的挑战」
- 但 NTLM 没有**抗重放保护**（无服务器身份验证）→ SMB Relay
- Kerberos（在域环境中）提供更强的安全性（票据+时间戳防重放）
- SMB 3.1.1 的预认证完整性确保 Negotiate 阶段未被篡改

### 2.4 Tree Connect（连接到共享）

```
客户端 → 服务端:
  TREE_CONNECT Request
    Path: \\SERVER\SHARE$

服务端验证权限:
  → 检查用户是否有该共享的访问权限
  → 检查共享权限 + NTFS 权限

服务端 → 客户端:
  TREE_CONNECT Response
    ShareType: DISK / PIPE / PRINT
    ShareFlags: ...
    Capabilities: ...
    MaximalAccess: 读写权限掩码
```

**安全含义：**
- **隐藏共享**（如 ADMIN$、C$、IPC$）以 `$` 结尾，但在知道名称的情况下仍可访问
- **ADMIN$** → 可远程管理（需要管理员权限）
- **IPC$** → 命名管道，用于远程过程调用（RPC）—— 这是渗透测试的关键入口

### 2.5 Create（打开文件/管道/设备）

```
客户端 → 服务端:
  CREATE Request
    Name: \path\to\file.txt
    DesiredAccess: READ_DATA | WRITE_DATA
    FileAttributes: ...
    ShareAccess: READ | WRITE
    CreateDisposition: OPEN_IF

服务端 → 客户端:
  CREATE Response
    FileId: <128 bit 持久句柄>  ← 后续操作使用这个 ID
    CreationTime: ...
    LastAccessTime: ...
    AllocationSize: ...
    EndOfFile: ...
```

**安全含义：**
- FileId 是持久句柄（在 SMB 3.0+ 中可跨连接迁移）→ 故障转移能力
- **命名管道**（如 `\pipe\srvsvc`、`\pipe\samr`、`\pipe\lsarpc`）通过 CREATE 打开
- 管道名后缀 `\pipe\` 指示这是一个命名管道，不是文件

**关键！IPC$ + 命名管道是渗透测试的核心入口：**

```
常见命名管道:
  srvsvc     → 服务管理（列出共享、获取服务器信息）
  samr       → SAM 账户管理（枚举用户、组）
  lsarpc     → 本地安全机构策略
  winreg     → 远程注册表
  netlogon   → 域登录（Netlogon 协议）
  epmapper   → DCE/RPC 端点映射器
```

---

## 三、SMB 3.x 安全增强

### 3.1 SMB Encryption

```
SMB 3.0 引入端到端加密:
  - 加密在 SMB 层实现（不需要 TLS/IPsec）
  - 使用 AES-128-CCM (SMB 3.0) 或 AES-128-GCM (SMB 3.1.1)
  - 保护所有文件数据和元数据

启用方式:
  1. 服务器级: Set-SmbServerConfiguration -EncryptData $true
  2. 共享级: Set-SmbShare -Name Share -EncryptData $true
  3. 客户端强制: Set-SmbClientConfiguration -RequireEncryption $true
```

**安全含义：**
- 加密后即使中间人拿到流量也无法解密
- 加密不依赖 SMB Signing（签名验证身份，加密保护内容）
- 性能开销（SMB 3.1.1 的 AES-128-GCM 有硬件加速，影响很小）

### 3.2 SMB Signing（签名）

```
SMB 签名原理:
  - 每个 SMB 消息附带 HMAC 签名
  - 密钥基于会话密钥派生
  - 接收方验证签名 → 确认消息未篡改且来自合法会话

配置级别:
  Disabled: 不签名、也不验证签名
  Enabled:  可签名（对方要求时才签）
  Required: 强制签名（不签名的请求被拒绝）

通过注册表:
  HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters
    RequireSecuritySignature = 1 (Required)
```

**安全含义：**
- SMB 签名是**防御 SMB Relay 的关键机制**
- 如果服务器设了 `SIGNING_REQUIRED` → 攻击者不能 Relay（签名验证失败）
- 如果服务器设了 `SIGNING_ENABLED`（不强制）→ 攻击者伪造不签名的请求 → RELAY 成功
- **渗透测试检查重点：** `crackmapexec smb --gen-relay-list targets.txt 192.168.1.0/24`

### 3.3 预认证完整性 (SMB 3.1.1)

```
SMB 3.1.1 新增:
  在 Negotiate 阶段，客户端和服务端交换哈希值:
    PreauthIntegrityHashValue = SHA-512(双方 Negotiate 消息)

  该哈希在后续 Session Setup 中被包含在认证中
  → 任何对 Negotiate 消息的篡改都会导致认证失败

解决的问题:
  SMB 3.0 的 Negotiate 阶段是明文的
  → 中间人可以降级 dialect（如 3.0 → 2.1）
  → 降级后加密等功能丢失
  → SMB 3.1.1 的预认证完整性杜绝了降级攻击
```

### 3.4 安全协商

```
SMB 3.1.1 强制:
  - 拒绝 SMB 2.0.2 之前的版本
  - 不接受无法验证完整性的 Negotiate
  - 拒绝不支持的 dialect 降级

客户端和服务端在 Negotiate 中互相验证对方的 dialect 能力表:
  - 如果服务端选择了不在客户端列表中的 dialect → 拒绝连接
  - 防止中间人注入伪造的 dialect
```

---

## 四、SMB 与 Windows 认证

### 4.1 NTLM 认证（在 SMB 上）

```
NTLMv2 挑战-响应流程（通过 SMB SESSION_SETUP）:

1. 客户端: NTLM_NEGOTIATE → 服务端
   (版本标志 + 域名 + 工作站名)

2. 服务端: NTLM_CHALLENGE → 客户端
   (8 字节随机挑战 ServerChallenge + 可选 TargetInfo)

3. 客户端计算:
   NTOWFv2 = HMAC-MD5(密码哈希, 用户名 + 域名)
   LMOWFv2 = NTOWFv2 (除非需要向下兼容)
   NetNTLMv2Hash = HMAC-MD5(NTOWFv2, ServerChallenge + Blob)
   
   Blob = 时间戳 + 客户端随机 + 域名 + 其他 TargetInfo

4. 客户端: NTLM_AUTHENTICATE → 服务端
   (NetNTLMv2Hash + Blob + 用户名 + 域名)

5. 服务端验证:
   从 DC 获取用户密码哈希
   计算期望的 NetNTLMv2Hash
   比较客户端提供的值和期望值
```

**爆破 NTLM 的问题：**
```
NTLMv2 响应 = 密码哈希加密的挑战

但:
  - 不能直接反向（密码不是挑战，挑战是随机数）
  - 只能通过**离线暴力破解**：
    用候选密码计算 NTOWFv2 → 加密挑战 → 比较结果
  - 工具: john / hashcat（模式 5600 = NTLMv2）
```

### 4.2 Kerberos 认证（域环境）

```
域成员在 SMB 上使用 Kerberos（而非 NTLM）:

1. 客户端获取 TGT ← KDC (DC)
2. 客户端请求服务票据 ← KDC
3. 客户端发送 AP-REQ（服务票据）到 SMB 服务器
4. 服务器用自身的机器账户密钥解密票据
5. 验证时间戳（防重放）
6. 接受或拒绝连接

Kerberos vs NTLM:
  安全:                Kerberos ⭐⭐⭐⭐⭐  NTLM ⭐⭐⭐
  防重放:              Kerberos ✓          NTLM ✗
  双因素友好:          Kerberos ✓          NTLM ✗
  需要 DC 可达:        Kerberos ✓          NTLM ✗
  域环境默认:          Kerberos ✓          NTLM ✗
  
  如果 Kerberos 失败 → 回退到 NTLM
```

---

## 五、SMB 攻击面详解

### 5.1 EternalBlue (CVE-2017-0144)

```
类型: SMBv1 缓冲区溢出
影响: Windows XP / 7 / 2008 / 2008 R2（未打补丁）
严重程度: 10.0 (CVSS)
利用方式: 认证前远程代码执行

原理:
  SMBv1 的 CreateAndx Transaction 请求中
  攻击者可以指定一个超大值
  → 内核池缓冲区溢出
  → 控制执行流

后果:
  - WannaCry (2017) 利用 NSA 泄露的 EternalBlue 漏洞
  - 感染 150+ 国家的 30 万+ 台机器
  - 造成约 40 亿美元的损失

防御: 禁用 SMBv1（默认配置）
  Set-SmbServerConfiguration -EnableSMB1Protocol $false
```

### 5.2 SMB Relay (NTLM Relay)

**SMB Relay 是内网渗透最经典、最高效的攻击之一。**

```
攻击场景:
  攻击者位于客户端和服务器之间的网络中。

正常流程:
  客户端 → 服务端: 认证请求 (NTLM_NEGOTIATE)
  服务端 → 客户端: 挑战 (NTLM_CHALLENGE)
  客户端 → 服务端: 加密响应 (NTLM_AUTHENTICATE)

Relay 攻击:
  攻击者截获认证请求 → 连接到目标服务端 → Relay 认证

  攻击者 ← 客户端: NTLM_NEGOTIATE
  攻击者 → 目标服务器: NTLM_NEGOTIATE
  目标服务器 → 攻击者: NTLM_CHALLENGE
  攻击者 ← 客户端: NTLM_CHALLENGE (转发的)
  客户端 → 攻击者: NTLM_AUTHENTICATE
  攻击者 → 目标服务器: NTLM_AUTHENTICATE (转发的)
  ✓ 验证通过 → 攻击者获得目标服务器的访问权限
```

**关键点：**
- 攻击者**不需要知道密码**——攻击者只是"转发"认证
- 攻击者获得的是**客户端用户的权限**
- 如果目标是域控 → 攻击者获得域管理员权限

**工具：**
```
Responder             → 捕获网络上的 LLMNR/NBT-NS 请求
ntlmrelayx (Impacket) → Relay 认证到目标
crackmapexec          → 检测 SMB 签名状态
```

**防御（只有一种可靠方案）：**
```
在所有系统上强制 SMB 签名:
  Set-SmbServerConfiguration -RequireSecuritySignature $true
```

**为什么签名有效：** 攻击者转发的认证签名会指向原始会话，目标服务器验证签名时发现是转发 → 拒绝。

### 5.3 SMB 暴力破解 / 密码喷洒

```
暴力破解:
  crackmapexec smb 192.168.1.100 -u administrator -p passwords.txt

密码喷洒（避免账户锁定）:
  所有用户尝试同一个密码 → 换密码 → 再试
  crackmapexec smb 192.168.1.0/24 -u users.txt -p "Password123!"
```

### 5.4 Pass-the-Hash (PtH)

```
NTLM 认证使用「密码哈希」而非「密码明文」
  → 如果攻击者获得了 NTLM 哈希（而不是密码）
  → 可以直接用哈希进行 NTLM 认证
  → 不需要知道原始密码

工具:
  impacket-wmiexec -hashes LMHASH:NTHASH user@target
  impacket-psexec -hashes LMHASH:NTHASH user@target
  crackmapexec smb target -u user -H NTHASH
```

**为什么 PtH 有效：** NTLM 挑战-响应是用密码哈希计算的，不是密码本身。哈希是 "足够" 的凭证。

### 5.5 IPC$ 命名管道枚举

```
枚举 SMB 共享:
  smbclient -L //target -U user

枚举域用户（通过 SAMR 管道）:
  rpcclient -U user target
  > enumdomusers
  > enumdomgroups

枚举其他信息（通过 LSARPC/SRV$VC）:
  > srvinfo
  > enumprivs
  > lsaenumsid

工具:
  crackmapexec smb target -u user -p pass --users    # 枚举用户
  crackmapexec smb target -u user -p pass --shares   # 枚举共享
  crackmapexec smb target -u user -p pass --lusers   # 本地用户
  crackmapexec smb target -u user -p pass --sessions # 活跃会话
```

### 5.6 Named Pipe 提权

```
Windows 上命名管道的模拟 (Impersonation):
  服务端创建命名管道 → 客户端连接 → 服务端 ImpersonateNamedPipeClient
  → 服务端以客户端用户的身份运行

​Service 漏洞:
  系统服务（SYSTEM）创建一个命名管道
  普通用户连接 → 服务端模拟用户 → 一般的安全操作
  但：如果服务端在模拟后主动访问用户资源
  → 用户可以拦截 (Print Spooler 漏洞、各种 Token 窃取)
```

### 5.7 SMB Ghost (CVE-2020-0796)

```
类型: SMBv3 压缩漏洞（SMB 3.1.1）
影响: Windows 10 1903/1909, Server 1903/1909
严重程度: 10.0 (CVSS)
利用方式: 认证前远程代码执行

原理:
  SMB 3.1.1 支持压缩
  攻击者发送精心构造的压缩数据包
  → 内核池溢出
  → 控制执行流

修复: KB4551762 (2020年3月)
```

---

## 六、IPC$ 和命名管道（渗透测试核心入口）

### 6.1 IPC$ 是什么

```
IPC$ 是 Windows 的“进程间通信”共享
  • 不是文件共享！它是命名管道的入口
  • 可以通过 \\target\IPC$ 访问所有命名管道
  • 匿名访问：部分管道不需要认证（但越来越少）
  • 认证后：取决于用户权限可以访问不同管道
```

### 6.2 关键命名的管道

| 名称 | 服务 | 功能 | 渗透价值 |
|------|------|------|---------|
| **srvsvc** | 服务器服务 | 共享管理 | ⭐⭐⭐ **枚举共享、服务器信息** |
| **samr** | SAM | 用户/组管理 | ⭐⭐⭐⭐⭐ **枚举域用户、组** |
| **lsarpc** | 本地安全机构 | 策略查询 | ⭐⭐⭐ **获取域 SID、策略信息** |
| **winreg** | 注册表 | 远程注册表操作 | ⭐⭐⭐ **远程访问注册表** |
| **netlogon** | Netlogon | 域登录 | ⭐⭐⭐⭐ **Netlogon 漏洞** |
| **epmapper** | 端点映射 | RPC 端点查询 | ⭐⭐⭐ **发现其他服务** |
| **spoolss** | 打印后台处理 | 打印管理 | ⭐⭐⭐ **PrintNightmare, 强制认证** |
| **lsass** | 本地安全认证子系统 | 安全令牌 | ⭐⭐⭐⭐ **高价值，但保护严格** |

### 6.3 利用 IPC$ 枚举域用户

```
rpcclient -U '' -N target  ← 匿名连接（如允许）
  → 如果不允许匿名 → 用已知账户

rpcclient -U domain/user%pass target
  > enumdomusers              ← 列出所有域用户
  user:[administrator] rid:[0x1f4]
  user:[guest] rid:[0x1f5]
  user:[kadmin] rid:[0x444]
  user:[sqlsvc] rid:[0x445]

  > enumdomgroups             ← 列出所有域组
  group:[Domain Admins] rid:[0x200]
  group:[Domain Users] rid:[0x201]

  > queryuser 0x444           ← 查询用户详细信息
  User Name : kadmin
  Full Name : KAdmin
  Home Drive: \\server\home\kadmin
  Last Logon: 2026-05-15 14:30:00
```

### 6.4 使用命名管道的攻击

```
强迫认证 (Coerced Authentication):
  Printer Bug (MS-RPRN):
    \\attacker@80/test  ← WebDAV 路径
  
  PetitPotam (MS-EFSR):
    \\attacker/test
  
  效果: 让域控向我发起 NTLM 认证 → 抓取域控的哈希

利用命名管道传递恶意 DLL:
  如果某个服务（如 SQL Server）以 SYSTEM 运行
  并且允许连接命名管道
  → 利用该管道执行命令
```

---

## 七、SMB 在 AD 环境中的角色

### 7.1 域控 SMB 的特殊性

```
域控制器暴露的 SMB 共享:
  SYSVOL: \\domain\SYSVOL
    → 域策略文件（含登录脚本、GPO）→ 有时包含明文密码

  NETLOGON: \\domain\NETLOGON
    → 登录脚本位置

  C$ / ADMIN$:
    → 仅域管理员可访问
    → 完全控制的入口

重要: 域控的 SMB 端口不可禁用（AD 依赖 SMB）
```

### 7.2 SMB 与 Active Directory 的关系

```
AD 使用 SMB 做:
  1. 域成员与 DC 之间的认证（Netlogon 管道）
  2. GPO 下发（文件复制通过 SYSVOL）
  3. 组策略结果报告
  4. 域控制器之间的复制（FRS/DFSR）

如果 SMB 被阻断 → AD 功能瘫痪（但不是所有功能）
```

---

## 八、从原理推导攻击面

### 攻击面 1：签名不强制

```
假设: 「管理员配置了 SMB 签名」
  但：配置了「启用」≠ 配置了「强制」

签名启用 = 支持签名（但不强制）
签名强制 = 只接受有签名的请求

如果只启用不强制 → 攻击者伪造无签名的请求 → Relay 成功

可推导攻击:
  1. 扫描网络 → 找出 SMB 不强制签名的服务器
  2. 用 Responder 捕获认证
  3. 用 ntlmrelayx Relay 到不强制签名的服务器
  4. 获得该服务器上的用户权限
```

### 攻击面 2：SMBv1 的遗留

```
假设: 「系统已经安装了最新补丁」
  但：SMBv1 仍然启用

可推导攻击:
  即使打了 EternalBlue 补丁（MS17-010）
  SMBv1 本身仍是数千次审计过的协议
  新的 SMBv1 漏洞仍有可能被发现
  （参考 CVE-2020-0796 SMBv3 的不久前也被找到）

最佳实践: 禁用 SMBv1
```

### 攻击面 3：命名管道的匿名访问

```
假设: 「IPC$ 不需要认证」
  但：匿名访问 ≠ 完全访问

不同的命名管道有不同的「匿名访问」策略:
  一些管道允许匿名连接（如 epmapper）
  一些管道需要认证（如 samr）
  域控的默认配置（含 Windows 2008 之前）允许匿名枚举

可推导攻击:
  匿名枚举 SAMR → 获取所有域用户名
  有了用户名 → 密码喷洒 → 找到弱密码账户
```

### 攻击面 4：NTLM 无抗重放

```
假设: 「密码是安全的，所以认证是安全的」
  但：NTLM 没有「连接绑定」——认证可被重放

可推导攻击:
  攻击者不需要破解密码
  攻击者只需要「转发」认证过程
  → 这是 SMB Relay 的根本原理
  → 只有 SMB 签名可防御
```

### 攻击面 5：隐藏共享的"隐藏"

```
假设: 「隐藏共享（$）是安全的」
  但：$ 只是从网络浏览列表中隐藏
     知道名称就可以访问

可推导攻击:
  \\target\C$  → 访问 C 盘（需管理员）
  \\target\ADMIN$  → 访问 Windows 目录
  \\target\IPC$ → 命名管道

这些隐藏共享是所有域管理员的标准工具
也是所有攻击者的首选目标
```

### 攻击面 6：Windows 的密码缓存

```
假设: 「输入一次密码后就是安全的」
  但：Windows 缓存登录凭据（LSASS 进程）

可推导攻击:
  1. 获得 SYSTEM 权限
  2. 从 LSASS 进程内存中提取 NTLM 哈希
  3. 使用哈希做 Pass-the-Hash
  4. 以该用户的身份访问其他 SMB 服务
  （工具: mimikatz sekurlsa::logonpasswords）
```

---

## 九、渗透测试中的 SMB 检查清单

```bash
# 1. SMB 版本探测
nmap -p 445 --script smb-protocols target
# → 确认 SMBv1 是否启用

# 2. SMB 签名状态
nmap -p 445 --script smb2-security-mode target
# → 确认是否需要 SMB 签名

# 3. 生成 Relay 目标列表
crackmapexec smb --gen-relay-list targets.txt 192.168.1.0/24

# 4. 枚举共享
smbclient -L //target -U user
crackmapexec smb target -u user -p pass --shares

# 5. SMB 暴力破解
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt

# 6. Pass-the-Hash
impacket-wmiexec -hashes :NTHASH user@target
impacket-psexec -hashes :NTHASH user@target

# 7. 枚举域用户（通过 SAMR 管道）
rpcclient -U '' -N target
> enumdomusers

# 8. SMB Relay 攻击
# responder.conf → 关闭 SMB 服务器
responder -I eth0 -rdw
ntlmrelayx.py -tf targets.txt -smb2support

# 9. 命名管道枚举
net use \\target\IPC$ /u:user password
# 然后用 rpcclient / impacket 交互

# 10. EternalBlue 检查
nmap -p 445 --script smb-vuln-ms17-010 target
msf6: use auxiliary/scanner/smb/smb_ms17_010
```

---

## 十、总结

### SMB 安全的本质

```
SMB 是一个设计复杂、版本漫长演进的协议：
  1.0 → 不安全（EternalBlue）
  2.0 → 部分安全（有签名但不强制）
  3.0 → 较安全（加密可选）
  3.1.1 → 安全（强制安全协商、预认证完整性）
```

其安全核心依赖于三个配置：

| 配置 | 作用 | 必须的？ |
|------|------|---------|
| **禁用 SMBv1** | 消除最危险的历史版本 | **✅ 必须** |
| **强制 SMB 签名** | 防御 Relay 攻击 | **✅ 必须** |
| **启用 SMB 加密** | 防御流量嗅探 | **✅ 推荐** |

**渗透测试视角：SMB 是内网渗透的"高速公路"。** 从匿名枚举到暴力破解、从 Pass-the-Hash 到 SMB Relay、从 EternalBlue 到 IPC$ 管道——SMB 提供了内网攻击的绝大多数入口。

**最关键的检测：** SMB 签名是否强制。如果非强制 → 整个网络可能都被 Relay 攻破。
