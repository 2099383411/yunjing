# Active Directory 域安全 — 攻击路径、ACL 滥用与横向移动

> Level 0: 基础原理 / 网络安全
> 前置知识：Kerberos 协议 (06-kerberos-security.md)、NTLM 协议 (07-ntlm-security.md)
> 适用场景：企业内网渗透、AD 域安全评估、红队渗透

---

## 一、AD 域架构基础

### 1.1 域核心组件

```
┌────────────────────────────────────────────────────────────┐
│                   Active Directory 域                        │
│                                                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ 域控 (DC)   │  │ 域控 (DC)   │  │ 域控 (DC)   │         │
│  │ 主 (PDC)    │  │ 副本        │  │ 全局编录     │         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
│         │                │                │                │
│         └────────────────┼────────────────┘                │
│                          │                                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │        NTDS.DIT (AD 数据库)                            │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────────────┐    │  │
│  │  │ 用户对象  │ │ 计算机对象│ │ 组策略对象 (GPO)    │    │  │
│  │  │ 组对象    │ │ 服务账户  │ │ OU / 容器          │    │  │
│  │  └──────────┘ └──────────┘ └────────────────────┘    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌─────────────┐  ┌─────────────┐                          │
│  │ 成员服务器   │  │ 工作站      │                          │
│  └─────────────┘  └─────────────┘                          │
└────────────────────────────────────────────────────────────┘
```

### 1.2 关键数据库表 (NTDS.DIT)

| 表 | 内容 | 攻击者关注点 |
|:---|:-----|:-----------|
| `datatable` | 所有对象（用户、组、计算机、GPO） | 用户 NTLM Hash、组成员关系 |
| `sd_table` | 安全描述符（ACL） | **谁对什么有权限** |
| `link_table` | 链接属性（组成员、委派） | 域信任关系 |
| `hiddentable` | 已删除对象 | 曾经存在的账户 |

### 1.3 域信任关系

```
类型：                   信任方向：
┌────────────┐          ┌──────────┐
│ 父子域信任  │          │ 单向 →   │
│ 树信任      │          │ 双向 ↔   │
│ 森林信任    │          │ 快捷信任 │
│ 外部信任    │          └──────────┘
│ 林信任      │
└────────────┘

关键：信任不代表可访问！需要额外权限
```

**域信任攻击面：**
- SID History 注入（跨信任）
- TGT 委派跨信任
- 林信任的 SID 过滤配置

---

## 二、AD 枚举技术

### 2.1 无凭证枚举

| 技术 | 工具 | 可获取信息 |
|:----|:----|:---------|
| LDAP 匿名查询 | ldapsearch | 部分 AD 配置（默认禁止） |
| SMB 空会话 | enum4linux | 用户列表、共享、RID 枚举 |
| DNS 区域传输 | dig axfr | 域中所有服务器名 |
| Kerberos 用户枚举 | Kerbrute | 有效用户名（无密码） |

### 2.2 低权限凭证枚举

| 命令/工具 | 获取信息 |
|:---------|:--------|
| `net user /domain` | 域用户列表 |
| `net group /domain` | 域组列表 |
| `PowerView` | AD 对象完整信息 |
| `BloodHound (SharpHound)` | **攻击路径图** |
| `ADExplorer` | AD 对象属性全览 |

### 2.3 BloodHound 攻击路径查询

**关键查询：**

```
# 最短路径到域管理员组 (Shortest Path to DA)
MATCH p = (n {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@TESTLAB.LOCAL"})
RETURN p

# 拥有管理员权限的用户的会话 (Admin Sessions)
MATCH (c:Computer)-[:HasSession]->(u:User)
WHERE u.domain = "TESTLAB.LOCAL"
RETURN c.name, u.name

# 基于 ACL 的提权路径 (ACL abuse)
MATCH p = (u:User)-[{acl:true}]->(g:Group {highvalue:true})
RETURN p
```

---

## 三、AD 攻击路径分类

### 3.1 ACL/权限滥用 (最普遍)

| 权限 | 可执行操作 | 影响 |
|:----|:---------|:-----|
| `GenericAll` | 完全控制对象 | 可直接改密码 / 加组成员 |
| `GenericWrite` | 修改对象属性 | 改属性引发权限提升 |
| `WriteOwner` | 更改所有者 | 拥有后可进一步提权 |
| `WriteDACL` | 修改 ACL | 可授予自己完全控制 |
| `ForceChangePassword` | 改密码 | 无需原密码 |
| `AddMember` | 添加组成员 | 直接进入高权限组 |
| `AddSelf` | 将自己加入组 | 同上 |
| `ExtendedRight` | 特定操作 | 如"重置密码" |

**经典 ACL 攻击链：**
```
① 发现用户 A 对用户 B 有 WriteOwner 权限
② 将用户 B 的所有者改为用户 A
③ 用户 A 获得对用户 B 的 GenericWrite
④ 修改用户 B 的属性 → 加用户 A 到高权限组
⑤ 用户 A 成为 Domain Admin
```

### 3.2 GPO 滥用

| GPO 修改能力 | 攻击效果 |
|:------------|:--------|
| 添加启动脚本 | 在所有受影响的机器上执行代码 |
| 修改防火墙规则 | 开放端口 |
| 修改用户权限分配 | 添加 SeDebugPrivilege / SeTakeOwnershipPrivilege |
| 修改注册表 | 多种后门 |
| 修改服务配置 | 修改服务的启动账户 |

**检测：** 谁可以修改 GPO？
- `WriteProperty` 或 `CreateChild` 在 GPO 对象上
- 组策略创建者所有者 (Group Policy Creator Owners) 组成员
- 默认：Domain Admins / Enterprise Admins

### 3.3 组策略偏好 (GPP) 凭据泄露

```
路径：\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\{GUID}\MACHINE\
      Preferences\Groups\Groups.xml

// 文件中的 cpassword 用 AES-256 加密
// 但微软公开了加密密钥！(2006-2014年所有GPP)

解密：gpp-decrypt <CPASSWORD>
```

### 3.4 基于资源的约束委派 (RBCD) 滥用

**原理：** Windows Server 2012+ 引入，允许目标服务控制谁可以委派给它

```
攻击条件：
┌─────────────────────────────────────────────┐
│ ① 拥有对计算机账户的 GenericAll/GenericWrite │
│ ② 或拥有对计算机账户的 AddAllowedToAct      │
│ ③ 可以创建机器账户（默认域用户可创建10个）    │
└─────────────────────────────────────────────┘

攻击流程：
① 创建机器账户 (MachineAccountQuota)
② 设置目标计算机的 msDS-AllowedToActOnBehalfOfOtherIdentity
③ 以机器账户身份 Kerberos 委派到该计算机 → SYSTEM
```

### 3.5 SID History 攻击

| 类型 | 描述 | 条件 |
|:----|:-----|:----|
| **SID History 注入** | SID History 属性用于域迁移 | 需要 `DS-Replication-Get-Changes` |
| **Extra SID 攻击** | 在 Kerberos TGT 中添加额外 SID | 需要 KRBTGT Hash |
| **跨林 SID 过滤** | 林信任默认启用 SID 过滤 | 禁用时可跨林提权 |

---

## 四、AD 攻击工具与命令

### 4.1 信息收集

```powershell
# PowerView
Get-NetUser -Username admin* | select samaccountname,memberof
Get-NetGroup -GroupName "Domain Admins"
Get-NetComputer -FullData | select dnshostname,operatingsystem
Find-LocalAdminAccess                              # 当前用户有本地管理员权限的机器
Invoke-UserHunter                                  # 发现指定用户登录过的机器

# BloodHound 收集器
SharpHound.exe -c All --LDAPUser user --LDAPPass pass -d domain.local
```

### 4.2 利用工具

```bash
# impacket 工具集 (Linux)
impacket-GetNPUsers domain.local/ -usersfile users.txt -request -format hashcat
impacket-GetUserSPNs domain.local/user:pass -request
impacket-secretsdump domain.local/user:Password123@DC-IP -just-dc
impacket-smbexec domain.local/user:Password123@TARGET
impacket-wmiexec domain.local/user:Password123@TARGET

# ceritpy (ADCS 攻击)
certipy-ad find domain.local/user:Password123@DC-IP -vulnerable
certipy-ad req domain.local/user:Password123@CA-SRV -ca CA-NAME -template User
certipy-ad auth -pfx certificate.pfx -dc-ip DC-IP

# CrackMapExec / NetExec
cme smb TARGETS -u user -p pass --local-auth
nxc smb TARGETS -u user -p pass --shares
```

### 4.3 横向移动

| 工具 | 认证方式 | 需要条件 |
|:----|:--------|:--------|
| impacket-psexec | SMB | ADMIN$ 可写 |
| impacket-wmiexec | WMI (RPC) | RPC 可用，管理员权限 |
| impacket-smbexec | SMB (RPC) | SMB 可用，管理员权限 |
| impacket-dcomexec | DCOM | DCOM 可用，管理员权限 |
| impacket-atexec | 任务计划程序 | SMB 可用，管理员权限 |
| winrm/evil-winrm | WinRM (HTTP/HTTPS) | WinRM 启用，管理员权限 |

---

## 五、AD 攻击完整攻击链

```
Phase 1: 侦察
┌────────────────────────────────────────────────────────┐
│ 信息收集 → 域名、DC IP、用户名、SPN、ACL、组关系       │
│ 工具：BloodHound / PowerView / enum4linux / ldapsearch │
└────────────────────────────────────────────────────────┘
         │
         ▼
Phase 2: 初始访问
┌────────────────────────────────────────────────────────┐
│ Kerberoasting / AS-REP Roasting / 密码喷洒 / NTLM 中继 │
│ SQL 注入 → xp_cmdshell → OS shell                    │
└────────────────────────────────────────────────────────┘
         │
         ▼
Phase 3: 权限提升
┌────────────────────────────────────────────────────────┐
│ ACL 滥用 / RBCD / ADCS / GPO 滥用 / Local Privesc     │
│ 目标：获得域管理员或服务器管理员权限                     │
└────────────────────────────────────────────────────────┘
         │
         ▼
Phase 4: 横向移动
┌────────────────────────────────────────────────────────┐
│ 凭据窃取 → Hash/票据 → PTH/PTT → 更多服务器           │
│ 目标：逐步靠近域控/关键服务器                           │
└────────────────────────────────────────────────────────┘
         │
         ▼
Phase 5: 域控接管
┌────────────────────────────────────────────────────────┐
│ DCSync → KRBTGT Hash → 黄金票据 → 域全域控             │
│ 或：ADCS → 证书 → TGT → 域控权限                      │
└────────────────────────────────────────────────────────┘
```

---

## 六、检测与防御

### 6.1 防御优先级

| 优先级 | 措施 | 效果 |
|:-----:|:----|:----|
| 🥇 | 最小权限原则 | 遏制 ACL 滥用 |
| 🥇 | 启用 SMB Signing | 防止 NTLM 中继 |
| 🥇 | 禁用 LLMNR/NBT-NS | 防止 Hash 捕获 |
| 🥈 | 受保护的组策略 | 限制 GPO 修改权限 |
| 🥈 | LAPS (本地管理员密码) | 防止 Hash 复用 |
| 🥈 | Credential Guard | 防止 PTH |
| 🥉 | 监控事件 4662/5136 | 检测 ACL 修改 |
| 🥉 | 定期审查委派 | 减少委派攻击面 |

### 6.2 监控关键事件

| 事件 ID | 含义 |
|:-------:|:-----|
| 4624 | 登录成功 |
| 4625 | 登录失败（密码喷洒有用） |
| 4662 | 对目录服务对象执行操作 |
| 4670 | 对象权限被修改 |
| 4688 | 新进程创建（横向移动检测） |
| 4740 | 账户被锁定 |
| 4768 | TGT 请求（黄金票据检测） |
| 4769 | ST 请求（Kerberoasting 检测） |
| 5136 | 目录服务对象被修改 |
| 5140 | 文件共享被访问 |

---

## 七、LLM 推理辅助

### 触发条件
- "AD"、"域"、"域控"、"DC"、"Active Directory"
- "BloodHound"、"ACL"、"委派"、"GPO"
- "DCSync"、"KRBTGT"、"SID"、"林信任"
- "提权"、"横向移动"、"域渗透"

### 检测信号表
| 信号 | 含义 | 置信度 |
|:----|:-----|:------:|
| 用户对另一个用户有 GenericAll | ACL 滥用链起点 | 高 |
| SYSVOL 中有 Groups.xml + cpassword | GPP 凭据泄露 | 极高 |
| 机器账户 MachineAccountQuota > 0 | RBCD 可利用 | 中 |
| DC 开放 443 + /certsrv | ADCS ESC8 中继可能 | 高 |
| 非约束委派的服务器 | TGT 窃取可能 | 极高 |
| msDS-AllowedToDelegateTo 非空 | 约束委派可滥用 | 中 |

### 验证步骤
1. 枚举域信息 → 域名、功能级别、DC 列表
2. 收集域用户列表 → 密码策略 → 账户状态
3. 运行 BloodHound 收集器 → 分析攻击路径
4. 尝试 Kerberoasting / AS-REP Roasting
5. 检查 SYSVOL 中的 GPP 凭据
6. 扫描 ADCS 端点
7. 检查 ACL 权限链

### 利用链扩展
- AS-REP Roasting → 密码 → 登录 → BloodHound → ACL 滥用 → DCSync
- Responder → NTLM 中继 → Shell → BloodHound → RBCD → DC
- ADCS ESC8 → 证书 → TGT → DCSync
- SMB 空会话 → 用户枚举 → 密码喷洒 → Kerberoasting → 服务账户 → 服务器访问

### 关联攻击面
- [Kerberos 安全](06-kerberos-security.md) → 域渗透协议基础
- [NTLM 安全](07-ntlm-security.md) → 初始访问关键入口
- [Windows 安全](09-windows-security.md) → 本地提权与 Token 操纵
- [SSL/TLS](protocols/03-tls-security.md) → ADCS 的 PKI 基础

### 常见误判
- 有 ACL 权限 ≠ 立即可以利用（有些需要额外条件）
- BloodHound 发现路径 ≠ 实际可利用（防火墙/网络隔离可能阻断）
- 机器账户配额 > 0 不是漏洞（默认配置，需要辅助条件才能利用）
- 非约束委派可被利用，但需要诱导域管理员访问（不是即时的）
- ADCS 发现不代表可利用（需要检测特定 ESC 条件）
