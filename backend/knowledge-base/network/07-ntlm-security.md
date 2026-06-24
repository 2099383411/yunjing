# NTLM 协议安全 — 挑战-响应、Pass-the-Hash 与中继攻击

> Level 0: 基础原理 / 网络安全
> 适用场景：Windows 内网渗透、NTLM 中继攻击、Pass-the-Hash 利用

---

## 一、NTLM 协议架构

### 1.1 协议版本

| 版本 | 名称 | 安全性 | 当前状态 |
|:----|:----|:-----:|:--------|
| LM | LAN Manager | ❌ 极弱 | 默认禁用 |
| NTLMv1 | Windows NT LAN Manager | ❌ 弱 | 生产环境偶见 |
| NTLMv2 | NTLM 第二版 | ⚠️ 中等 | 当前默认 |

### 1.2 NTLMv2 握手流程

```
Client                                    Server
  │                                          │
  │ ① 协商 (Negotiate)                       │
  │ ──────────────────────────────────→       │
  │                                          │
  │ ② 挑战 (Challenge)                       │
  │ ←──────────────────────────────────       │
  │           8字节随机数 (Server Challenge)   │
  │                                          │
  │ ③ 认证 (Authenticate)                    │
  │ ──────────────────────────────────→       │
  │           NTOWFv2 + Challenge + Time      │
  │                                          │
  │ ④ 验证                                    │
  │    Server → DC: Netlogon (需通过)         │
  │                                          │
```

### 1.3 哈希计算过程

```
NTLM Hash (NTOWFv1) = MD4(UTF-16LE(password))

NTLMv2 响应计算：
┌─────────────────────────────────────────────┐
│ NTOWFv2 = HMAC-MD5( NTLM Hash,              │
│                       UserName + Domain )    │
│                                             │
│ NTLMv2_Hash = HMAC-MD5( NTOWFv2,            │
│                        ServerChallenge +     │
│                        Blob )                │
│                                             │
│ Blob = Timestamp + Random +                 │
│        TargetInfo + Others                  │
└─────────────────────────────────────────────┘
```

**关键点：**
- NTLM Hash = MD4(密码) — 单向不可逆
- NTLMv2 响应中加入时间戳防止重放
- Server Challenge 由服务器随机生成

---

## 二、攻击面分析

### 2.1 Pass-the-Hash (PTH)

**原理：** NTLM 认证使用 Hash 而非明文密码，攻击者获得 Hash 即可直接认证

```
① 从 LSASS/memory dump/SAM 获取 NTLM Hash
② 使用 Hash 直接进行 NTLM 认证
③ 无需知道明文密码

工具：impacket-wmiexec、impacket-smbexec、CrackMapExec
```

**限制：**
- 只对 NTLM 认证有效（Kerberos 需要 TGT）
- 需要目标服务接受 NTLM 认证
- 某些服务（如 RDP）默认不接受 PTH

### 2.2 NTLM Relay (中继攻击)

**原理：** 攻击者位于 Client 和 Server 中间，将 Client 的 NTLM Challenge-Response 中继到目标 Server

```
                        攻击者
Client ──→ 连接请求 ──→ ┌───────┐ ──→ 中继到目标 ──→ Server
                        │ Relay │                     │
                        │       │ ←─ Server Challenge─ │
                        └───────┘                     │
Client ←── Challenge ───┘    ↑                        │
   ↓                          │                        │
   Client 计算响应             │                        │
   ↓                          │                        │
Client ──→ 响应 ────────────┘  ──→ 中继响应 ──────────→ │
                                                       │
                                      验证通过 ✅ (攻击者以Client身份)
```

**SMB Signing 的影响：**
| SMB Signing 状态 | Client | Server | 可中继？ |
|:----------------:|:------:|:------:|:--------:|
| 禁用 | — | — | ✅ 可 |
| 启用 | 任意 | 强制 | ❌ 不可 |
| 启用 | 强制 | 任意 | ❌ 不可 |

**检测：** 扫描网络中 SMB Signing 禁用的机器

### 2.3 LLMNR/NBT-NS 投毒 (Poisoning)

**原理：** Windows 解析无法通过 DNS 解析的主机名时，会广播 LLMNR/NBT-NS 查询攻击者冒充目标响应，捕获 NTLM Hash

```
Client: "谁是 FILE-SRV?"  (广播)
   │
   ├── DNS Server: 不知道 (N/A)
   │
   ├── LLMNR 广播 (多播)
   │       └── 攻击者: "我是 FILE-SRV! 快来认证!"
   │
   └── NBT-NS 广播
           └── 攻击者: "我是 FILE-SRV! 快来认证!"

Client → 攻击者的伪造服务 → NTLM 握手 → 攻击者捕获 Hash
```

**工具：** Responder, Inveigh

### 2.4 NTLMv1 降级攻击

**原理：** 强制客户端使用 NTLMv1 替代 NTLMv2，NTLMv1 的 Challenge-Response 可以在 5 分钟内破解出密码

```
攻击方式：
① 修改组策略或注册表强制 NTLMv1
② 响应协商时声称"我只支持 NTLMv1"
③ 捕获 NTLMv1 响应 → 破解 → 密码

破解速度：NTLMv1 响应 ≈ 5 分钟（GPU）
```

### 2.5 中继到 LDAP/S (ADCS Web Enrollment)

**原理：** 某些服务（如 ADCS Web Enrollment）不支持 NTLM 签名，可接收中继的 NTLM 认证并授予证书

```
① 捕获 NTLM 认证
② 中继到 http://CA-SRV/certsrv/
③ 请求基于 NTLM 认证的证书
④ 用证书请求 TGT → 域控权限

工具：certipy (ADCS 攻击)
```

---

## 三、利用链组合

### 3.1 从零到初始访问

```
域外/工作组
   │
   ▼
Responder 监听 → 等待 LLMNR/NBT-NS 请求
   │
   ▼
捕获 NTLMv2 Hash (或中继)
   │
   ├── 破解 → 获得明文密码 → 登录
   │
   └── 中继到 SMB (SMB Signing 禁用)
           │
           ▼
        获得 Shell (impacket-smbexec/wmiexec)
```

### 3.2 从初始访问到域控

```
低权限 Shell
   │
   ▼
检查 SMB Signing → 扫描禁用机器列表
   │
   ▼
Responder + SMB Relay → 捕获高权限用户的 NTLM 认证
   │
   ▼
中继到目标服务器 → 获得高权限 Shell
   │
   ▼
BloodHound 枚举 → DCSync → 域控
```

---

## 四、检测与防御

| 攻击类型 | 检测方法 | 防御措施 |
|:---------|:--------|:---------|
| Pass-the-Hash | 监控同一 IP 在不同机器上使用不同账户 | 启用 Credential Guard；启用 LSA 保护 |
| NTLM Relay | 网络设备检测 NTLM 认证中网络地址不匹配 | 启用 SMB Signing；启用 EPA |
| LLMNR/NBT-NS 投毒 | 检测网络中未经授权的 mDNS 响应 | 通过组策略禁用 LLMNR/NBT-NS |
| NTLMv1 降级 | 监控 NTLMv1 认证事件 | 完全禁用 NTLMv1 |
| ADCS 中继 | 监控非交互式证书请求 | 启用 HTTPS + EPA；启用 NTLM 封锁 |

---

## 五、LLM 推理辅助

### 触发条件
- "NTLM"、"Hash"、"Pass-the-Hash"、"PTH"
- "中继"、"Relay"、"Responder"、"SMB Signing"
- "LLMNR"、"NBT-NS"、"NetNTLM"、"Challenge"
- "impacket" + "smbexec/wmiexec/atexec"

### 检测信号表
| 信号 | 含义 | 置信度 |
|:----|:-----|:------:|
| SMB 端口 (445) 开放 + Signing 禁用 | 可中继攻击 | 高 |
| 网络中大量 LLMNR 广播 | 无对应 DNS，可投毒 | 高 |
| 事件 4624 + 登录类型 3 + NTLM 认证 | 网络登录，可追溯 | 中 |
| LSASS 中提取的 NTLM Hash | 可 PTH | 极高 |

### 验证步骤
1. 扫描所有存活主机的 SMB Signing 状态
2. 识别网络中启用了 LLMNR/NBT-NS 的机器
3. 检查域控 ADCS 端口 (443/certsrv) 是否暴露
4. 检查组策略中 NTLM 封锁级别
5. 验证当前凭证可访问的资源范围

### 利用链扩展
- Responder → Hash 捕获 → Hashcat 破解 → 横向移动
- Responder + SMB Relay → 获得 Shell → BloodHound → DCSync
- NTLM 中继到 ADCS → 证书 → TGT → 域控
- NTLMv1 抓包 → 5 分钟破解 → 明文密码

### 关联攻击面
- [Kerberos 安全](06-kerberos-security.md) → NTLM→Kerberos 转换
- [AD 域安全](未完成) → 域攻击路径
- [HTTP 协议安全](02-http-protocol-security.md) → Web 应用的 NTLM 认证
- [Windows 安全](未完成) → LSASS 保护、Credential Guard

### 常见误判
- NTLMv2 Hash 破解成本高，8位混合密码平均需要数天
- SMB Signing 启用 ≠ 无法利用（仍可中继到其他协议）
- Responder 收到的 Hash 不一定是目标用户的（可能来自其他服务）
- PTH 对 RDP 默认无效（需 wdigest 启用或注册表修改）
