# 05. SSH 协议安全深度分析

> 领域：网络协议安全
> 关联：03-tls-protocol-security.md（类似安全通道协议对比）、04-dns-protocol-security.md（DNS 正确解析后才能 SSH）
> 学习路线：TCP/IP → HTTP → TLS → DNS → SSH（当前）

---

## 一、SSH 协议概述

SSH (Secure Shell) 由 Tatu Ylönen 于 1995 年设计，用于替代不安全的 rsh/rlogin/telnet。

### 1.1 协议栈中的位置

```
应用层 (Shell/SFTP/SCP/端口转发)
    ↑
SSH 连接层 — 通道管理、会话复用、端口转发
SSH 认证层 — 用户认证（密码、公钥）
SSH 传输层 — 密钥交换、服务器认证、加密、完整性
TCP (端口 22)
```

**三层架构设计：** 传输层建立安全通道 → 认证层验证身份 → 连接层复用通道——每层独立、松耦合。

### 1.2 SSH-1 vs SSH-2

| 特性 | SSH-1 (1995) | SSH-2 (RFC) |
|------|:-----------:|:-----------:|
| 架构 | 单层 | **三层** |
| 密钥交换 | RSA（无 PFS） | **DH/ECDH（完美前向保密）** |
| 完整性 | CRC-32（弱） | **HMAC** |
| 通道复用 | 不支持 | 支持 |
| 当前状态 | 已废弃 | 唯一标准 |

**SSH-1 致命缺陷：** CRC-32 完整性 + 固定加密密钥 → 可插入恶意数据到加密流。

---

## 二、SSH 传输层协议（握手）

### 2.1 完整握手流程

```
Client                                     Server
  │──── TCP 连接 ──────────────────────────►│
  │──── "SSH-2.0-OpenSSH_9.3\r\n" ────────►│
  │◄──── "SSH-2.0-OpenSSH_8.9\r\n" ────────│  ← 版本交换（明文）
  │──── SSH_MSG_KEXINIT ──────────────────►│
  │◄──── SSH_MSG_KEXINIT ──────────────────│  ← 算法协商（明文）
  │──── SSH_MSG_KEX_ECDH_INIT ────────────►│
  │◄──── KEX_ECDH_REPLY (公钥+主机密钥+签名)│  ← 密钥交换
  │         密钥推导 (共享密钥 K)             │
  │──── SSH_MSG_NEWKEYS ──────────────────►│
  │◄──── SSH_MSG_NEWKEYS ──────────────────│  ← 启用加密
  ══════ 以下全部加密 ═══════════════════════
  │──── SERVICE_REQUEST ──────────────────►│
  │◄──── SERVICE_ACCEPT ───────────────────│
  │──── USERAUTH_REQUEST ─────────────────►│
  │◄──── USERAUTH_SUCCESS ────────────────│
  ══════ 以下可请求连接服务 ════════════════
```

### 2.2 版本交换

```
双方发送版本标识明文:
  客户端: "SSH-2.0-OpenSSH_9.3 Ubuntu-3\r\n"
  服务端: "SSH-2.0-OpenSSH_8.9p1 Debian-5\r\n"
```

**安全含义：** 明文暴露 SSH 版本 → 指纹识别。已知版本漏洞可针对性利用。

### 2.3 算法协商 (KEXINIT)

双方交换支持的算法列表，协商出共同的第一优先算法：

```
Key Exchange (KEX):
  curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256

Server Host Key:
  ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512

Encryption:
  chacha20-poly1305, aes256-gcm, aes256-ctr

MAC:
  hmac-sha2-256-etm, hmac-sha1
```

**安全含义：** 弱算法（如 diffie-hellman-group1-sha1）可能仍在列表中。KEXINIT 本身明文，但 exchange_hash 包含双方 KEXINIT → 防篡改。

### 2.4 密钥交换 (ECDH)

```
1. 客户端生成临时 ECDH 密钥对 (c_priv, c_pub)
2. 服务器生成临时 ECDH 密钥对 (s_priv, s_pub)
3. 双方独立计算 K = ECDH(己方私钥, 对方公钥)
4. 服务器签名: signature = sign(host_private_key, exchange_hash)
5. 客户端验证服务器签名

exchange_hash = hash(
  双方版本字符串 + 双方KEXINIT + 主机密钥 +
  双方临时公钥 + 共享密钥K
)
```

**安全要点：**
- **完美前向保密 (PFS)：** 临时密钥一次性，主机密钥泄露不影响历史会话
- exchange_hash 包含全部握手消息 → 任何篡改导致签名验证失败
- 签名绑定主机密钥 → 证明服务器身份

### 2.5 密钥派生

从 K 和 H 派生 6 个密钥（双方各 3 个）：
```
IV C→S, IV S→C          ← 初始化向量
Encryption Key C→S, S→C  ← 独立加密密钥
MAC Key C→S, S→C         ← 独立完整性密钥
```

每次密钥重交换生成新 K → 派生新密钥。

### 2.6 二进制包格式

```
+-------------------+-------------------+-------------------+-------------------+
| 长度 (4B)          | PAD_LEN (1B)      | Payload (可变)    | Padding (可变)     |
+-------------------+-------------------+-------------------+-------------------+
| MAC (可变)         |
+-------------------+
```

- 隐式序列号防重放（MAC 中包含 seq_num）
- Padding 防流量分析（长度随机化）
- MAC 保证完整性（加密不防篡改）

---

## 三、SSH 认证层

全部在加密通道内进行。

### 3.1 认证方法

| 方法 | 安全性 | 说明 |
|------|--------|------|
| **password** | 低 | 密码在加密通道传输（但仍可暴力破解） |
| **publickey** | 高 | 私钥签名挑战（私钥从不传输） |
| **keyboard-interactive** | 中 | 多轮，支持 2FA |
| **hostbased** | 低 | 信任客户端主机名 |
| **gssapi-keyex** | 高 | Kerberos 认证 |

### 3.2 公钥认证流程（核心机制）

```
1. 客户端发送公钥 → 服务器检查 authorized_keys
2. 服务器返回 PK_OK（确认公钥有效）
3. 客户端用私钥签名 (session_id + 认证请求)
4. 服务器验证签名 → SUCCESS
```

**安全要点：**
- 私钥**从不离开客户端**
- 签名绑定 session_id → 防签名重放
- 私钥可加密码保护（还需额外输入）

### 3.3 authorized_keys

```
~/.ssh/authorized_keys

格式:
  ssh-ed25519 AAAAC3... alice@laptop

可选限制:
  from="192.168.*"    → IP 限制
  command="/bin/rsync" → 命令限制
  no-port-forwarding  → 禁止端口转发
  no-pty              → 不分配 TTY
  restrict            → 全部限制
```

**这是 SSH 最关键的本地文件。可写入 = 永久后门。**

### 3.4 SSH 证书认证

```
CA 签发证书（优于公钥的集中管理方案）:
  ssh-keygen -s ca_key -I identity -n user -V +52w user_key.pub

证书包含: 公钥 + CA 签名 + 有效期 + 主体 + 权限
服务端: TrustedUserCAKeys /etc/ssh/ca_key.pub

优势:
  - 集中管理（无需分发公钥）
  - 自动过期（无需手动撤销）
  - 适合大规模部署
```

---

## 四、SSH 连接层（通道复用）

### 4.1 通道概念

```
认证成功后可开启多个逻辑通道:
  Channel 0: Shell 会话
  Channel 1: SFTP 文件传输
  Channel 2: 本地端口转发
  Channel 3: 远程端口转发
```

每个通道有独立 ID、窗口控制、数据类型。

### 4.2 端口转发（核心功能）

| 类型 | 命令 | 用途 |
|------|------|------|
| **本地转发** | `-L 8080:intra:80` | 本地 → SSH → 内网服务 |
| **远程转发** | `-R 8080:local:80` | 公网 → SSH → 本地服务 |
| **动态转发** | `-D 1080` | SOCKS 代理（通过 SSH 转发所有 TCP 流量） |

**渗透测试应用：**
- 本地转发 → 访问内网横向移动
- 远程转发 → 稳定的反向 Shell 替代方案（不受 NAT 限制）
- 动态转发 + proxychains → 完整的内网代理

---

## 五、SSH 攻击面详解

### 5.1 暴力破解

```
hydra -l root -P rockyou.txt ssh://192.168.1.100

SANS 报告: SSH 暴力破解是最常见的成功攻击方式。
攻击的是"人的弱点"——密码不够复杂。

绕过方式:
  - 慢速持续扫描（避开 fail2ban）
  - 分布式攻击（多 IP）
  - 常见用户名 root/admin/ubuntu
```

### 5.2 主机密钥验证绕过

```
第一次连接:
  → 用户看到 "authenticity can't be established"
  → 用户选择 "yes" → 信任攻击者的密钥（如果是 MITM）

危险配置:
  StrictHostKeyChecking=no  ← 禁用主机密钥验证
  UserKnownHostsFile=/dev/null
  → 每次连接都是 MITM 的机会
```

**known_hosts 变更警告不可忽视：** 可能是 MITM 也可能是正常密钥轮换，需人工判断。

### 5.3 CVE-2024-6387 (regreSSHion)

```
类型: 信号处理竞态条件
影响: OpenSSH < 8.5p1（GLIBC），认证前远程代码执行

原理:
  1. LoginGraceTime (120s) 超时 → SIGALRM 触发
  2. 信号处理函数调用 async-signal-unsafe 函数
  3. 竞态条件 → 内存篡改 → 代码执行

影响: 约 1400 万台暴露服务器
修复: OpenSSH 8.5p1+
```

### 5.4 CVE-2018-15473 (用户名枚举)

```
原理: 存在/不存在的用户返回延迟不同（毫秒级）
利用: msf auxiliary(scanner/ssh/ssh_enumusers)
修复: OpenSSH 7.7+
```

### 5.5 SSH Agent 转发滥用

```
ssh -A user@gateway → 远程可访问本地 agent

风险: gateway 被 root 控制 → 可通过 agent socket
          使用用户的私钥 → 访问该私钥允许的所有主机
```

### 5.6 私钥泄露

```
攻击面:
  - 私钥无密码 → U 盘丢失泄露
  - CI/CD 硬编码私钥 → 仓库泄露
  - 备份包含 ~/.ssh/ → 备份泄露
  - 前员工未撤销

利用: ssh -i leaked_key user@target
防御: 私钥加密 + 证书（自动过期）+ 定期轮换
```

---

## 六、从原理推导攻击面

| 假设 | 现实 | 攻击面 |
|------|------|--------|
| 首次主机密钥可信 | 无法验证 | 第一次连接 MITM |
| 用户密码够强 | 多数不够 | 暴力破解 |
| 防火墙阻断入站 = 安全 | 出站 SSH 不受阻 | 反向隧道 |
| 信任跳板机 | 跳板机被攻破 | Agent 转发滥用 |
| 密钥不会变 | 重装/轮换会变 | known_hosts 警告被忽略 |
| 漏洞修复后安全 | 还留有 authorized_keys | 持久后门 |

---

## 七、渗透测试中的 SSH 检查清单

```bash
# 版本获取
nc -nv target 22

# 算法枚举
nmap --script ssh2-enum-algos -p 22 target

# 主机密钥指纹
nmap --script ssh-hostkey -p 22 target

# 用户名枚举 (CVE-2018-15473)
msf6 > use auxiliary/scanner/ssh/ssh_enumusers

# 暴力破解
hydra -l root -P rockyou.txt ssh://target:22

# 私钥破解
ssh2john id_rsa > hash.txt
john --wordlist=rockyou.txt hash.txt

# 漏洞扫描
nmap --script ssh-vuln*.nse -p 22 target

# 建立 SOCKS 代理
ssh -D 1080 user@target
proxychains4 nmap -sT -Pn 10.0.0.0/24

# 检查 authorized_keys
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/
```

---

## 八、总结

SSH 是一个设计严谨的安全协议，但其安全性依赖于：

1. **用户行为**：会检查主机密钥吗？会设强密码吗？
2. **配置管理**：authorized_keys 被审计吗？旧密钥被撤销吗？
3. **实现维护**：OpenSSH 及时更新吗？

**渗透测试视角：SSH 的弱点不在协议层（协议很安全），而在人的使用和配置管理。** 攻击 SSH 最有效的方式仍然是暴力破解弱密码或者窃取无密码的私钥。

SSH 隧道是双刃剑：它是管理员的安全通道，也是攻击者的隐蔽通道。检测异常的 SSH 通信（特别是出站到公网的 SSH）是蓝队的重点关注方向。
