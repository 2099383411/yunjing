# 03. TLS 协议安全深度分析

> 领域：网络协议安全
> 关联：02-http-protocol-security.md（HTTP + TLS 构成 HTTPS）
> 学习路线：TCP/IP 栈 → HTTP 协议 → TLS 协议（当前）

---

## 一、TLS 协议概述

TLS (Transport Layer Security) 是互联网最核心的安全协议。它工作在第4层（传输层）和第7层（应用层）之间 — 在 TCP 之上、应用层之下。

### 1.1 协议栈中的位置

```
应用层 (HTTP/FTP/SMTP)       ← 应用数据
   ↓ 加密后传输
TLS Record Layer             ← 分片、压缩、加密、MAC
   ↓
TCP                          ← 可靠传输
   ↓
IP
```

**关键理解：** TLS 不是对 HTTP 的简单"加锁"，而是在 TCP 之上新建立了一层安全子协议。这层协议有自己的记录格式、状态机和生命周期。

### 1.2 TLS 解决的三个问题

| 问题 | 攻击场景 | TLS 方案 |
|------|---------|---------|
| **保密性** | 通信内容被第三方监听 | 对称加密 (AES-GCM/ChaCha20) |
| **完整性** | 通信内容被篡改 | AEAD 或 HMAC |
| **真实性** | 冒充服务器/客户端 | 证书链 + 数字签名 |

这三点缺一不可。如果只加密不认证 → MITM 可以伪造密钥。如果只认证不加密 → 通信内容裸奔。

### 1.3 版本演变

```
SSL 1.0 (1994) — 从未公开，存在严重缺陷
SSL 2.0 (1995) — 有缺陷，已弃用 (RFC 6176)
SSL 3.0 (1996) — POODLE 攻击，已弃用 (RFC 7568)
TLS 1.0 (1999) — SSL 3.0 的演进，BEAST 攻击
TLS 1.1 (2006) — 缓解 CBC 攻击，已弃用
TLS 1.2 (2008) — 当前主流，广泛部署
TLS 1.3 (2018) — RFC 8446，现代安全标准
```

**安全洞察：** 每个版本的更迭，都是因为前一个版本被发现存在"攻击者可以通过 XX 方式绕过 XX 安全假设"。TLS 版本号本身就是一部安全攻防史。

---

## 二、TLS 1.2 握手协议（详细拆解）

TLS 1.2 的完整握手需要 2 个网络往返（RTT），每一步都包含安全假设。

### 2.1 完整握手流程

```
Client                                     Server
   │                                          │
   │──── ClientHello ────────────────────────►│
   │   (TLS 版本、密码套件列表、随机数)          │
   │                                          │
   │◄──── ServerHello ────────────────────────│
   │   (选定的版本、密码套件、随机数)            │
   │◄──── Certificate ────────────────────────│
   │   (X.509 证书链)                         │
   │◄──── ServerKeyExchange ──────────────────│
   │   (DH/ECDH 参数 + 签名)                  │
   │◄──── ServerHelloDone ───────────────────│
   │                                          │
   │──── ClientKeyExchange ─────────────────►│
   │   (DH 公钥 / 加密的 pre-master-secret)   │
   │──── ChangeCipherSpec ──────────────────►│
   │──── Finished (已加密) ──────────────────►│
   │                                          │
   │◄──── ChangeCipherSpec ──────────────────│
   │◄──── Finished (已加密) ─────────────────│
   │                                          │
   │══════════ Application Data ══════════════│
```

### 2.2 每个消息的安全含义

#### ClientHello
```
结构:
  Protocol Version:   0x0303 (TLS 1.2)
  Random:             32 字节 (28 字节随机 + 4 字节时间戳)
  Session ID:         (可选) 恢复之前会话的标识
  Cipher Suites:      [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ...]
  Extensions:         SNI, ALPN, Supported Groups, Signature Algorithms
```

**安全含义：**
- `Random` 用于防止重放攻击（每个连接随机值不同）
- `Cipher Suites` 的顺序影响安全协商结果（客户端偏好）
- `SNI (Server Name Indication)` 允许在同一 IP 上托管多个证书域 — 但以明文发送，泄露了要访问的域名

#### ServerHello + Certificate

```
服务器选择密码套件，发送证书链。

证书链结构:
  服务器证书 (leaf)
    ├── 颁发者: 中间 CA
  中间 CA 证书
    ├── 颁发者: 根 CA
  根 CA 证书 (自签名)
```

**安全含义：**
- 证书的信任基于 CA 体系（假设 CA 是可信的）
- CA 被攻破 → 整个信任体系崩塌（如 DigiNotar 事件）
- 证书验证依赖于：
  1. 签名验证（使用 CA 的公钥）
  2. 有效期检查（notBefore/notAfter）
  3. 吊销状态检查（CRL/OCSP）
  4. 域名匹配（CN/SAN）
- **每个检查都是可绕过点**：自我签发的证书、跨期证书、OCSP 超时自动放行

#### ServerKeyExchange (仅 DHE/ECDHE)

```
服务器发送 DH 公钥 + 用证书私钥签名

结构:
  Curve Type:    named_curve (secp256r1)
  Public Key:    65 字节 (未压缩 ECC 点)
  Signature:     用证书私钥对以上参数的签名
```

**安全含义：**
- 这是"证书"和"密钥交换"的关键连接点
- 攻击者伪造 DH 参数 → 如果签名验证不通过 → 连接中断
- 但若客户端**跳过签名验证** → 中间人可以替换公钥（MITM）
- POODLE/BEAST 等攻击正是利用客户端跳过验证的路径

#### ClientKeyExchange

```
客户端发送自己的 DH 公钥

然后双方独立计算 premaster_secret:
  premaster_secret = DH(客户端私钥, 服务器公钥)
                   = DH(服务器私钥, 客户端公钥)
  
然后派生主密钥:
  master_secret = PRF(premaster_secret, "master secret",
                      ClientHello.random + ServerHello.random)
```

**安全含义：**
- premaster_secret 是双方安全交换的关键材料
- PFS (Perfect Forward Secrecy)：如果使用 DHE/ECDHE，即使证书私钥泄露，过去的通信也被保密，因为 premaster_secret 是**临时**的
- 相反，RSA 密钥交换中客户端用服务器公钥加密 premaster_secret 发送 → 服务器私钥泄露 → 所有历史流量可解密
- **TLS 1.3 移除了 RSA 密钥交换，强制 PFS**

#### 密文切换 (ChangeCipherSpec)

```
该消息表示：从此之后，所有内容将使用协商好的密钥加密。
```

**安全含义：**
- 这是"加密隧道"的起点
- 所有之前的握手消息（ClientHello、ServerHello）都是明文的
- 攻击者可以读取 SNI（域名）、证书等元数据 → **但无法修改**
- TLS 1.3 将所有握手消息加密 → 保护隐私

#### Finished

```
MAC( master_secret, "client finished" + 所有之前的握手消息哈希 )
```

**安全含义：**
- 这是"完整性验证" — 验证握手过程中**没有任何消息被篡改**
- 如果中间人修改了任何握手消息 → 哈希不匹配 → 连接中断
- 所以握手消息虽是明文，但被 Finished 签名，无法篡改
- **这是 TLS 的关键防御机制**：抵御主动中间人攻击

### 2.3 会话恢复 (Session Resumption)

```
优化方案1 - Session ID (服务端状态):
  客户端: 发送之前收到的 Session ID
  服务器: 查找缓存 → 复用之前的 master_secret
  (跳过证书交换和完整密钥协商)

优化方案2 - Session Ticket (客户端状态):
  服务器: 将会话状态加密为 ticket (发给客户端)
  客户端: 下次连接发送 ticket → 服务器解密后复用
```

**安全含义：**
- Session Ticket 是加密的状态（使用服务器持有 Key）
- 如果 Key 泄露 → 可以解密所有 session ticket → 解密的会话
- Session Ticket 的过期时间、轮换策略决定了泄露窗口
- 一些实现使用 AES-CBC + 固定 Key → 可被主动攻击

---

## 三、TLS 1.3 的变化（RFC 8446）

TLS 1.3 是一次**革命性重写**，而不是 TLS 1.2 的增量升级。

### 3.1 核心变化

| 特性 | TLS 1.2 | TLS 1.3 | 安全原因 |
|------|---------|---------|---------|
| 握手 RTT | 2 RTT | **1 RTT (0-RTT 模式)** | 性能 |
| 密钥交换 | RSA/DHE/ECDHE | **仅 ECDHE** | 强制 PFS |
| 密码套件 | 复杂组合（密钥交换+认证+加密+哈希） | **仅 5 个 AEAD 套件** | 简化 |
| 握手加密 | 明文 | **全加密** | 隐私 |
| 静态 RSA | 支持 | **删除** | 无 PFS |
| CBC 模式 | 支持 | **删除** | 易受攻击 |
| RC4/DES/3DES | 支持 | **删除** | 弱密码 |
| 压缩 | 支持 (CRIME/BREACH) | **删除** | 泄露明文信息 |
| 重协商 | 支持 | **删除** | 复杂且易错 |
| ChangeCipherSpec | 独立消息 | **兼容性替身** | 简化 |

### 3.2 TLS 1.3 握手 (1-RTT)

```
Client                                           Server
   │──── ClientHello ──────────────────────────────►│
   │   (key_share: 客户端 ECDHE 公钥)                │
   │   (supported_versions: 0x0304)                 │
   │   (psk_key_exchange_modes)                     │
   │                                                │
   │◄──── ServerHello ──────────────────────────────│
   │   (key_share: 服务器 ECDHE 公钥)                │
   │◄──── EncryptedExtensions ─────────────────────│
   │◄──── Certificate (已加密) ─────────────────────│
   │◄──── CertificateVerify (已加密) ───────────────│
   │◄──── Finished (已加密) ────────────────────────│
   │                                                │
   │──── Finished (已加密) ────────────────────────►│
   │════════════ Application Data ══════════════════│
```

**关键改变：**
1. **1-RTT 完成握手** — 客户端在 ClientHello 中直接发送 ECDHE 公钥（key_share）
2. **握手立即加密** — 服务器在 ServerHello 之后的所有消息都是加密的
3. **0-RTT (Early Data)** — 客户端可在第一个消息就发送应用数据（基于 PSK）
4. **密码套件简化** — 只协商 AEAD 加密+哈希，不再包含密钥交换和签名

### 3.3 0-RTT 的安全风险

**0-RTT 数据存在重放攻击风险**：
- 客户端发送的数据在收到服务器 Finished 之前就到达了
- 攻击者可以截获并重放 0-RTT 数据
- 服务器需要实现**重放检测**（基于时间窗口或一次性 ticket）
- **非幂等的请求不应使用 0-RTT**（如支付、转账）

---

## 四、TLS 记录层 (Record Layer)

TLS 数据最终以"记录"的形式传输。记录层是 TLS 的最小传输单元。

### 4.1 记录格式

```
Record Header (5 字节):
  Content Type:    1 字节 (20=CCS, 21=Alert, 22=Handshake, 23=AppData)
  Protocol Version: 2 字节 (0x0301-0x0304)
  Length:          2 字节 (payload 长度)
  ───────────
  Payload:         (加密/未加密)
```

**安全含义：**
- Content Type 字段是明文的 — 攻击者可区分握手和应用程序数据
- TLS 1.3 对加密的应用数据用最后 1 字节指示真实类型（规避中间盒过滤）
- 记录长度最大 2^14 = 16384 字节

### 4.2 加密方式 (AEAD)

TLS 1.3 唯一支持的加密模式是 AEAD (Authenticated Encryption with Associated Data)：

```
AEAD 加密 = 加密 + 认证 一次完成

输入:
  Key:        对称密钥
  Nonce:      序列号 + IV (保证一次一密)
  Plaintext:  明文数据
  AAD:        关联数据 (记录头)

输出:
  Ciphertext: 密文
  Tag:        认证标签 (验证完整性)
```

**安全含义：**
- AEAD 解决了"先加密再 MAC"的顺序依赖问题
- TLS 1.2 的 CBC + HMAC 模式存在 Vaudenay padding oracle 攻击等漏洞
- 序列号防重放 — 每个连接有独立的写入/读取序列号计数器
- 密钥被用完一定量数据后必须重新生成（`KeyUpdate`）

### 4.3 记录层安全机制

#### 序列号
```
每个连接方向有独立的 64 位序列号
初始为 0，每条记录 +1
AEAD nonce = IV XOR (序列号)
```

- 序列号不能重置（除非重新握手）
- 一旦序列号回绕 → 会话必须终止
- 这防止了重放攻击（相同的明文加密后每次的 ciphertext 不同）

#### KeyUpdate
```
TLS 1.3 允许在连接期间更新密钥：
  KeyUpdate(update_requested)
  ↓
  双方同时更新发送密钥
  (新的密钥 = HKDF-Expand(旧密钥, ...))
```

- 限制单个密钥加密的数据量
- 防止流量分析（关键点切换后难以关联前后流量）

---

## 五、证书链验证（信任的核心）

证书系统是 TLS 信任的基础。理解证书验证 = 理解 TLS 信任模型的全部假设。

### 5.1 X.509 证书结构

```
Certificate:
  版本号 (V3)
  序列号
  签名算法 (SHA256-RSA)
  颁发者 (Issuer)
  有效期 (notBefore ~ notAfter)
  主体 (Subject)
  公钥信息 (算法 + 公钥值)
  ─────────── 扩展 (V3) ───────────
  主体备用名称 (SAN)       ← 域名绑定
  密钥用途 (Key Usage)     ← 限制密钥用途
  扩展密钥用途 (EKU)      ← 限制证书用途
  基本约束 (CA: True/False) ← 是否是 CA
  CRL 分发点              ← 吊销列表
  OCSP 响应者             ← 在线吊销状态
  ─────────── 签名 ───────────
  由颁发者的私钥签名
```

### 5.2 验证路径

```
[根 CA 证书] ← 自签名，存在浏览器/OS 信任存储
     │ 颁发
[中间 CA 证书] ← 可有多级
     │ 颁发
[服务器证书] ← 叶子证书，绑定到具体域名
```

**验证步骤：**
1. **签名验证**：用父证书的公钥验证子证书的签名
2. **有效期检查**：当前时间在 notBefore ~ notAfter 之间
3. **用途检查**：CA 标志、EKU、Key Usage 正确
4. **域名匹配**：SAN/CN 匹配请求的域名
5. **吊销检查**（可选）：CRL/OCSP

### 5.3 每个检查的绕过方式

| 检查项 | 绕过方式 | 真实案例 |
|--------|---------|---------|
| 签名验证 | 自签名证书（浏览器警告但用户点继续） | 内部网络攻击 |
| 有效期 | 跨期证书（时间同步问题） | MD5 碰撞绕过 |
| 域名匹配 | SAN 通配符 `*.example.com`→`example.com` 可能失败 | cert 解析 bug |
| 吊销检查 | OCSP 超时 → 浏览器"软失败"自动放行 | 2013 Chrome 策略 |
| CA 信任 | 加入恶意 CA 到信任存储 | Superfish 事件 |
| CA 被攻破 | 签发假证 | DigiNotar 2011 |

**关键洞察：** 吊销检查的"软失败"设计是一个安全假设：假设 OCSP 不可用是因为网络问题而不是攻击。但实际上，攻击者可以**阻断 OCSP 请求**，让浏览器认为 CA 不可用 → 自动放行 → MITM 成功。

### 5.4 CA 信任体系的问题

```
信任的基础假设:
  1. 所有 CA 都是负责任、安全的
  2. CA 会正确验证域名所有权
  3. CA 会及时吊销泄露的证书
  4. CRL/OCSP 始终可用

现实:
  1. DigiNotar 被伊朗黑客攻破 → 签发 *.google.com 被用于监视
  2. Comodo/GlobalSign 也曾被攻破
  3. WoSign/CNNIC 被发现存在不当签发行为
  4. 浏览器/OS 移除这些 CA 要数月或更久
```

**所以有了证书透明度 (Certificate Transparency)：**
- 所有 SSL 证书必须提交到公开日志
- 浏览器检查证书是否在日志中出现过
- 如果 CA 在不知会的情况下签发证书 → 可被检测
- 这是对"CA 是可信的"这一假设的修正

---

## 六、TLS 攻击面详解

### 6.1 降级攻击 (Downgrade Attack)

#### SSL Stripping（协议降级）
```
用户请求 https://example.com
    │
攻击者劫持:
  ├── 到用户的连接: http (明文)
  └── 到服务器的连接: https (安全)
      
用户: http://example.com (不自知)
攻击者: 可以看到所有用户数据
服务器: 认为 HTTPS 连接正常
```

**原理：** 用户不会手动输入 `https://`，而是输入 `example.com`。浏览器默认使用 HTTP。如果服务器没有 HSTS，攻击者可以维持 HTTP 连接。

**防御：** HSTS (HTTP Strict Transport Security)
```
服务器响应头:
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

含义:
  - 浏览器记住：该域名只能用 HTTPS 访问 (max-age 秒)
  - includeSubDomains: 子域名也强制
  - preload: 浏览器硬编码该域名（不可撤销）
```

**绕过 HSTS：**
- 第一次访问（preload 列表之外） → 仍可能被降级
- 子域名未覆盖（未设 includeSubDomains）
- 用户手动忽略浏览器警告 → 点"继续"的瞬间已经泄密
- HSTS 超时后（max-age 过了） → 降级窗口再次出现

#### TLS 版本降级

```
攻击者修改 ClientHello:
  ClientHello.version = 0x0301 (TLS 1.0)  ← 原本是 0x0303 (TLS 1.2)
  
服务器: 认为客户端只支持 TLS 1.0 → 降级
```

**TLS 1.3 的防御（downgrade sentinel）：**
```
服务器在 ServerHello.random 末尾写入特殊字节:
  如果协商 TLS 1.0 → 0x0301 重复写入 random
  如果协商 TLS 1.1 → 0x0302 重复写入 random
  
客户端检查: 如果 random 末尾有这些标记
  → 意味着服务器收到了低版本但客户端实际上支持更高版本
  → 中间人攻击！连接立即中断
```

#### POODLE (Padding Oracle On Downgraded Legacy Encryption)

```
目标: SSL 3.0 的 CBC 模式
条件: 攻击者可以控制部分明文（如 JavaScript 注入）
方法:
  1. 强制降级到 SSL 3.0
  2. 利用 CBC padding 的弱点逐字节推断加密内容
  3. 对 Cookie 等秘密内容进行侧信道恢复
  
影响: 可解密加密 Cookie → 会话劫持
```

#### BEAST (Browser Exploit Against SSL/TLS)

```
目标: TLS 1.0 的 CBC 模式
条件: 攻击者能执行 JavaScript（同源或 XSS）
方法:
  1. 利用 TLS 1.0 CBC 的 IV 预测问题
  2. 逐字节猜测加密内容（Cookie）
  3. 利用 HTTPS 请求的已知模式
  
影响: 解密 HTTPS Cookie
```

#### FREAK (Factoring RSA Export Keys)

```
目标: 出口密码限制
条件: 服务器支持 export-grade RSA (512 位)
方法:
  1. 客户端发送正常密码套件列表
  2. 中间人修改为「仅支持 export RSA」
  3. 服务器使用弱 RSA (512 位)
  4. 中间人因式分解 512 位 RSA
  5. MITM
```

### 6.2 证书相关攻击

#### MITM 代理攻击

```
攻击者设备上:
  1. 生成自签名根证书
  2. 将该证书加入设备的信任存储
  3. 对目标域签发即时证书
  4. 拦截所有 HTTPS 流量
  
常见场景: 企业防火墙、恶意软件、蓝队加密检测
```

#### 通配符证书泄露

```
*.example.com 可以保护所有 *.example.com
如果一个子域名被攻破 → 证书无效（因为通配符只匹配一层）
但如果被盗 → 可保护任意子域名
```

#### OCSP Stapling

```
问题: 浏览器直接请求 OCSP 响应者
  - 增加延迟
  - 泄露用户访问的域名给 OCSP 响应者
  - OCSP 响应者可追踪用户

解决 (OCSP Stapling):
  服务器: 提前获取 OCSP 响应 + 缓存
  服务器: 在 TLS 握手中「附上」OCSP 响应
  浏览器: 验证 OCSP 响应 → 无需额外请求
```

#### 证书透明度绕过

```
虽然 CT 要求证书公开
但恶意 CA 可先签发 → 提交日志 → 在日志检查完成前使用
大多数浏览器在收到 Signed Certificate Timestamp (SCT) 后即信任
如果 SCT 后续无效... 但连接已经建立
```

### 6.3 密码学攻击

#### ROBOT (Return Of Bleichenbacher Oracle)

```
目标: RSA 密钥交换（TLS 1.2 之前）
原理:
  1. Bleichenbacher 1998 年发现的 PKCS#1 v1.5 padding oracle
  2. 服务器对不同格式的预主密钥返回不同错误
  3. 这些差异→信息泄漏→逐步恢复预主密钥
  
影响: 恢复 TLS 会话的预主密钥 → 解密通信
  
防护: 禁用 RSA 密钥交换（使用 ECDHE），TLS 1.3 已删除 RSA 交换
```

#### DROWN (Decrypting RSA with Obsolete and Weakened eNcryption)

```
目标: 服务器同时支持 SSLv2 + TLS
原理:
  1. 攻击者连接到服务器的 SSLv2（故意开放或同一公钥的另一个服务）
  2. SSLv2 存在协议漏洞（明文传输 premaster_secret 请求）
  3. 利用 SSLv2 的弱点解密 TLS 连接的加密内容

影响: 即使 TLS 配置正确，只要同一密钥支持 SSLv2 就受影响
影响范围: 约 33% 的 HTTPS 服务器
修复: 完全禁用 SSLv2
```

#### Logjam

```
目标: DHE 密钥交换（TLS 1.2）
原理:
  1. 政府/攻击者可以预先计算 DH 群的离散对数（针对 1024 位）
  2. 中间人修改 ClientHello → 仅允许 export-grade DH（512 位）
  3. 实时破解 512 位 DH → 获取密钥
  
影响: 解密 1024 位 DHE 的 TLS 连接
条件: 服务器支持 DHE_EXPORT
修复: 禁用 export 密码套件，使用 2048+ 位 DH
```

### 6.4 实现层面的漏洞

| 漏洞 | 实现 | 原因 | 影响 |
|------|------|------|------|
| Heartbleed | OpenSSL | 心跳扩展缓冲区未检查 | 读取服务器内存（私钥可泄露） |
| CCS Injection | OpenSSL | ChangeCipherSpec 未验证状态 | 窃听 |
| Triple Handshake | 多实现 | 重协商 + Session ID 冲突 | MITM |
| ALPACA | 多实现 | 跨协议攻击（FTP/HTTP 共用到 TLS） | Cookie 窃取 |
| Raccoon | 多实现 | DH 共享秘密的 TLS 1.2 漏洞 | 密钥恢复 |

#### Heartbleed (CVE-2014-0160)

```
原理:
  心跳请求: "请回复 'ABC' 这个字符串"
  正常响应: "ABC"
  
  恶意请求: "请回复 'ABC' [长度=65535]"
  响应: "ABC" + [后面 65532 字节内存中的随机内容]
  
  因为 OpenSSL 没有验证用户声称的长度是否匹配实际数据
```

**影响：** 可以读取服务器内存中的：
- 私钥
- 其他用户的会话密钥
- 用户密码 / Credit Card / 其他敏感数据

**根本原因：** 一个**边界检查缺失** — 没有验证 `请求长度 == 实际数据长度`

---

## 七、从原理推导攻击面

> 结合我们已有的知识体系（TCP 协议、HTTP 协议），看看 TLS 的哪些"假设"可以被攻击。

### 攻击面 1：降级的代价不对称

```
攻击者成本: 修改 ClientHello 中的版本字段 → 极低
服务器代价: 接受低版本 → 暴露整个加密通道

关键假设:
  「服务器接受低版本是为了兼容性」
  但这假设了「降级是安全的」
```

**可推导的攻击：** 任何接受比最高版本更低的协议版本都是攻击面。防御是**服务器应拒绝所有不安全的旧版本**。

### 攻击面 2：补救失败的吊销检查

```
假设: 「OCSP 响应者不可用时，浏览器应接受证书，而不是完全拒绝」
  这假设了「OCSP 不可用 = 网络问题而非攻击」
  
  但攻击者可以阻断 OCSP 请求:
    - DNS 劫持 OCSP 响应者域名
    - 防火墙阻止到 CRL/OCSP 的请求
    - ARP/DHCP 伪造 OCSP 响应者 IP
```

**可推导的攻击：** 如果目标使用 HTTPS，阻断它的 OCSP 请求，然后使用已经被吊销但仍在有效期的旧证书。

### 攻击面 3：证书链的任意链接

```
假设: 「CA 是可信的，所有它签发的证书都代表合法的身份」
  这假设了「CA 会验证所有签发请求」

  但存在:
    - CA 被攻破 → 签发任意域名的有效证书
    - CA 被政府控制 → 签发监控证书
    - CA 配置错误 → 向未验证所有权的申请人签发证书
```

**可推导的攻击：** 如果目标是 HTTPS 服务，攻击目标环境的信任存储（添加恶意 CA 证书），或者利用 CA 的弱点。

### 攻击面 4：不安全的会话恢复

```
假设: 「Session Ticket 是安全的，因为它是加密的」
  但:
    - 如果加密密钥是固定的 → 可以暴力破解
    - 如果使用弱加密（AES-CBC）→ padding oracle
    - Ticket 可以重放（如果未绑定到特定连接）
```

**可推导的攻击：** 截获 Session Ticket → 重放到另一个连接 → 可能恢复会话（取决于服务器实现）。

### 攻击面 5：密文的元数据分析

```
假设: 「TLS 加密了通信内容 = 通信是安全的」
  但:
    - 流量长度泄漏（分片大小）
    - 流量时序泄漏（按键时间）
    - 记录数量泄漏（请求页面的资源数量）
```

**可推导的攻击：** 即使无法解密，通过分析加密流量的模式（长度、时序、流量方向）可以推断访问的网站（VFy - Standardized Website Fingerprinting）。

### 攻击面 6：证书透明性的延迟

```
假设: 「CT 日志包含了所有签发的证书」
  但:
    - CA 可以签发证书 → 立即使用 → 然后提交日志
    - 日志提交到浏览器更新黑名单可能有数天延迟
    - 攻击者在这段时间内是安全的
```

**可推导的攻击：** 利用 CT 日志和浏览器更新之间的时间差。在受控环境中（如内网目标），CT 日志可能根本不被检查。

### 攻击面 7：「信任我」模式的用户

```
假设: 「用户会注意到浏览器警告」
  事实: 几乎没有人注意
    - 2015 年 Google 研究：30% 的 HTTPS 警告被忽略
    - 内网用户更容易点「继续」
    - 攻击者可以使用自签名证书
```

**可推导的攻击：** 任何在浏览器中弹出证书警告的场景都是攻击面。自签名证书 + 用户点继续 = TLS 保护完全失效。

---

## 八、与知识体系中的其他内容关联

### 与 TCP 的关系

```
TLS 记录在 TCP 分段之上传输
  → TLS 记录边界 ≠ TCP 分段边界
  → TCP 重组后 TLS 才能解密
  → TCP 序列号攻击影响的不只是 TCP，还有 TLS

攻击者不能篡改 TLS 内容（AEAD 保护）
但攻击者可以:
  - 延迟 TLS 记录（影响实时应用）
  - 丢弃 TLS 记录（导致连接中断）
  - 重放 TLS 记录（在相同会话窗口中）
```

### 与 HTTP 的关系

```
HTTPS = HTTP 运行在 TLS 之上

但是:
  1. 浏览器先请求 HTTP (80) → 收到 301 重定向到 HTTPS (443)
     → 第一次请求是明文 → SSL Stripping 攻击窗口
  
  2. HSTS 列表 (preload) 在最开始就强制 HTTPS
     → 消除第一次明文请求窗口
     → 但 HSTS 列表需要浏览器厂商同意 → 不是所有网站都能加入

  3. Cookie 的 Secure 属性: 要求只在 HTTPS 连接中发送
     → 如果没标记 → 攻击者降级到 HTTP → Cookie 明文泄露
```

### 与 DNS 的关系

```
TLS 依赖 DNS 解析目标 IP
  → DNS 劫持/中毒 → 连接被重定向到攻击者服务器
  → 攻击者服务器 + 自签名证书 → 用户看到警告（但可能点继续）
  → 即使不点继续，DNS 已经被污染

DOH (DNS over HTTPS) 用 TLS 保护 DNS 查询
  → 阻止了 DNS 层面的劫持
  → 但 DOH 服务器本身也有 TLS 问题 ...
  → 这是一个递归的安全依赖
```

---

## 九、渗透测试中的 TLS 检查清单

检查 TLS 的「假设」是否成立：

### 1. 版本降级测试
```
# 只支持 TLS 1.2+？
openssl s_client -connect target:443 -tls1_3
openssl s_client -connect target:443 -tls1_2
openssl s_client -connect target:443 -tls1_1   # 应该失败
openssl s_client -connect target:443 -tls1     # 应该失败
openssl s_client -connect target:443 -ssl3     # 应该失败
```

### 2. 弱密码套件
```
# 是否支持 export 套件？
nmap --script ssl-enum-ciphers -p 443 target
sslyze --tls13 target:443
```

### 3. 证书检查
```
# 证书链是否完整？有效期？SAN 匹配？
openssl s_client -connect target:443 -showcerts
# 输出: 证书链、CN、SAN、有效期、CA 的 OCSP/CRL

# 私钥安全？
# 如果多处共享同一证书 → 私钥泄露面更广
```

### 4. 证书透明度
```
# 证书是否在 CT 日志中？
# 浏览器访问 → 地址栏检查 CT 标志（绿色锁）
```

### 5. HSTS
```
# 是否启用 HSTS？
curl -I https://target.com
# 检查: Strict-Transport-Security 响应头
# 如果缺失 → SSL Stripping 风险
```

### 6. Session Ticket
```
# 使用 ticket 的生存期？
# 服务器密钥的轮换策略？
# ticket 是否可以重放？（两次相同 ticket 连接）
```

### 7. 共享密钥
```
# 不同的服务使用相同的 TLS 证书/私钥？
# → 一个泄密全完蛋
```

---

## 总结

TLS 是一个设计精良的协议，但它建立在多个假设之上：

1. **CA 是可信的** — 证书链验证依赖这个假设
2. **用户会注意警告** — 但实际上不会
3. **OCSP 服务器始终可用** — 但实际上可能被阻断
4. **降级只发生在客户端请求时** — 但中间人可以篡改请求
5. **证书不会被提前签发** — 但 CT 日志有延迟窗口

**渗透测试者要做的是：检查这些假设在目标环境中是否成立。** 如果任何一个假设被打破，TLS 提供的「安全」就不是真正的安全。


---

## 【LLM 推理段 — TLS/SSL 证书与配置检查】

### 触发条件
- 目标开放 443/8443 等 HTTPS 端口
- 任何使用 TLS 的服务（SMTPS、LDAPS、IMAPS）

### 检测信号
| 信号 | 说明 | 置信度 | 检测方法 |
|------|------|--------|---------|
| 证书过期 | 浏览器提示证书过期 | 高 | openssl s_client 查看 |
| 自签名证书 | 不是受信任 CA 签发 | 高 | 检查证书签发者 |
| 弱加密套件 | 支持 RC4/3DES/EXPORT | 高 | nmap --script ssl-enum-ciphers |
| 弱协议 | 支持 SSLv2/SSLv3/TLSv1.0 | 高 | nmap --script ssl-enum-ciphers |
| 证书 CN 与域名不匹配 | 证书为其他域名签发 | 中 | 检查 subject CN |
| HSTS 缺失 | 无 Strict-Transport-Security 头 | 低 | curl -I 检查响应头 |

### 验证步骤
1. 证书有效性: `openssl s_client -connect target:443 -servername target 2>&1`
2. 协议支持: `nmap --script ssl-enum-ciphers -p 443 target`
3. 证书链: `openssl s_client -showcerts -connect target:443`
4. 确认标准: 证书过期/自签名/弱加密套件/弱协议支持

### 利用链扩展
| 问题 | 风险 | 后续攻击面 |
|------|------|-----------|
| 自签名证书 | 中间人攻击 | 证书固定可绕过 |
| 弱加密套件 | 解密流量 | 密码分析攻击 |
| SSLv3 支持 | POODLE 攻击 | 明文泄露 |
| TLSv1.0 支持 | BEAST/Lucky13 | 会话劫持 |
| 证书过期 | 服务可能不再维护 | 其他漏洞风险更高 |

---

## 【LLM 推理段 — TLS 中间人攻击场景】

### 触发条件
- 攻击者在目标网络路径上（同局域网/WiFi）
- 目标未使用 HSTS 或首次访问

### 检测信号
- 无 HSTS 头的 HTTPS 站点
- 支持降级到 HTTP（HTTP 重定向到 HTTPS 时可拦截）

### 验证步骤
1. ARP 欺骗 / 伪造网关
2. SSL Strip: 将 HTTPS 链接替换为 HTTP
3. 确认标准: 成功截获明文流量

### 利用链扩展
- SSL Strip -> 凭证窃取 -> 账号接管
