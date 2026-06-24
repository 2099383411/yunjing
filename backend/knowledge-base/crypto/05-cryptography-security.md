# 05. 密码学基础与安全陷阱

> 领域：密码学
> 关联：protocols/03-tls-protocol-security.md（TLS 是密码学的集大成者）
> 学习路线：对称 → 非对称 → 哈希 → 签名 → 证书 → 攻击 → 现代协议

---

## 一、密码学的核心角色

密码学不是用来"藏消息"的——它解决四个问题：

```
机密性 (Confidentiality)    → 别人看不懂
完整性 (Integrity)         → 别人改不了
认证 (Authentication)     → 别人冒充不了
不可否认性 (Non-repudiation) → 抵赖不了

现实生活中这四样东西缺哪个都活不了
网络安全也是一样
```

**重要认知：** 密码学是工具，不是银弹。用错密码学比没用更危险。

---

## 二、对称加密 (Symmetric Cryptography)

### 2.1 基本原理

```
  密钥:       K (比如: 0xAB... 16字节)
  明文:       "Hello World"
  加密:       C = Enc(K, "Hello World")
  密文:       C (看起来像随机数据)
  解密:       Dec(K, C) = "Hello World"

  加密和解密用同一个密钥。
  好处: 超快（硬件加速）
  坏处: 密钥怎么安全地交给对方？
```

### 2.2 分组密码 (Block Cipher)

```
AES (Advanced Encryption Standard):
  - NIST 标准（2001年至今）
  - 分组大小: 128 bits (16 字节)
  - 密钥长度: 128/192/256 bits
  - 内部结构: 替代-置换网络 (Substitution-Permutation Network)
  - 硬件支持: AES-NI 指令集（现代 CPU 内置）

工作原理（简化）:
  明文 128-bit 分成 4×4 矩阵 → 经过多轮操作:
    1. SubBytes:   每个字节按 S-box 替换
    2. ShiftRows:  行移位
    3. MixColumns: 列混合
    4. AddRoundKey: 加轮密钥

  AES-128 = 10 轮
  AES-192 = 12 轮
  AES-256 = 14 轮
```

### 2.3 分组密码的工作模式 (Modes of Operation)

**为什么需要工作模式？**

AES 只能加密 16 字节块。你的消息通常是 1000 字节。工作模式告诉你怎么把块拼起来加密长消息。

**ECB 模式（别用）：**
```
  明文:    [块1] [块2] [块3]
           ↓      ↓      ↓
  加密:   E(K,块1) E(K,块2) E(K,块3)
           ↓      ↓      ↓
  密文:   [C1]   [C2]   [C3]

  问题: 相同的明文块 → 相同的密文块！
  后果: 你可以在密文中看出模式
        经典的"企鹅图片"问题——加密后还能看到企鹅的轮廓
```

**CBC 模式（历史原因仍在使用）：**
```
  加密:
    C0 = IV
    C1 = E(K, P1 ⊕ C0)
    C2 = E(K, P2 ⊕ C1)
    C3 = E(K, P3 ⊕ C2)

  解密:
    P1 = D(K, C1) ⊕ C0
    P2 = D(K, C2) ⊕ C1

  好处: 相同的明文产生不同的密文
  坏处:
    - 不能并行加密（依赖前一个块）
    - 无法抵抗填充预言攻击（Padding Oracle Attack）
    - 需要额外的 MAC 来保证完整性
```

**CTR 模式（计数器模式）：**
```
  加密:
    C1 = P1 ⊕ E(K, Counter1)
    C2 = P2 ⊕ E(K, Counter2)
    C3 = P3 ⊕ E(K, Counter3)

  好处:
    - 可并行
    - 不需要填充（因为 XOR 操作)
    - 随机构建，任意位置解密

  坏处:
    - 从不重复使用 counter 值！（否则完全暴露）
    - 完整性仍需要额外保护
```

**GCM 模式（现在最流行的模式）：**
```
  GCM = CTR 模式 + GHASH 认证

  加密: CTR 模式加密（快、并行）
  认证: GHASH 和最后的 GCTR（提供完整性）

  好处（一站式）:
    - 加密 + 完整性 = 认证加密 (AEAD)
    - 并行
    - 不需要填充
    - TLS 1.2/1.3 默认使用

  安全要点:
    - 从不重用 nonce (IV)！GCM 的 nonce 重用是灾难性的
    - 只用一次的 nonce 被重用 → 密钥 Ke 被推导
    - 如果 GCM nonce 重用，GHASH 认证密钥也被推导
    - 那么攻击者可以解密任意密文并伪造任意消息
    - AES-GCM nonce 长度 12 字节（96 bits）最佳
    - 更长的 nonce 经过 GHASH 转换，可能碰撞
```

### 2.4 流密码 (Stream Cipher)

```
原理: 密钥流生成器 → 产生伪随机字节流
      密钥流 ⊕ 明文 = 密文

实际: ChaCha20（替换 RC4 的现代流密码）
  - 在 TLS 1.3 中是标准备选
  - 比 AES-GCM 在某些平台上更快（移动设备）
  - 抗时间攻击

关键规则: 密钥流永不重复使用
  - 一个 key 只能加密一个消息（除非有随机 nonce）
  - ChaCha20 + Poly1305 = 认证加密
```

---

## 三、非对称加密 (Asymmetric / Public-Key Cryptography)

### 3.1 基本原理

```
  密钥对: 公钥 PK (公开) + 私钥 SK (秘密)

  加密:
    发送者用 PK 加密 → 只有 SK 持有者能解密
    示例: 任何人可以给你发加密消息

  签名:
    签名者用 SK 签名 → 任何人可用 PK 验证
    示例: 软件发布者签名

  好处: 不需要预先共享密钥
  坏处: 慢（比对称加密慢 100-1000 倍）

所以现实世界用"混合加密"：
  非对称 → 交换对称密钥
  对称 → 加密大量数据
```

### 3.2 RSA

```
RSA 是第一个实用的公钥密码系统（1977）。

数学基础: 大整数分解的困难性

  过程:
    1. 随机选择两个大素数 p, q
    2. n = p × q
    3. 计算 φ(n) = (p-1)(q-1)
    4. 选择 e (通常 65537) 满足 gcd(e, φ(n)) = 1
    5. d = e^(-1) mod φ(n)
    
    公钥: (n, e)
    私钥: (n, d)

  加密: c = m^e mod n
  解密: m = c^d mod n

密钥大小:
  2048-bit RSA = 安全（预计到 2030年）
  4096-bit RSA = 更安全（慢很多）
  1024-bit RSA = 不安全（已被分解）

安全性问题:
  - RSA 密钥生成需要好的随机数
  - 没有好的填充方案 → 选择明文攻击
  - PKCS#1 v1.5 填充 → Bleichenbacher 攻击（填充预言）
  - OAEP 填充 → 现代 RSA 加密的标准
```

**Bleichenbacher 攻击（1998年）**：
```
  场景: SSL 3.0 / TLS 1.0 使用 RSA 密钥交换

  服务器收到加密的 pre-master secret：
    1. 解密 → 检查格式（PKCS#1 v1.5 填充）
    2. 如果填充格式正确 → 继续握手
    3. 如果填充格式错误 → 返回错误

  攻击者可以：
    1. 截获加密的 pre-master secret C
    2. 选择 s, 计算 C' = C × s^e mod n
    3. 发送 C' 给服务器
    4. 服务器返回：格式正确 / 格式错误
    5. 这"1 bit"信息让攻击者逐步恢复明文
    
  共需要约 2^20 次查询 → 恢复完整的 pre-master secret
  后果: 攻击者可以解密整个 TLS 会话

  修复: TLS 1.3 完全移除了 RSA 密钥交换
```

### 3.3 ECC (Elliptic Curve Cryptography)

```
ECC 用更小的密钥提供同等级的安全:

  RSA 2048-bit ≈ ECC 224-bit
  RSA 3072-bit ≈ ECC 256-bit
  RSA 7680-bit ≈ ECC 384-bit

数学基础: 椭圆曲线上的离散对数问题

  ECC 优势:
    - 密钥更小
    - 计算更快
    - 节省带宽

  常用曲线:
    - P-256 (secp256r1) — NIST 标准
    - P-384 (secp384r1) — NIST 标准
    - X25519 (Curve25519) — Daniel Bernstein 设计
    - Ed25519 — Edwards 曲线（用于签名）

  安全问题（某些曲线）:
    - P-256 的生成过程不透明（NIST 曲线）
    - 有些人不信任 NIST 曲线
    - Ed25519/X25519 完全透明 → 社区更偏好
```

### 3.4 Diffie-Hellman 密钥交换

```
DH 不是加密，也不是签名。
它让双方在不安全的通道上建立共享密钥。

原理:
  Alice: 选择 a (私密) → 计算 A = g^a mod p (发送)
  Bob:   选择 b (私密) → 计算 B = g^b mod p (发送)

  共享密钥: K = B^a mod p = A^b mod p = g^(ab) mod p

安全性: 攻击者知道 g, p, A, B，但无法计算 g^(ab) mod p
        (离散对数问题)

DH vs RSA 密钥交换:
  RSA 密钥交换:
    - 客户端选择 pre-master secret → 用服务器公钥加密
    - 如果服务器私钥泄露 → 所有历史会话可解密
    - 没有前向保密 (Perfect Forward Secrecy)
  
  (EC)DHE 密钥交换:
    - 双方各自生成临时密钥对
    - 交换完成后销毁临时私钥
    - 即使服务器长期密钥泄露 → 历史会话仍安全
    - 前向保密 ✓

这就是 TLS 1.3 强制要求 (EC)DHE 的原因。
```

---

## 四、哈希函数 (Hash Functions)

### 4.1 基本性质

```
哈希函数 H: 任意长度输入 → 固定长度输出

  性质 1: 确定性 —— 相同的输入总是相同的输出
  性质 2: 快速 —— 计算快
  性质 3: 抗原像 —— 给定 H(m), 无法计算 m
  性质 4: 抗第二原像 —— 给定 m1, 找不到 m2 ≠ m1 使 H(m1) = H(m2)
  性质 5: 抗碰撞 —— 找不到任意 m1 ≠ m2 使 H(m1) = H(m2)
```

### 4.2 常见的哈希函数

```
SHA-1:
  - 输出: 160-bit (20 bytes)
  - 状态: 已被淘汰
  - 2017年 Google 展示了 SHAttered（第一个公开的碰撞）
  - 仍被用于 legacy 系统（很大安全风险）

SHA-256 (SHA-2 家族):
  - 输出: 256-bit (32 bytes)
  - 状态: 目前安全
  - Merkle-Damgård 结构
  - 问题: 容易受长度扩展攻击（见下文）

SHA-3:
  - 输出: 可配置 (224/256/384/512)
  - 状态: 安全
  - 结构: Keccak (海绵结构)
  - 不受长度扩展攻击影响

BLAKE2/BLAKE3:
  - 输出: 可变
  - 状态: 安全（比 SHA-2/3 快很多）
  - 在密码学社区广泛使用
```

### 4.3 Merkle-Damgård 结构与长度扩展攻击

**Merkle-Damgård 结构（MD5、SHA-1、SHA-2 使用）：**

```
  输入消息: M = M1 || M2 || M3

  处理过程:
    IV_0          (固定的初始向量)
     ↓
    M1 → 压缩函数 → IV_1
     ↓
    M2 → 压缩函数 → IV_2
     ↓
    M3 + 填充 → 压缩函数 → IV_3 = 哈希输出

  关键: 哈希输出就是最后一个压缩函数的内部状态
        这个状态可以被"提取并继续"
```

**长度扩展攻击的原理：**

```
  服务器计算 H(secret || message) 作为 MAC

  假设:
    secret = "key" (3字节)
    message = "admin=False"
    MAC = SHA256("keyadmin=False") = 0xabc123...

  攻击者知道:
    - message = "admin=False"
    - MAC = 0xabc123... (上面计算的)
    - secret 的长度（猜测或已知）

  攻击者可以:
    1. 从已知 MAC = 0xabc123... 恢复 SHA256 内部状态
    2. 构造额外数据: "admin=True"（攻击者控制的附加数据）
    3. 计算新哈希: 
       H(secret || "admin=False" || padding || "admin=True")
    4. 这个新哈希是有效的！
    
  原因: 哈希函数不知道"padding"和"真实数据"的区别
        padding 只是规范的一部分
        服务器看到相同结构 → 视为合法

  防御: 使用 HMAC 结构
    HMAC(K, M) = H(K ⊕ opad || H(K ⊕ ipad || M))
    不暴露 H的 内部状态给攻击者

  或者使用 SHA-3 (海绵结构，不受长度扩展影响)
```

### 4.4 哈希的实际应用

```
1. 密码存储（本应使用，但很多系统搞错了）:
   错: MD5(password)          ← 彩虹表可逆
   错: SHA256(password)       ← 查表逆转
   好: bcrypt(password, salt)  ← 慢、加盐
   好: argon2(password, salt)  ← 慢、加盐、抗GPU

2. 消息完整性:
   发送: (message, H(message))
   接收: 重算 H(message) → 对比

3. 文件校验:
   发布: (file.exe, SHA256(file.exe))
   验证: 下载 → 计算 SHA256 → 对比
```

---

## 五、消息认证码 (MAC) 与数字签名

### 5.1 MAC (对称密钥)

```
MAC = 使用共享密钥生成消息的"标签"
  发送者: MAC = f(K, message)
  接收者: 重算 MAC → 验证

用于:
  - 消息完整性（没有被篡改）
  - 消息认证（确实是拥有 K 的人发的）

常见 MAC 算法:
  HMAC-SHA256
  AES-CMAC
  GMAC (AES-GCM 使用的认证部分)
```

### 5.2 数字签名 (非对称密钥)

```
签名 = 私钥签名 + 公钥验证

  签名者 A:
    1. 计算 H(message)
    2. 用 SK_A 加密哈希 = 签名
    3. 发送 (message, 签名)

  验证者:
    1. 用 PK_A 解密签名 → 得到哈希
    2. 自己计算 H(message)
    3. 对比 → 如果相同，是 A 签的

签名不是加密！
  加密: 只有接收者能解密
  签名: 任何人都能用公钥验证签名

签名算法:
  RSA-PSS（RSA 签名的现代标准）
  ECDSA（基于 ECC）
  Ed25519（Edwards 曲线签名，目前推荐）
```

---

## 六、证书与 PKI

### 6.1 数字证书 (X.509)

```
证书解决的问题:
  Alice 拿到了 Bob 的公钥 —— 但这个公钥真的是 Bob 的吗？

证书内容:
  主体: CN=github.com
  公钥: (RSA 2048-bit / ECC P-256)
  颁发者: CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1
  有效期: 2024-01-01 ~ 2025-01-01
  序列号: 0xABCD...
  签名: (颁发者的私钥签名)

证书链:
  Root CA ← 中间 CA ← 服务器证书
    └─ 自签名       └─ 签发下级      └─ 网站证书

验证过程:
  1. 服务器发送证书链
  2. 客户端的信任存储中有 Root CA 的公钥
  3. 验证 Root CA 签名的中间 CA
  4. 验证中间 CA 签名的服务器证书
  5. 检查证书未被吊销（CRL/OCSP）
  6. 检查域名匹配（CN/SAN）
```

### 6.2 PKI 的脆弱点

```
1. CA 被攻破:
   DigiNotar (2011): 攻击者申请了 *.google.com 的假证书
   → 伊朗用户被中间人攻击
   → DigiNotar 破产

2. CA 签发恶意证书:
   CNNIC (2015): 签发了未授权的中间 CA 证书
   → 被主流浏览器移除信任

3. Let's Encrypt:
   - 自动化 DV 验证（只验证域名控制）
   - 没有 OV/EV（验证组织身份）
   - 好处: 免费，HTTPS 普及
   - 风险: 任何人都可以申请任意域名的证书
```

### 6.3 证书固定 (Certificate Pinning)

```
HTTPS 证书固定（HPKP — HTTP Public Key Pinning）：
  浏览器"记住"特定的证书或公钥
  如果下次连接使用不同的证书 → 拒绝连接

但 HPKP 已被 Chrome 弃用（因为太容易导致网站不可访问）

替代方案: Expect-CT / Certificate Transparency
```

---

## 七、常见的密码学攻击

### 7.1 填充预言攻击 (Padding Oracle Attack)

```
适用: CBC 模式 + 服务端泄露填充验证结果

原理:
  假设服务器解密 CBC 密文后做两件事:
    - 如果填充格式正确 → 正常处理
    - 如果填充格式错误 → 返回错误

  攻击者可以通过修改密文的最后一个字节
  → 观察服务器是否返回填充错误
  → 逐步恢复明文

过程:
  目标: 解密密文块 C3（第3块）

  1. 创建伪造的前一块 C'2 = 任意值
  2. 发送 (C'2, C3) 给服务器
  3. 服务器解密:
     P'3 = D(K, C3) ⊕ C'2
  4. 检查 P'3 的填充:
     - 如果 P'3 的最后一个字节 = 0x01 → 填充有效
     - 如果 P'3 的最后一个字节 ≠ 0x01 → 填充错误
  5. 服务器返回成功/失败 → 1 bit 信息
  6. 攻击者可以暴力猜测最后一个字节
     （最多 256 次尝试找到使填充有效的值）
  7. 找到后: D(K,C3)[最后] = 猜测值 ⊕ C'2[最后]
  8. 然后向前推进，猜测倒数第二个字节...

  每次攻击需要约 128 × 块大小 次尝试
  对于 16 字节块 → 约 2048 次查询

  在 SSL/TLS 中:
    POODLE (2014): 降级到 SSL 3.0 → CBC 填充预言
    Lucky 13 (2013): TLS CBC 的时间侧信道攻击

  现代修复: TLS 1.3 移除了 CBC 模式
```

### 7.2 时间侧信道攻击

```
密码学操作如果"耗时"泄露了信息 → 侧信道

例子 1: RSA 解密时间
  如果 d 的某一位 = 1 → 多做一次乘法 → 多一点时间
  攻击者: 多次测量解密时间 → 推导私钥 d
  修复: 恒定时间实现 (constant-time)

例子 2: MAC 验证
  错: strcmp(计算的MAC, 接收的MAC) ← 逐字节比较
      如果第一字节错了 → 立即返回（快）
      如果前N字节都对了，第N+1字节错了 → 返回稍慢
  攻击者: 测量响应时间 → 逐字节猜对MAC
  修复: 恒定时间比较 (memcmp_const_time)

例子 3: AES 的缓存侧信道
  AES 使用 S-box 查找表 → 访问时间取决于缓存状态
  攻击者: 在同一个 CPU 核上运行进程
          监听缓存变化 → 推导密钥
  修复: 硬件 AES-NI 指令（恒定时间）
```

### 7.3 随机数攻击

```
密码学的安全都依赖"好的随机数":
  - RSA 密钥生成需要随机 p, q
  - AES key 需要随机
  - nonce/IV 需要随机或唯一

糟糕的随机数导致的安全问题:

1. 重复的 nonce (AES-GCM):
   nonce 重用一次 → 攻击者恢复 GHASH 认证密钥
   → 可以伪造任意认证标签
   → 可以解密任意密文

2. 弱随机数生成器:
   Debian OpenSSL bug (2006-2008):
     Valgrind 检测到未初始化的内存
     开发者注释了 1 行代码:
       // MD_Update(&m, buf, j);
     这行代码是收集熵的关键步骤
     结果: 只有 ~32768 种可能的随机数
     所有 Debian/Ubuntu 生成的 SSH/RSA 密钥都是可预测的

3. 熵不足:
   Linux /dev/random 阻塞时 → 应用程序使用 /dev/urandom
   嵌入式设备（路由器/IoT）:
     启动时没有足够的熵 → 生成可预测的密钥
```

### 7.4 密钥重用攻击

```
一个密钥服务多个目的 → 灾难

经典案例:
  使用同一个 RSA 密钥对实现加密和签名:
    攻击者: 发送 "解密这个"的请求
            实际上是"签名这个"
    结果: 攻击者获得了对同一个密钥的签名操作

  使用相同密钥做不同方向的加密:
    Alice → Bob: AES-GCM(key, nonce=1, msg)
    Bob → Alice: AES-GCM(key, nonce=1, ack)
    
    nonce 相同 → 认证密钥泄露！
    → 攻击者伪造任意消息

  教训: 不同目的使用不同密钥（密钥分离）
```

### 7.5 降级攻击 (Downgrade Attack)

```
攻击者让通信双方使用不安全的低版本协议。

LOGJAM (2015):
  - 攻击者: 修改 ClientHello
  - 说服服务器使用 512-bit DH（"出口级"）
  - 512-bit DH 可以被预先计算破解
  - 影响: TLS 连接的 confidentiality 被破坏

FREAK (2015):
  - 类似 logjam，针对 RSA 导出级密钥
  - 迫使服务器使用 512-bit RSA

DROWN (2016):
  - 攻击 TLS 服务器同时运行 SSLv2（为兼容性）
  - 攻破 SSLv2 连接 → 恢复 TLS 连接的密钥
  - 影响: 三分之一 的 HTTPS 服务器

修复: TLS 1.3 移除了所有遗留算法
      服务器禁用 SSL 2.0/3.0
      最低使用 TLS 1.2
```

---

## 八、混合加密与安全通道

### 8.1 真实世界的加密

```
现实中没人"只用对称"或"只用非对称":

  混合加密:
    1. 非对称: 双方协商共享密钥
    2. 对称: 用共享密钥加密大量数据
    3. 认证: 加密前/后提供完整性

  TLS 1.3 的具体实现:
    ClientHello (密钥交换提议)
    ServerHello + 证书 + 签名 + 密钥交换(临时密钥)
    Finished (全部握手消息的 MAC)
    ─── 以上是握手（非对称）───
    应用数据 (对称加密: AES-GCM / ChaCha20-Poly1305)
```

### 8.2 前向保密 (Perfect Forward Secrecy)

```
没有前向保密的协议（RSA 密钥交换）:
  攻击者记录所有加密流量
  后来获取了服务器的私钥
  → 可以解密所有历史会话

有前向保密的协议 (ECDHE / DHE):
  每个会话使用临时密钥对
  会话结束后丢弃临时私钥
  即使长期私钥泄露 → 历史会话安全

这就是为什么 TLS 1.3 强制使用 (EC)DHE
这就是 Signal 协议的"自我消除消息"的基础
```

### 8.3 认证加密 (AEAD)

```
AEAD = Authenticated Encryption with Associated Data

  加密 + 认证 + 附加数据（如IP头）

  安全通道的正确设计:
    错: 只加密不认证                      ← 可被篡改
    错: 只认证不加密                      ← 可被读取
    错: 先认证后加密 (MAC-then-Encrypt)    ← 危险（TLS 1.2之前）
    错: 先加密后认证 (Encrypt-then-MAC)    ← 可接受
    对: 认证加密一体 (GCM/ChaCha20-Poly1305)  ← 推荐

  TLS 1.3 只允许 AEAD 模式:
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
```

---

## 九、后量子密码学 (Post-Quantum Cryptography)

### 9.1 为什么要关心？

```
Shor 算法（量子计算机）可以指数级加速:
  - 大整数分解 → 破解 RSA
  - 离散对数 → 破解 DH、ECC、DSA

预计 10-15 年内大规模量子计算机可行
意味着目前所有非对称加密都会失效

"Harvest Now, Decrypt Later" 攻击:
  攻击者现在记录加密流量
  等量子计算机可用 → 解密历史数据
  所以你需要"现在就迁移到后量子"

后量子 ≠ 量子密钥分发 (QKD)
  后量子密码: 新的数学难题（基于格/lattice等）
  QKD: 用量子力学原理分发密钥（需要专门硬件）
```

### 9.2 NIST 后量子标准（2024）

```
选择的标准算法:
  CRYSTALS-Kyber   → 密钥封装 (KEM) — 替代 RSA/DH
  CRYSTALS-Dilithium → 数字签名 — 替代 RSA/ECDSA
  SPHINCS+         → 签名（备选）
  Falcon           → 签名（备选）

数学基础: 格密码 (Lattice-based Cryptography)
  - 基于 Learning With Errors (LWE) 问题
  - 被广泛认为量子安全
  - 密钥/签名比传统 RSA 大很多（KB 级别）

过渡方案: 混合密钥交换
  TLS 1.3 支持:
    ClientHello 中包含多个密钥共享
    传统密钥 (ECDHE X25519) + 后量子密钥 (Kyber-768)
    即使量子计算机出现 → 会话仍安全
```

---

## 十、渗透测试中的密码学检查

### 10.1 TLS 配置检查

```bash
# 用 openssl 检查服务器支持的 TLS 版本和密码套件
openssl s_client -connect target.com:443 -tls1_3
openssl s_client -connect target.com:443 -tls1_2

# 检查证书链
openssl s_client -connect target.com:443 -showcerts

# 使用 testssl.sh（最全面的 TLS 检查工具）
testssl.sh target.com

# 检查弱加密套件是否开启
# 特别是: DES, 3DES, RC4, CBC 模式

# 检查 SSLv2/SSLv3 是否启用（灾难）
```

### 10.2 常见漏洞

```
1. 使用自签名证书或过期证书
   → 理论上不危险，实践中用户忽略警告直接访问

2. 证书 CN/SAN 不匹配
   → 浏览器显示警告 → 但用户可能忽略

3. CBC 模式 + 填充预言攻击
   → 检查 TLS 版本（TLS 1.0/1.1 有漏洞）
   → 检查服务器是否泄露填充错误

4. 弱 Diffie-Hellman 参数
   → 使用 1024-bit DH（被 logjam 攻击）
   → 使用固定的 DH 组（没有前向保密）

5. 不安全的随机数
   → 检查 JWT token 是否可预测
   → 检查 session ID 是否可预测
   → 检查 CSRF token 是否可预测

6. 密码存储不当
   → 明文存储密码
   → 使用 MD5/SHA1 对密码哈希
   → 没有加盐
```

### 10.3 检查清单

```bash
# 1. TLS 版本检查
#   禁止: SSLv2, SSLv3, TLS 1.0, TLS 1.1
#   允许: TLS 1.2, TLS 1.3

# 2. 证书检查
openssl x509 -in cert.pem -text -noout | grep -E "Issuer|Subject|Not Before|Not After|DNS"
#   是否使用信任的 CA？
#   是否有完整的证书链？
#   是否在有效期内？
#   是否支持扩展验证 (EV)？

# 3. 密码套件检查
#   禁止: NULL, EXPORT, RC4, DES, 3DES, CBC
#   允许: AES-GCM, ChaCha20-Poly1305

# 4. JWT 检查
#   alg: none? → 认证绕过
#   alg: HS256 → 密钥是否够长？
#   alg: RS256 → 公钥是否可获取？

# 5. 密码重置 token
#   是否可预测？
#   是否基于时间戳 + 简单的随机数？
#   是否有过期时间？
```

---

## 十一、总结

### 核心思维模型

```
做密码学正确的三件事:
  1. 用现成的、经过审计的库
     不自己实现加密算法
     不自己发明加密协议

  2. 使用认证加密 (AEAD)
     AES-GCM 或 ChaCha20-Poly1305
     不是 CBC + HMAC
     不是 ECB

  3. 保持 nonce/IV 唯一
     对同一密钥永不重用 nonce
     随机生成 nonce（至少 12 字节）
```

### 安全金字塔

```
                   ┌─────────────┐
                   │   TLS 1.3   │  ← 最高安全级别
                   ├─────────────┤
                   │    AEAD     │  ← AES-GCM/ChaCha20-Poly1305
                   ├─────────────┤
                   │  前向保密   │  ← ECDHE
                   ├─────────────┤
                   │   签名      │  ← Ed25519 / ECDSA / RSA-PSS
                   ├─────────────┤
                   │   哈希      │  ← SHA-256 / SHA-3
                   ├─────────────┤
                   │   随机数    │  ← 恒定时间、熵充足
                   └─────────────┘
```

### 最危险的密码学错误（从渗透测试看）

```
等级 1（灾难 — 整个应用有漏洞）:
  - 密码以明文存储
  - JWT 的 alg 设置为 "none"
  - 自定义加密算法
  - 硬编码的加密密钥

等级 2（严重 — 关键功能有漏洞）:
  - 使用不安全的 TLS 版本（SSLv3/TLS 1.0）
  - 密码重置 token 可预测
  - 使用 ECB 模式
  - 不验证证书链
  - 使用 MD5/SHA1 做安全相关操作

等级 3（中等 — 需要情境利用）:
  - 时间侧信道（MAC 验证）
  - 弱随机数（熵不足）
  - 不安全的密钥存储
  - 降级攻击
```

> **密码学最难的部分不是算法，是「密钥管理」。**
> 
> 算法你选 AES-GCM 就对了。
> 但 Key 怎么生成的？怎么存的？怎么分发的？怎么轮换的？怎么撤销的？
> 这些问题才是实际中漏洞最多的地方。
