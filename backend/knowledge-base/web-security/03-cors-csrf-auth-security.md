# CORS、认证机制与 OAuth 安全

> 知识库层级：Level 1 - Web 安全基础
> 日期：2026-06-04
> 来源：W3C CORS Specification, RFC 6749 (OAuth 2.0), PortSwigger Research, Auth0 Blog

## 一、跨源资源共享（CORS）

### 1.1 为什么需要 CORS？

同源策略（SOP）默认禁止跨源请求读取响应数据。但 Web 应用天然需要跨源访问：

```
前端 https://app.example.com 需要访问 https://api.example.com/data
  ↓
SOP 阻止了 JavaScript 读取跨源响应
  ↓
需要一套机制让服务器"选择性地"允许跨源访问
  ↓
这就是 CORS
```

### 1.2 CORS 的工作原理

**CORS 是一个"服务端授权的跨源访问机制"。** 通过 HTTP 响应头实现：

```
浏览器发送请求（带 Origin 头）
    ↓
服务器响应（带 Access-Control-Allow-Origin 头）
    ↓
浏览器检查：Origin 是否在允许列表中？
    ↓
允许 → JavaScript 可以读取响应
拒绝 → JavaScript 无法读取响应（但请求可能已经到达服务器）
```

### 1.3 简单请求 vs 预检请求

| 类型 | 条件 | 行为 |
|------|------|------|
| **简单请求** | GET/HEAD/POST + 简单 Content-Type + 无自定义头 | 直接发送，浏览器检查响应头 |
| **预检请求** | PUT/DELETE/PATCH + 自定义头 + 非简单 Content-Type | 先发 OPTIONS 预检，通过后再发实际请求 |

**安全含义：** 预检请求意味着服务器可以先知道"即将有跨源请求到来"。但简单请求不会预检，所以 `<img src="https://api.example.com/delete?id=1">` 这样的 CSRF 攻击无法被 CORS 阻止（请求已经发送，只是 JS 不能读响应）。

### 1.4 CORS 配置错误的攻击面

| 配置 | 风险 | 攻击方式 |
|------|------|----------|
| `Access-Control-Allow-Origin: *` | 任何网站都可跨源读取数据 | 恶意网站读取 API 数据 |
| `Access-Control-Allow-Credentials: true` + 反射 Origin | 凭据被发送到攻击者网站 | `Origin: https://evil.com` → 服务器反射回 `evil.com` |
| `Access-Control-Allow-Methods: DELETE` | 允许跨源删除操作 | 结合 CSRF |
| `Vary: Origin` 缺失 | CDN/Proxy 缓存了跨源响应 | 访问者拿到之前用户的跨源响应 |

**最危险的组合：**
```http
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```
→ 攻击者网站可以读取用户的敏感数据（凭据附带）

---

## 二、Web 认证机制

### 2.1 Cookie-Based Session 认证

```
用户登录 → 服务器生成 Session ID → 设置 Cookie
后续请求 → 浏览器自动发送 Cookie → 服务器查找 Session → 确认身份
```

**安全要点：**

| Cookie 属性 | 作用 | 安全意义 |
|-------------|------|----------|
| `Secure` | 仅通过 HTTPS 发送 | 防止中间人窃取 Cookie |
| `HttpOnly` | JavaScript 无法读取 | 防止 XSS 窃取 Cookie |
| `SameSite` | 限制跨站发送 | 防止 CSRF |
| `Domain` | 限制发送的域名范围 | 防止子域名攻击 |
| `Path` | 限制发送的路径范围 | 最小权限原则 |

**攻击面分析：**

| 攻击 | 底层原因 | 利用条件 |
|------|----------|----------|
| Session 固定 | 服务器在用户登录前就分配了 Session ID | 攻击者先给用户一个已知的 Session ID |
| Session 劫持 | Cookie 被窃取（XSS/网络嗅探） | 未设置 HttpOnly/Secure |
| Session 预测 | Session ID 生成不够随机 | 可预测的 ID 生成算法 |
| Session 侧信道 | Cookie 大小暴露用户身份 | 利用压缩比差异 |

### 2.2 Token-Based 认证（JWT）

**JWT 结构：**
```
header.payload.signature
  ↓         ↓         ↓
算法类型  用户身份  防篡改签名
(Base64)  (Base64)  (HMAC/RSA/ECDSA)
```

**JWT 的安全陷阱：**

| 攻击 | 原理 | 示例 |
|------|------|------|
| **alg: none** | 服务端未验证签名算法 | `alg: none` → 不验证签名 → 任意伪造 Token |
| **密钥混淆** | 服务端使用 RSA 公钥验证 HMAC Token | 公钥可知 → 用公钥作为 HMAC 密钥伪造 |
| **kid 注入** | kid 头用于查找密钥，可能通过文件读取 | `kid: ../../etc/passwd` |
| **过期时间忽视** | `exp` 字段未验证 | 过期的 Token 仍然可用 |
| **弱密钥** | HMAC 密钥强度不足 | 密钥字典爆破 |

**防御：**
- 始终验证 `alg` 字段，拒绝 `none`
- 使用强随机密钥
- 验证 `exp`, `nbf`, `iss`, `aud` 字段
- 避免在 JWT 中存储敏感数据（Payload 是 Base64 编码，不是加密）

### 2.3 多因素认证（MFA）绕过

| 绕过方式 | 原理 | 常见场景 |
|----------|------|----------|
| **暴力破解** | TOTP 码只有 6 位，某些实现未限制尝试次数 | 30 秒内可尝试所有组合 |
| **会话重用** | 完成 MFA 后 Session 不重新绑定 | 攻击者可以在 MFA 前劫持会话 |
| **短信劫持** | SIM Swap 攻击 | 攻击者转移受害者的手机号 |
| **备份码泄露** | MFA 启用时的备用码未安全存储 | 数据库泄露 |
| **OAuth 回退** | 应用降级到无 MFA 的认证方式 | 攻击者强制使用较弱认证 |

---

## 三、OAuth 2.0 与 SSO 安全

### 3.1 OAuth 2.0 的核心流程

```
用户 → 客户端应用（App）→ 授权服务器 → 资源服务器

1. App 请求用户授权
2. 用户同意授权
3. App 获得授权码（Authorization Code）
4. App 用授权码换取访问令牌（Access Token）
5. App 用访问令牌获取用户数据
```

### 3.2 OAuth 的主要攻击面

| 攻击 | 原理 | 条件 |
|------|------|------|
| **CSRF on OAuth** | 授权码绑定不当 | 攻击者用自己的授权码替换用户的 |
| **重定向 URI 劫持** | redirect_uri 校验不严 | `redirect_uri=https://app.com.evil.com/callback` |
| **Token 泄露** | Token 在 URL 片段中存在 | Referer 头、浏览器历史、日志 |
| **混淆代理攻击** | 客户端误用授权码 | 一个 App 的授权码被另一个 App 使用 |
| **隐式模式漏洞** | implicit grant type 直接在 URL 中返回 Token | Token 泄露风险极高 |

### 3.3 SSO 单点登录的安全模型

SSO 的安全核心在于 **信任关系**：

```
一个认证提供者（IdP）→ 多个服务提供者（SP）
                    ↑
             信任是关键
```

**攻击面：**
- **IdP 被攻破** → 所有 SP 被攻破（单点失效）
- **SP 的 metadata 被篡改** → 攻击者注册自己的 SP
- **SAML 签名验证绕过** → XML 签名包装攻击
- **用户身份联合** → 一个 SP 中的身份篡改影响其他 SP

---

## 四、从原理推导攻击方向

### 4.1 Web 认证的底层矛盾

```
安全性 ←→ 用户体验

强密码要求        → 用户使用密码管理器/写下密码
MFA              → 用户抱怨繁琐
短 Session 过期   → 用户频繁重新登录
严格 CORS        → 开发人员配置宽松策略
```

**渗透测试员的视角：** 每个为了"用户体验"而放宽安全配置的地方，就是攻击面。

### 4.2 认证攻击的思维框架

```
前提: 我需要获取系统访问权限
  ↓
路径 A: 绕过认证
  ├─ 弱密码爆破
  ├─ 默认凭据
  ├─ 认证逻辑缺陷 (忘记密码、记住我)
  └─ Session 劫持
  ↓
路径 B: 绕过权限检查
  ├─ IDOR (参数篡改)
  ├─ 水平越权 (查看其他用户的数据)
  └─ 垂直越权 (普通用户→管理员)
  ↓
路径 C: 利用信任关系
  ├─ OAuth 混淆代理
  ├─ SSO 信任滥用
  └─ 第三方集成漏洞
```

### 4.3 真实渗透链路中的认证攻击

```
发现 API 端点 (子域名枚举/目录爆破)
  ↓
测试认证机制 (Cookie/JWT/OAuth)
  ↓
发现 CORS 配置错误 (Access-Control-Allow-Origin: *)
  ↓
构造钓鱼页面读取用户 API 响应
  ↓
获取用户数据（含 OAuth Token）
  ↓
用 Token 访问第三方服务
  ↓
扩大攻击面
```

---

## 【LLM 推理段 — CORS 配置错误】

### 触发条件
- 目标有 API 接口（REST/GraphQL），特别是需要跨域请求的
- 响应头中有 `Access-Control-Allow-Origin`
- 典型场景: SPA 前端 + API 后端分离架构

### 检测信号
| 信号类型 | 具体表现 | 置信度 | 检测方法 |
|---------|---------|--------|---------|
| 响应头 | `Access-Control-Allow-Origin: *` | 高 | curl -I 查看响应头 |
| 响应头 | `Access-Control-Allow-Origin` 回显 Origin | 高 | 传 Origin: https://evil.com 看是否回显 |
| 凭证 | `Access-Control-Allow-Credentials: true` | 高 | 检查响应头 |
| 方法 | `Access-Control-Allow-Methods` 包含 DELETE/PUT | 中 | OPTIONS 预检请求 |

### 验证步骤
1. 发 OPTIONS 预检请求 → 看允许的 Origin 和方法
2. 传 Origin: https://attacker.com → 如果回显 → CORS 配置错误确认
3. 如果同时有 `Allow-Credentials: true` + Origin 回显 → 可利用（可窃取用户数据）
4. 确认标准: 攻击者页面可通过 AJAX 读取目标 API 的响应

### 利用链扩展
| 条件 | 可做 | 后续 |
|------|------|------|
| Origin 回显 + Credentials | 窃取登录用户 API 数据 | 信息泄露、越权 |
| Origin 回显（无凭证） | 读取公开 API 数据 | 信息收集 |

### 常见误判
- `Access-Control-Allow-Origin: *` 但无 `Credentials` → 只能读取公开数据，不算高危
- Origin 白名单中有可信第三方域名 → 检查第三方是否有子域名接管风险

---

## 【LLM 推理段 — CORS + CSRF 组合攻击】

### 触发条件
- API 同时有 CORS 配置错误 + Cookie 认证

### 检测信号
- CORS 允许任意 Origin + Cookie 无 SameSite=Strict
- API 对状态变更操作无 CSRF token 校验

### 验证步骤
1. 构造攻击页面 → 用户访问 → AJAX 发请求带 Cookie → 读取响应
2. 确认标准: 攻击页面可读取敏感响应数据 或 执行状态变更

---

## 【LLM 推理段 — 认证绕过】

### 触发条件
- 目标有登录/注册/密码重置功能
- 使用 JWT/OAuth/Session 认证方案

### 检测信号
| 信号类型 | 具体表现 | 置信度 | 检测方法 |
|---------|---------|--------|---------|
| JWT | token 在 URL/请求头 | 高 | 解码看 payload |
| JWT | alg: none | 极高 | 修改 alg 为 none 重放 |
| JWT | 公钥已知 | 高 | 修改 payload 用公钥验签 |
| Session | 可预测 session ID | 中 | 连续登录看 ID 规律 |
| OAuth | redirect_uri 未校验 | 高 | 修改 redirect_uri 到 evil.com |
| 密码重置 | token 在 URL 中 | 中 | 分析 token 是否可预测 |

### 验证步骤
1. **JWT none 攻击**: 解码 JWT → 改 alg 为 none → 重放 → 通过则确认
2. **JWT 算法混淆**: 获取公钥 → 用公钥签名 HS256 → 通过则确认
3. **Session 预测**: 连续登录获取多个 session ID → 分析规律 → 预测其他用户 session
4. **密码重置 token**: 获取重置链接 → 分析 token 是否为时间戳/MD5(用户名) → 可预测则确认
5. **OAuth redirect**: 修改 redirect_uri → 看是否跳转到攻击者服务器接收 code

### 利用链扩展
| 利用方式 | 后续攻击面 |
|---------|-----------|
| JWT 伪造 | 任意用户登录、越权 |
| Session 劫持 | 完全接管用户会话 |
| 密码重置 | 账号接管 |
| OAuth code 劫持 | 第三方账号接管 |

### 常见误判
- JWT alg 为 none 但在白名单中禁用 → 攻击失败，但不代表有其他 JWT 漏洞
- OAuth redirect_uri 校验存在但允许子路径 → 通过子路径注入
