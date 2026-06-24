# HTTP 协议规范与安全

> 知识库层级：Level 1 - 网络协议基础
> 日期：2026-06-04
> 来源：RFC 9110/9112, PortSwigger Research, USENIX Security 25, Cloudflare Blog

## 一、HTTP 的核心概念

### 1.1 HTTP 的本质

HTTP 是一个**基于消息的、无状态的应用层协议**。它的核心设计：

```
请求: 方法 + URI + 版本 + 头字段 + 可选消息体
响应: 版本 + 状态码 + 原因短语 + 头字段 + 可选消息体
```

**关键特征：**
- **无状态：** 每个请求是独立的，服务器不记住之前请求的上下文
- **文本协议：** 所有消息头都是人类可读的 ASCII 文本
- **分层体系：** 可以有多个中间件（代理、网关、CDN）参与请求转发

### 1.2 请求格式

```
GET /index.html HTTP/1.1        ← 请求行
Host: example.com                ← 必需的头字段（HTTP/1.1 强制）
User-Agent: Mozilla/5.0         ← 可选头
Accept: text/html               ← 内容协商
Authorization: Bearer xyz123    ← 认证
Cookie: session=abc123          ← 状态管理

                                  ← 空行（\r\n\r\n 分隔头和体）
body content...                  ← 请求体（GET 通常无体）
```

**请求行三要素：**
- **方法：** GET（查）、POST（增）、PUT（改）、DELETE（删）、HEAD、OPTIONS、PATCH
- **URI：** 协议相对路径或绝对路径
- **版本：** HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3

### 1.3 响应格式

```
HTTP/1.1 200 OK                  ← 状态行
Content-Type: text/html          ← 响应类型
Content-Length: 1024             ← 消息体长度
Set-Cookie: session=abc123       ← 状态设置
Cache-Control: no-cache          ← 缓存控制
Server: nginx/1.26.0             ← 服务器信息

                                  ← 空行
<html>                           ← 响应体
...
</html>
```

## 二、消息体长度确定（Message Framing）

这是 HTTP 安全中最关键的技术细节。消息体长度的确定方式决定了**请求走私 (Request Smuggling)** 等严重漏洞的根源。

### 2.1 五种确定方式（优先级顺序）

```
① Transfer-Encoding: chunked   ← 优先级最高
② Content-Length 字段          ← 第二优先级
③ 如果是 multipart/byteranges → 边界确定
④ 没有体 → 没有 Content-Length 即长度为 0
⑤ 服务器在连接关闭前发送完    ← HTTP/1.0 的后备方案
```

### 2.2 分块编码（Chunked Transfer Encoding）

```
HTTP/1.1 200 OK
Transfer-Encoding: chunked

25                            ← 16 进制的块大小（37 字节）
This is the data in the first chunk
1a                            ← 26 字节
and this is the second one   
0                             ← 0 表示结束
                              ← 结束后的空行
```

**构造细节：**
- 块大小是十六进制 ASCII 数字，后面跟 CRLF
- 然后是块内容，再跟 CRLF
- 最后一个块大小是 0，表示终止
- 可以在结束块后跟**尾部字段 (Trailer)**（RFC 9112 允许）

### 2.3 Content-Length 头

```
Content-Length: 348
```

消息体的字节数。**必须是精确的十进制整数。** 如果实发长度 > Content-Length，多出的部分属于下一个请求。如果实发长度 < Content-Length，连接可能会挂起。

## 三、请求走私（HTTP Request Smuggling）

### 3.1 漏洞根源

请求走私的根本原因是**前端服务器和后端服务器对 HTTP 请求的边界理解不一致。**

```
前端代理 (Nginx)        后端服务器 (Apache)
    │                        │
    ├── 发送请求 ───────────→ │
    │                        │
    │  前端认为请求在 A 结束  │  后端认为请求在 B 结束
    │  则 B 开始处是下一个请求 │  则 A 和 B 之间是同一个请求
    │                        │
    │  → 一个请求被拆解为两个 ←│
```

### 3.2 CL.TE 类型（Content-Length vs Transfer-Encoding）

前端使用 Content-Length，后端使用 Transfer-Encoding：

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 44            ← 前端认为整个请求 44 字节
Transfer-Encoding: chunked    ← 后端用 chunked 解析

0                            ← 后端看到 0 → 认为请求结束

GET /admin HTTP/1.1           ← 后端认为这是一个新请求
Host: vulnerable.com
```

**攻击效果：** 前端把 `GET /admin` 当作第一个请求的一部分，后端把它当作第二个请求。如果前端验证权限（前端检查 `/admin` 是否可访问），攻击者可以绕过检查直接访问内网管理接口。

### 3.3 TE.CL 类型（Transfer-Encoding vs Content-Length）

前端使用 Transfer-Encoding，后端使用 Content-Length：

```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4             ← 后端认为只有 4 字节（"0\r\n"）
Transfer-Encoding: chunked    ← 前端用 chunked 解析

5c                           ← 92 字节的恶意请求
POST /admin HTTP/1.1
Host: vulnerable.com
Content-Length: 15

x=1
0                            ← chunked 结束标志

                               ← 后端看到 4 字节后认为请求结束
                               → "POST /admin..." 开始下一个请求
                               → 后端认为是合法用户请求
```

### 3.4 TE.TE 类型（两者都解析 Transfer-Encoding 但方式不同）

前端和后端都解析 Transfer-Encoding，但对头字段的解析方式不同（如大小写、空格差异）：

```http
POST / HTTP/1.1
Host: vulnerable.com
Transfer-Encoding: chunked    ← 前端识别
Transfer-encoding: x          ← 后端正则匹配时忽略大小写差异
                               → 后端的 Transfer-encoding 不合法
                               → 后端回退到 Content-Length
```

### 3.5 请求走私的经典攻击场景

| 攻击场景 | 效果 |
|----------|------|
| **绕过权限检查** | 前端检查 URL 权限，但被走私的请求绕过检查直达后端 |
| **会话劫持** | 将请求走私到其他用户的连接中，窃取响应数据 |
| **缓存投毒** | 向缓存服务器注入恶意内容，让后续用户收到攻击者控制的页面 |
| **XSS 注入** | 在缓存页面中注入恶意 JavaScript |
| **绕过 WAF** | 前端 WAF 检查了请求，但走私的请求未经检查直达后端 |

## 四、HTTP 认证机制

### 4.1 HTTP Basic Auth

```http
Authorization: Basic base64(username:password)
```

- 密码只经过 base64 编码（非加密），等价于明文传输
- 除非配合 HTTPS，否则中间人可以直接读取
- 浏览器会缓存凭据，且没有简便的登出机制

### 4.2 HTTP Digest Auth

```http
Authorization: Digest username="admin",
    realm="test",
    nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
    uri="/protected",
    response="6629fae49393a05397450978507c4ef1",
    opaque="5ccc069c403ebaf9f0171e9517f40e41"
```

- 客户端用密码和 nonce 计算哈希，不直接发送密码
- 但服务器必须存储明文或等价的哈希（彩虹表攻击风险）
- 没有完美的前向保密（如果密码泄露，历史通信都可以被解密）

### 4.3 Bearer Token (JWT/Bearer)

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

- Token 由服务器签发，客户端持证访问
- 核心安全问题：Token 的签名验证、Token 泄露（XSS/日志/URL 泄露）
- 无状态：服务器不需要存储 session，但 Token 签发后无法立即撤销

## 五、状态管理：Cookie

### 5.1 Cookie 的安全属性

| 属性 | 作用 | 安全意义 |
|------|------|----------|
| `Secure` | 只在 HTTPS 中发送 | 防止明文传输泄露 |
| `HttpOnly` | 禁止 JavaScript 访问 | 防止 XSS 窃取 Cookie |
| `SameSite=Strict` | 只在同站请求发送 | 防御 CSRF |
| `SameSite=Lax` | GET 请求的同站要求放宽 | 平衡安全和可用性 |
| `Domain` | 指定可接收 Cookie 的域名 | 严格限制到最小域 |
| `Path` | 指定可接收 Cookie 的路径 | 限制作用范围 |

### 5.2 Cookie 注入与篡改

```
Cookie 的本质：
服务器通过 Set-Cookie 设置 → 浏览器保存
→ 后续请求自动带上 → 服务器校验

攻击角度：
① 子域名可以设置父域名的 Cookie
  → 如果攻击者控制了子域名，可以覆盖父域名的 Cookie
  → 实现会话固定（Session Fixation）
  
② Cookie 可以被中间人篡改（没有 Secure 属性时）
  → HTTP 连接中的 Cookie 可以被修改
  → 如果服务器信任 Cookie 做身份判断 → 身份伪造

③ Cookie 可以被 JavaScript 读取和修改（没有 HttpOnly 时）
  → XSS 攻击者可以窃取所有 Cookie
  → 修改 Cookie 实现会话劫持

④ Cookie 大小限制（通常 4096 字节）
  → 如果 Cookie 太大 → 部分截断 → 可能破坏签名/完整性
```

## 六、HSTS（HTTP Strict Transport Security）

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**原理：** 告诉浏览器："从现在起，这个域名只能走 HTTPS，持续一年。子域名也一样。"

**为什么需要 HSTS：** 即使用户访问 HTTPS 网站，第一次请求也可能走 HTTP（用户手动输入域名或点击 HTTP 链接）。攻击者可以在第一次 HTTP 请求时劫持连接。

**攻击绕过：**
- HSTS 只在第一次收到响应后才生效，**第一次建立连接之前是不安全的**
- 如果浏览器没有预加载列表，首次访问仍可被劫持
- 老旧的 HSTS 或不包括子域名的 HSTS 会让攻击面扩大

## 七、跨域策略：CORS（Cross-Origin Resource Sharing）

### 7.1 为什么需要 CORS？

浏览器的**同源策略 (Same-Origin Policy)** 默认禁止脚本访问不同源的资源。但有些场景下需要跨域资源的读取（比如 API 请求）。

CORS 是一个**权限声明机制**，服务器通过响应头告诉浏览器："允许特定来源的脚本读取我的资源。"

### 7.2 关键头字段

```
Access-Control-Allow-Origin: https://example.com   ← 允许哪个源
Access-Control-Allow-Credentials: true              ← 是否允许带凭据
Access-Control-Allow-Methods: GET, POST             ← 允许哪些方法
Access-Control-Allow-Headers: Content-Type          ← 允许哪些头
Access-Control-Expose-Headers: X-Custom-Header      ← 允许暴露哪些头
Access-Control-Max-Age: 3600                        ← 预检结果缓存时间
```

### 7.3 预检请求（Preflight Request）

对于非简单请求（`PUT/DELETE`、自定义头、非 `text/plain` 类型），浏览器先发一个 `OPTIONS` 请求：

```http
OPTIONS /api/data HTTP/1.1
Origin: https://evil.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom-Header
```

服务器回复许可后，浏览器才发真正的请求。

### 7.4 CORS 常见配置错误

| 配置错误 | 攻击方式 |
|----------|----------|
| `Access-Control-Allow-Origin: *` | 任何网站都可以读取 API 响应 |
| `Access-Control-Allow-Origin: null` | 任意 sandbox 文档都可以访问 |
| 动态 Origin 反射（未验证） | `evil.com` 被直接反射到 `Allow-Origin` |
| 允许 `*` + `credentials: true`（规范不允许，但某些实现有误） | 凭据泄露 |

## 八、重要技术细节：RFC 9112 更新内容（2022年）

2022 年的 RFC 9112 取代了 2014 年的 RFC 7230，从安全角度最重要的变化：

| 变化 | 内容 | 安全意义 |
|------|------|----------|
| 更加严格要求 CRLF | 接收方必须拒绝或清理空白行、bare CR | 减少解析差异导致的走私 |
| Transfer-Encoding 优先 | 明确要求 Transfer-Encoding 覆盖 Content-Length | 减少 CL.TE 争议 |
| 禁止两者共存 | 同时有 Content-Length 和 Transfer-Encoding 必须拒绝 | 直接封堵 CL.TE 类攻击 |
| 对 chunk 大小的限制 | 限制 chunk size 解析的灵活性 | 减少解析漏洞 |

**现实问题：** 尽管 RFC 9112 发布于 2022 年，大量生产环境系统（Nginx < 1.27、Apache < 2.5、各种 HTTP 库）仍然沿用旧解析方式，造成了安全空窗。

## 九、从协议原理推导攻击面

### 9.1 每个协议特征对应的攻击方向

| HTTP 特征 | 攻击面 | 原理 |
|-----------|--------|------|
| 消息边界由头字段确定 | 请求走私 | 前后端解析不一致 |
| 无状态设计 | 会话固定、CSRF | 没有内建的请求关联机制 |
| 文本协议 | CRLF 注入、HTTP 头拆分 | 换行符被错误地解释为消息边界 |
| 可读的 URI | 路径遍历、URL 编码绕过 | URI 的规范性不够严格 |
| 可扩展的头字段 | 头注入、Host 头攻击 | 自定义头字段缺乏安全规范 |
| 分块编码 | CL.TE 走私 | 两种确定长度的方式可能冲突 |
| 缓存机制 | 缓存投毒、缓存欺骗 | 缓存键和实际请求内容的不匹配 |
| Cookie 的路径/域继承 | 会话固定、子域名 Cookie 覆盖 | Cookie 作用域大于预期 |
| CORS 是权限声明非强制 | CORS 配置错误数据泄露 | 依赖服务器正确配置而非协议强制 |

### 9.2 渗透测试中的 HTTP 协议检查点

```
1. 检查 Transfer-Encoding 和 Content-Length 冲突
   → 发送同时包含两者的请求，观察服务器行为

2. 检查 CRLF 注入
   → 在参数中插入 %0d%0a（CRLF），看是否影响响应

3. 检查 Host 头攻击
   → 修改 Host 头，观察是否影响服务器行为

4. 检查 Cookie 安全属性
   → Secure、HttpOnly、SameSite 是否都正确设置

5. 检查 CORS 配置
   → 用不同 Origin 测试，看 Access-Control-Allow-Origin

6. 检查 HSTS
   → 响应头是否包含 HSTS、max-age 是否足够长

7. 检查 HTTPS 降级
   → 能否强制使用 HTTP 访问敏感页面
```

---

**下一层：** 理解 HTTP 协议后，下一步是"Web 浏览器安全模型"——同源策略、DOM 安全、XSS/CSRF 的底层原理、Content Security Policy。

---

## 【LLM 推理段 — HTTP 请求走私】

### 触发条件
- 前端反向代理（Nginx/HAProxy/Cloudflare）+ 后端应用服务器（Apache/Tomcat/gunicorn）
- 前后端对 HTTP 请求边界理解不一致
- 典型: CL-CL、CL-TE、TE-CL、TE-TE

### 检测信号
| 信号类型 | 具体表现 | 置信度 | 检测方法 |
|---------|---------|--------|---------|
| 架构 | 检测到反向代理 | 中 | 响应头有 Via/X-Cache/X-Forwarded-For |
| 延时 | 请求构造后响应延迟异常 | 高 | 发送走私 payload 看响应时间 |
| 污染 | 后续请求被影响 | 极高 | 走私后下一个请求返回异常响应 |
| 技术栈 | Nginx + Apache 组合 | 中 | whatweb/响应头识别 |

### 验证步骤
1. CL-TE: 构造 Content-Length 和 Transfer-Encoding 冲突的请求 → 看后端如何解析
2. TE-CL: 反向构造 → 看前端和后端解析顺序差异
3. 确认标准: 两个请求打包发送，第二个请求的响应被第一个请求的响应替代

### 利用链扩展
| 利用方式 | 说明 |
|---------|------|
| 缓存投毒 | 将恶意响应缓存到 CDN，影响所有用户 |
| 请求劫持 | 绕过前端安全控制，直接访问后端接口 |
| WAF 绕过 | 走私请求绕过 WAF 检测 |

---

## 【LLM 推理段 — HTTP 安全头检查】

### 触发条件
- 任何 HTTP 服务

### 检测信号
| 安全头 | 缺失风险 | 期望值 |
|--------|---------|--------|
| Content-Security-Policy | XSS 防御薄弱 | 应配置白名单/Nonce |
| Strict-Transport-Security | SSL Strip 风险 | max-age >= 31536000 |
| X-Content-Type-Options | MIME 类型混淆 | nosniff |
| X-Frame-Options | 点击劫持 | DENY/SAMEORIGIN |
| Referrer-Policy | 路径泄露 | same-origin/no-referrer |
| Permissions-Policy | API 滥用 | 最小权限原则 |

### 验证步骤
1. curl -I 目标 → 逐项检查安全头
2. 确认标准: 缺少安全头或配置过于宽松

---

## 【LLM 推理段 — Cookie 安全】

### 检测信号
| Cookie 属性 | 意义 | 检查方法 |
|------------|------|---------|
| Secure | 仅 HTTPS 传输 | Set-Cookie 无 Secure → 明文网络泄露 |
| HttpOnly | JS 不可读 | 无 HttpOnly → XSS 可窃取 |
| SameSite | CSRF 防御 | None → 跨站请求可带 Cookie |
| Path | 作用域 | 设置过宽 → 子路径可访问 |
| Domain | 作用域 | 设置过宽 → 子域名可访问 |
| Expires/Max-Age | 持久化 | 过长 → 泄露风险持续 |

### 利用链扩展
- SameSite=None + 无 Secure → 跨站请求可带 Cookie，即使 HTTP 也可传输
- 无 HttpOnly + XSS → Cookie 窃取 → 会话劫持
