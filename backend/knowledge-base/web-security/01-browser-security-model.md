# Web 浏览器安全模型

> 知识库层级：Level 1 - Web 安全基础
> 日期：2026-06-04
> 来源：MDN Web Docs, PortSwigger Research, W3C CSP Specification, IEEE S&P 17

## 一、同源策略（Same-Origin Policy）— 浏览器安全的基石

### 1.1 定义

同源策略是浏览器最核心的安全机制。它控制一个网页能从另一个网页读取什么数据，阻止恶意网站读取用户的敏感数据。

**源的定义：**

```
            ↓ 协议    ↓ 域名       ↓ 端口
URL: https://example.com:443/path?query#fragment

源 = 协议 + 域名 + 端口
```

| URL | 源 | 是否同源 |
|-----|----|----------|
| `https://example.com/page1` | `https://example.com` | ✅ 同源 |
| `https://example.com/page2` | `https://example.com` | ✅ 路径不同不影响 |
| `http://example.com/page1` | `http://example.com` | ❌ 协议不同 |
| `https://api.example.com` | `https://api.example.com` | ❌ 域名不同 |
| `https://example.com:8080` | `https://example.com:8080` | ❌ 端口不同 |

### 1.2 SOP 控制什么

| 操作 | SOP 规则 | 原因 |
|------|---------|------|
| **跨源读取 DOM** (`iframe.contentDocument`) | 🚫 拒绝 | 防止窃取密码/CSRF Token 等 |
| **跨源读取 Cookie** (`document.cookie`) | 🚫 拒绝 | Cookie 有独立的同源规则 |
| **跨源读取 localStorage** | 🚫 拒绝 | 存储隔离 |
| **跨源发送 XMLHttpRequest/fetch** | ⚠️ 允许发但不允许读 | 可以发送（会带 Cookie），但无法读取响应 |
| **嵌入资源** (`<img>`, `<script>`, `<link>`) | ✅ 允许 | 互联网的基本功能 |
| **跨源导航** (`window.location`) | ✅ 允许 | 正常跳转 |
| **跨源写入** (POST form) | ✅ 允许 | 允许提交表单 |

### 1.3 SOP 不是"加载阻止"，而是"读取阻止"

**这是最常见的误解。** SOP 并不阻止浏览器加载跨源资源，而是阻止 JavaScript 代码读取跨源资源的内容。

```
正确理解：
  浏览器加载了 https://evil.com 的脚本
  → 脚本可以运行（SOP 不阻止执行）
  → 但脚本不能用 fetch() 读取 https://bank.com 的响应
  → 因为响应来自不同源，SOP 阻止读取

常见误区：
  "SOP 会阻止加载跨源的图片/脚本/CSS" 
  ✅ 不会，只有 DOM 读取和 AJAX 响应读取被阻止
```

### 1.4 SOP 的实现差异

USENIX Security 2017 的研究发现，在 544 个测试用例中，约 23% 的浏览器之间存在 SOP 行为差异（IE/Edge 最多）。由于没有统一的 SOP 规范（只有 RFC 6454 定义了"Web Origin"，但没有完整的 SOP 规范），不同浏览器的实现存在边缘情况差异。

**边缘案例：**
- `data:` URI 的源：所有浏览器认为它是"空的唯一源"（null origin）
- `blob:` URI 的源：与创建它的文档相同
- `sandbox` iframe 的源：也是 "null"
- `file://` 协议的源：不同浏览器实现差异极大

---

## 二、SOP 绕过机制

### 2.1 CORS（Cross-Origin Resource Sharing）

不是"绕过 SOP"，而是"服务器授权浏览器放松 SOP"。

CORS 的工作模式是 **"权限声明"**（Permission-Based Authorization）：

```
浏览器：嘿服务器，我想跨源读取你的资源
       我的 Origin 是 https://evil.com

服务器：可以，你的 Origin 我允许（或不）
       Access-Control-Allow-Origin: https://evil.com
```

**完整 CORS 流程图（非简单请求）：**

```
浏览器                 服务器
  │                     │
  │  OPTIONS /api       │  ← 预检请求（Preflight）
  │  Origin: myapp.com  │
  │────────────────────→│
  │                     │
  │  200 OK             │
  │  Allow-Origin: *    │  ← 服务器声明许可
  │←────────────────────│
  │                     │
  │  GET /api           │  ← 正式请求
  │  Origin: myapp.com  │
  │  Authorization: ... │
  │────────────────────→│
  │                     │
  │  200 OK             │
  │  Data: {...}        │  ← 浏览器检查 Allow-Origin
  │←────────────────────│     匹配才把数据交给 JS
```

**CORS 头字段：**

| 响应头 | 含义 | 典型错误 |
|--------|------|----------|
| `Access-Control-Allow-Origin` | 允许哪些源 | 误设为 `*` 或动态反射未验证 |
| `Access-Control-Allow-Credentials` | 是否允许带 Cookie | 和 `*` 同时使用违反规范 |
| `Access-Control-Allow-Methods` | 允许的 HTTP 方法 | 允许了不应开放的方法 |
| `Access-Control-Allow-Headers` | 允许的自定义头 | 未做严格的允许列表 |
| `Access-Control-Max-Age` | 预检缓存时长 | 设置太久，策略更新无法立即生效 |
| `Access-Control-Expose-Headers` | 允许读取的响应头 | 暴露了敏感头 |

### 2.2 document.domain（已废弃）

`document.domain = "example.com"` 可以让子域名互相读取对方的 DOM。

```
https://payments.example.com 设置 document.domain = "example.com"
https://user-pages.example.com 设置 document.domain = "example.com"
→ 两者可以互相读取对方的 DOM
```

**为什么危险且已废弃：**
- 一旦设置，端口被设为 null（造成更奇怪的 SOP 行为）
- 所有子域名都可以互相访问，不是精确控制
- localStorage、IndexedDB 等 API 不会受 document.domain 影响
- 已被所有浏览器标记为废弃，不建议使用

### 2.3 postMessage API

```javascript
// 发送
targetWindow.postMessage("hello", "https://example.com");

// 接收
window.addEventListener("message", function(event) {
    // ⚠️ 必须验证 event.origin
    if (event.origin !== "https://example.com") return;
    
    // event.data 是消息内容
    // event.source 是发送窗口的引用
});
```

**安全关键：** postMessage 本身是安全的，但接收端没有验证 event.origin 会导致安全漏洞（典型：XSS 或数据泄露）。

---

## 三、XSS（Cross-Site Scripting）— 底层原理

### 3.1 根本原因

XSS 的根本原因是：**浏览器将不可信数据作为代码执行了。**

```
数据流：
用户输入 " <script>alert(1)</script> "
  → 服务器存储
  → 返回给其他用户
  → 浏览器渲染为 HTML
  → 浏览器将 ` <script>...` 解释为 JavaScript
  → 代码执行
```

**三种类型：**

| 类型 | 触发时机 | 数据流 | 经典场景 |
|------|---------|--------|----------|
| **反射型** | 请求时立即触发 | URL → 服务器 → 响应 → 浏览器 | 搜索页面 |
| **存储型** | 每次加载页面触发 | 用户 → 数据库 → 其他用户 → 浏览器 | 评论区 |
| **DOM 型** | 客户端 JS 处理 | URL → JavaScript → DOM | 前端路由 |

**底层原因：HTML 是一种"自描述"的标记语言，数据和标记混合在一起。** 当用户输入的数据中包含标记字符（`<` `>` `"` `'` `&`）时，如果不做转义，浏览器会把这些字符解释为代码。

```html
<!-- 安全的输出：用户输入被正确转义 -->
<div>用户说: &lt;script&gt;alert(1)&lt;/script&gt;</div>

<!-- 不安全的输出：直接拼接 -->
<div>用户说: <script>alert(1)</script></div>
<!-- ↑ 浏览器看到 <script> 标记，开始执行 JavaScript -->
```

### 3.2 XSS 的注入上下文

XSS 不只是 `<script>` 标签的问题。根据注入位置不同，攻击方式完全不同：

| 注入位置 | 绕过方式 | 示例 |
|----------|---------|------|
| **HTML 元素内部** | 使用 `<` `>` 闭合标签 | `"><img src=x onerror=alert(1)>` |
| **HTML 属性内** | 闭合引号+添加事件 | `" onfocus="alert(1)` |
| **`<script>` 标签内** | 闭合字符串 | `'; alert(1);//` |
| **CSS 内** | CSS 表达式、@import | `background:url(javascript:alert(1))` |
| **URL 内** | `javascript:` 伪协议 | `javascript:alert(1)` |
| **Angular/Vue 模板** | 模板表达式注入 | `{{constructor.constructor('alert(1)')()}}` |

### 3.3 XSS 的破坏力来源

为什么 XSS 这么危险？因为 **JavaScript 在受害者的浏览器上下文中有完全访问权限**：

| 能做的事 | 底层原因 | 影响 |
|----------|----------|------|
| 读取 Cookie | `document.cookie` 同源可访问 | 会话劫持 |
| 读取 localStorage | 同源存储可访问 | 凭据/Token 窃取 |
| 修改页面内容 | DOM 完全可写 | 钓鱼/恶意操作 |
| 发送任意请求 | fetch/XMLHttpRequest 可发 | CSRF 操作 |
| 读取屏幕内容 | DOM 可访问所有页面元素 | 信息窃取 |
| 访问 iframe | 同源 iframe 可互相访问 | 跨页面攻击 |

---

## 四、Content Security Policy（CSP）— XSS 的沙箱

### 4.1 CSP 的本质

CSP 是一个 HTTP 响应头，告诉浏览器"这个页面可以加载哪些来源的资源"。它是**浏览器执行的白名单策略**，即使 HTML 被注入了 `<script>alert(1)</script>`，如果 CSP 不允许内联脚本，浏览器也不会执行。

```http
Content-Security-Policy: script-src 'self'; object-src 'none'
```

上面这个策略说：脚本只能从同源加载，禁止 `<object>` 标签。

### 4.2 CSP 指令体系

| 指令 | 控制什么 | 关键安全点 |
|------|----------|-----------|
| `default-src` | 所有未指定资源的默认策略 | 作为兜底 |
| `script-src` | JavaScript 来源 | 最关键的指令 |
| `style-src` | CSS 来源 | 控制 CSS 注入 |
| `img-src` | 图片来源 | 数据外传的通道 |
| `connect-src` | fetch/XMLHttpRequest/WebSocket | 限制数据外传 |
| `frame-src` | iframe 来源 | 点击劫持防护 |
| `base-uri` | `<base>` 标签来源 | 防止 base tag 劫持 |
| `object-src` | `<object>`/`<embed>`/`<applet>` | 插件攻击面 |
| `form-action` | `<form>` 提交目标 | CSRF 辅助防御 |
| `frame-ancestors` | 谁可以嵌入当前页面 | 点击劫持防御 |
| `report-uri` / `report-to` | 违规上报地址 | 监控攻击尝试 |

### 4.3 白名单 CSP 的漏洞

传统 CSP 最常用的方式是白名单域名：

```http
script-src: https://cdn.example.com https://www.google-analytics.com
```

**这种方式的绕过方式很多：**

| 绕过技术 | 利用方式 |
|----------|----------|
| **JSONP 端点** | 白名单域名中如果有 JSONP 接口，攻击者可以用它执行任意 JS |
| **CDN 上的可写目录** | 攻击者可以在允许的 CDN 上上传恶意 JS |
| **Angular 回调** | 某些库的 callback 参数可以注入代码 |
| **跳转器** | 白名单域名可能有一个跳转到任意 URL 的接口 |
| **子域名接管** | 白名单域名中如果有未注册的子域名，攻击者可以注册它 |

### 4.4 严格 CSP（推荐方案）

**nonce 基础（推荐）：**

```http
Content-Security-Policy:
  script-src 'nonce-{每次请求随机生成}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```

```html
<script nonce="随机值">
  // 只有带这个 nonce 的脚本才会执行
</script>
```

**工作原理：**
1. 服务器每次响应时生成一个随机 nonce
2. 在 HTML 的 `<script>` 标签中嵌入这个 nonce
3. 浏览器检查 `<script>` 的 nonce 是否和响应头匹配
4. 注入了恶意脚本 `<script>alert(1)</script>` 没有 nonce → 不执行

**hash 基础：**

```http
Content-Security-Policy:
  script-src 'sha256-{脚本内容的哈希}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
```

**工作原理：** 浏览器计算每个内联脚本的 SHA256 哈希，和策略中的哈希对比。匹配才执行。

### 4.5 strict-dynamic 机制

`strict-dynamic` 是 CSP Level 3 的关键特性。

```
没有 strict-dynamic:
  信任的脚本 A (有 nonce) 创建了 <script src="...">
  → 动态创建的脚本没有 nonce → 被 CSP 阻止

有 strict-dynamic:
  信任的脚本 A (有 nonce) 创建了 <script src="...">
  → 信任从 A 传递到动态脚本 → 允许执行
```

**这解决了第三方脚本加载子资源的实际问题。** 但代价是：如果一个被信任的脚本存在漏洞（XSS），攻击者可以通过它创建任意恶意脚本。

### 4.6 2025-2026 年 XSS 攻防新态势

| 新攻击面 | 说明 |
|----------|------|
| **AI 生成的多态 Payload** | 每分钟数千种变体，基于签名的检测失效 |
| **mXSS (Mutation XSS)** | 利用浏览器的 HTML 解析器/清理器差异绕过 Sanitizer API |
| **CSP Nonce 泄露** | 通过 CSS 属性选择器、浏览器缓存等方式泄露 nonce |
| **Trusted Types + Sanitizer API** | 2026 年推荐标准，彻底消除 DOM XSS |
| **AI Agent 成为 XSS 载体** | 浏览器 AI 助手可能被用来执行恶意操作 |

---

## 五、CSRF（Cross-Site Request Forgery）

### 5.1 原理

```
用户已登录 bank.com（浏览器有 Cookie）

用户访问 evil.com
  → evil.com 的页面中有一个隐藏表单：
    <form action="https://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="10000">
    <input type="submit">
    </form>
  → 由于 SOP 不阻止表单提交，浏览器发送了 POST
  → 浏览器自动带上 bank.com 的 Cookie
  → 服务器收到请求（含合法的 Cookie）→ 执行转账
```

**CSRF 的本质：** 浏览器在发送跨源请求时会自动附带 Cookie。服务器无法区分"用户主动操作"和"被恶意页面诱导的操作"。

### 5.2 CSRF 防御

| 防御方法 | 原理 | 效果 |
|----------|------|------|
| **CSRF Token** | 表单中嵌入服务器生成的随机 token，服务器验证 | ✅ 最可靠 |
| **SameSite Cookie** | `SameSite=Strict` 阻止跨站发送 Cookie | ✅ 浏览器原生防御 |
| **自定义请求头** | 要求 AJAX 请求带 `X-Requested-With` | ⚠️ 简单请求跳过 |
| **二次确认** | 敏感操作要求再次输入密码 | ✅ 用户体验差 |
| **Referer/Origin 验证** | 检查请求的 Referer/Origin 头 | ⚠️ 可能被去掉 |

**SameSite Cookie 是防御 CSRF 的重大进展：**
- `Strict`：完全不在跨站请求中发送 Cookie → 最强的 CSRF 防护
- `Lax`：GET 请求（链接、预加载）发送 → 默认值，平衡安全和可用性
- `None`：总是发送 → 必须配合 Secure 属性

---

## 六、点击劫持（Clickjacking）

### 6.1 原理

攻击者将目标网站通过透明的 iframe 嵌入自己的页面，用户看似在点击攻击者的按钮，实际点击了 iframe 中的目标网站元素。

```
┌─────────────────────────────┐
│  攻击者的页面                │
│                             │
│  ┌─────────────────────┐    │
│  │ 透明 iframe          │    │
│  │ bank.com/transfer    │    │
│  │                     │    │
│  │  "确认转账10000元"  │    │
│  └─────────────────────┘    │
│                             │
│  把这里↑                    │
│  "点我领奖金"← 用户看到的   │
└─────────────────────────────┘
```

### 6.2 防御

```http
X-Frame-Options: DENY          // 禁止所有 iframe 嵌入
X-Frame-Options: SAMEORIGIN    // 只允许同源嵌入

// 更细致的新标准
Content-Security-Policy: frame-ancestors 'self' https://example.com
```

---

## 七、从 Web 安全模型推导攻击方向

### 7.1 各安全机制的弱点总结

| 机制 | 设计目标 | 已知弱点 |
|------|---------|----------|
| **SOP** | 隔离不同源的数据 | 边缘案例多、浏览器实现差异、JSONP 半绕过 |
| **CORS** | 松散的 SOP 控制 | `Access-Control-Allow-Origin: *`、反射 Origin |
| **CSP** | XSS 的沙箱 | 白名单 CSP 易绕过、nonce 可能泄露 |
| **Cookie 属性** | 保护会话 | Secure 以外属性依赖浏览器正确实现 |
| **HttpOnly** | 防止 JS 读取 Cookie | 依然可以被 XHR/SSRF 窃取 |
| **SameOrigin** | CSRF 防御 | SameSite=None + 跨站导航可以绕过 |
| **X-Frame-Options** | 点击劫持防御 | 单页面应用的 iframe 困境 |
| **HSTS** | 强制 HTTPS | 首次连接前的空窗期（但 preload 解决了一部分） |

### 7.2 Web 安全在渗透测试中的检查清单

```
1. 检查所有反映射、存储型、DOM 型 XSS
   → 重点：注入上下文（HTML 内/属性内/JS 内/CSS 内）

2. 检查 CSRF 防护
   → 查看表单是否带 CSRF Token
   → 查看 SameSite Cookie 设置
   → 检查自定义头验证

3. 检查 CORS 配置
   → 用不同 Origin 测试：evil.com, null, 带端口
   → 检查是否动态反射 Origin

4. 检查 CSP 配置
   → 允许 unsafe-inline 吗？
   → 白名单域名中是否有 JSONP 端点？
   → nonce 是静态还是在请求间重复？

5. 检查 Cookie 属性
   → Secure? HttpOnly? SameSite? Domain 范围?

6. 检查点击劫持防护
   → X-Frame-Options? frame-ancestors?

7. 检查 HSTS
   → max-age 足够长？includeSubDomains？preload？
```

---

**下一层：** 理解浏览器安全模型后，下一步是"开发安全"——各语言的内存安全问题、代码审计方法论、供应链安全。
