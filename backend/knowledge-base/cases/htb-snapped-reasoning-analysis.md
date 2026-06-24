# 案例参考：HTB Snapped — 完整攻击推理链

> 来源：0xdf hacks stuff
> 用途：学习渗透测试专家的推理思维，**非复制模板**
> 分析重点：每一步"为什么这么想"而非"做了什么"

---

## 攻击链全景

```
nmap 扫描
  ↓ 发现 22(SSH) + 80(HTTP) 开放
Web 访问主站
  ↓ 302 跳转到 snapped.htb → 虚拟主机 → 可能有子域名
子域名爆破 (ffuf)
  ↓ 发现 admin.snapped.htb
Nginx UI 管理面板 v2.3.2
  ↓ JS bundle 分析 → 发现 API 端点
API 端点分析
  ↓ /api/backup 无需认证
CVE-2026-27944 利用
  ↓ 响应头 X-Backup-Security 泄漏密钥
openssl 解密备份
  ↓ 拿到 SQLite 数据库 + bcrypt 哈希
hashcat 爆破
  ↓ jonathan:linkinpark (5秒)
SSH 登录 → 用户 shell
  ↓ user.txt
权限枚举
  ↓ snapd v2.63.1 < 修复版本 v2.73
CVE-2026-3888 竞争条件
  ↓ systemd-tmpfiles + SetUID snap-confine
Root Shell
  ↓ root.txt ✅
```

---

## 每一步的推理逻辑（这才是精华）

### Step 1: nmap 扫描
**动作：** `nmap -sC -sV -p- 10.10.11.xx`
**发现：** 22(SSH) + 80(HTTP) 
**推理：** 渗透测试第一步永远是发现攻击面——目标机器上哪些端口是开放的、运行什么服务。`-sC` 跑默认脚本，`-sV` 探测服务版本，`-p-` 扫全端口防遗漏。

### Step 2: Web 访问
**动作：** 访问 http://10.10.11.xx
**发现：** 302 跳转到 snapped.htb
**推理：** 302 跳转通常是虚拟主机配置，需要加 hosts。同时查看 Nginx 版本。

### Step 3: 子域名爆破
**动作：** `ffuf -w wordlist -H "Host: FUZZ.snapped.htb" -u http://snapped.htb`
**发现：** admin.snapped.htb
**推理：** 主站静态页面无交互→通常有管理后台→用字典猜子域名。

### Step 4: 发现 Nginx UI
**动作：** 访问 admin.snapped.htb
**发现：** Nginx UI v2.3.2
**推理：** 版本号信息重要→可搜已知漏洞。

### Step 5: JS 源码分析
**动作：** 查看 JS bundle
**发现：** API 端点 `/api/backup`
**推理：** 前端代码常暴露未公开 API，登录页面特别容易暴露通信模式。

### Step 6: CVE 搜索
**动作：** 搜 "Nginx UI v2.3.2 exploit"
**发现：** CVE-2026-27944
**推理：** 具体版本号→先搜已知漏洞（效率最高）。

### Step 7: 解密备份
**动作：** 多次请求提取密钥→openssl 解密
**发现：** SQLite + bcrypt 哈希
**推理：** 备份"安全密钥"在响应头中暴露→设计缺陷（密钥不应离开服务器）。

### Step 8: 密码爆破
**动作：** hashcat 爆破 bcrypt
**发现：** linkinpark
**推理：** bcrypt 需要 GPU 爆破。没破解则找其他路径。

### Step 9: SSH 登录
**动作：** SSH 登录
**发现：** user flag
**推理：** SSH 开放+密码已知→尝试登录。

### Step 10: 权限枚举
**动作：** 标准提权枚举
**发现：** snapd v2.63.1
**推理：** sudo→SUID→服务→内核→软件版本，一条链查下来。

### Step 11-12: CVE 利用
**动作：** 竞争条件利用
**推理：** 系统清理→攻击者替换文件→SetUID 程序以 root 加载恶意库。

---

## 推理链中的底层知识依赖

| 步骤 | 依赖的底层知识 |
|------|---------------|
| 子域名爆破 | DNS 解析机制、虚拟主机原理 |
| JS 源码分析 | Web 前后端通信架构 |
| CVE 匹配 | 版本号与漏洞对应关系 |
| 备份解密 | 加密设计原则（密钥不应暴露给客户端） |
| 密码爆破 | bcrypt 算法特性（慢哈希、GPU） |
| 竞争条件 | 文件操作非原子性、systemd 定时器 |
| SUID 提权 | 进程权限模型、动态链接器加载机制 |

**关键洞察：** 多数步骤是"经验+信息收集"。真正体现"从原理推导"的部分：
1. **竞争条件** — 理解文件系统操作的时序非原子性
2. **密钥泄露** — 理解"密钥不应离开服务器"的设计原则
3. **动态链接器替换** — 理解 SUID + 动态库加载机制

---

**对我们的启示：** 底层原理 + 案例经验，两条路一起走。
