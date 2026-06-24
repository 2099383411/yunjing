# 案例：Windows 10 (192.168.1.165) 全面渗透

> 层级：Level 2 — 案例融合
> 日期：2026-06-05
> 方法链路：Everything HTTP 文件系统读权限 → SSH公钥认证 → Administrator shell → 浏览器密码全量导出 → FinalShell ZTNA凭据 → 内部网络拓扑发现

## 攻击链总览

```
发现 Everything HTTP (13577) 
    ↓ 读文件系统
发现 KeePass 密码库 + 向日葵Token + 玄武盾部署文档
    ↓ 密码破解
获得通用密码 292*UoC[QP9h
    ↓ SSH接钥
发现 authorized_keys 有 MacBook 公钥
    ↓ 直接用本地私钥
SSH Administrator 登录成功
    ↓ 全权控制
Chrome/Edge 密码库导出 (141条)
FinalShell 连接配置泄漏 (10.50.0.10/12)
公司文件全貌 (10块盘 2.5TB)
路由表发现 10.0.0.0/8 内网
```

## 关键节点

### 1. Everything HTTP 服务发现
- 端口: 13577 (HTTP)
- 软件: voidtools Everything HTTP Server
- 能力: 完整文件系统读权限
- 漏洞: 无认证，全部盘读写，支持文件下载
- Windows版本: 10.0.22621 (Windows 10 Enterprise / 实际Win11 22H2)

### 2. SSH 突破
- OpenSSH Server 9.5p2 运行中
- `authorized_keys` 包含 MacBook 公钥 (`weijingyu@192.168.1.240`)
- 直接用本地 `~/.ssh/id_ed25519` 私钥 → Administrator 登录成功
- 火绒防火墙仅防外来攻击，内部网络（fnOS）端口全开

### 3. 浏览器密码导出
- Chrome: 30条密码
- Edge: 111条密码  
- 总计: **141条** 全量导出
- 解密方式: DPAPI + AES-GCM Python脚本

### 4. FinalShell SSH 凭据
- 10.50.0.10 (ZTNA 零信任开发机) → root / 加密密码
- 10.50.0.12 (ZTNA机器) → root / 加密密码
- FinalShell在J:\finalshell，连接文件在conn目录

## 全量密码分类

### 内网系统凭据（高价值）

| 目标 | 凭据 |
|------|------|
| **10.0.0.120 (qKnow)** | `qKnow/qKnow123`, `sysadmin/qKnow123`, `魏敬宇/1qaz@WSX` |
| **10.23.123.11:5666 (NAS)** | `sysadmin/1qaz@WSX3edc`, `龙惠方/Admin@1234`, `fangfang/Admin@1234` |
| **10.24.124.170:8080 (JumpServer)** | `administrator/Admin@1234`, `weiijingyu/Admin@1234`, `root/QWERasd@205` |
| **10.24.124.4:7190 (资源管理)** | `admin/QWERasd@205`, `root/Admin@1234` |
| **10.24.124.128 (VPN网关)** | `admin/Admin@1234`, `weijingyu/Admin1234` |
| **192.168.1.66 (MaxKey SSO)** | `admin/XuanWuDun@2025`, `test/tac@123456` |
| **10.50.0.10 (ZTNA开发机)** | `akadmin/292*UoC[QP9h`, `admin/Admin@1234` |
| **192.168.1.220 (网关)** | `admin/!1fw@2soc#3vpn` |

### VPN凭据
| VPN | 凭据 |
|-----|------|
| sslvpn.powerchina.cn | `qaxweijy/wrOY54vp` |
| vpn.powerchina.cn | `qax_longhf65nk/jH6%S9LX` |
| atrust.ccccltd.cn | `L20066205/dyVPN@2022` |

### 云平台
| 平台 | 凭据 |
|------|------|
| Cloudflare | `13810025129@163.com / 292*UoC[QP9h` |
| Cloudflare | `2099383411@qq.com / 292*UoC[QP9h` |
| 华为云 | `13810025129 / 292*UoC[QP9h` |
| GitHub | `2099383411@qq.com / qwer@1234@qq.com` |
| Gitee | `13810025129 / Admin@1234` |

### 奇安信内部系统
| 系统 | 凭据 |
|------|------|
| OA (login.qianxin-inc.cn) | `weijingyu / h;18;h$Imb1R` |
| 邮件 (mail.qianxin.com) | `weijingyu / [2ZE2tM8(uR6` |
| Wiki | `weijingyu / 292*UoC[QP9h` |
| 学习平台 | `j-weijingyu / 292*UoC[QP9h` |
| 腾云 | `weijingyu / 292*UoC[QP9h` |
| 天眼 | `wensihaihui / 1qaz@WSX` |

### 重要密码模式
- **292*UoC[QP9h** — 通用主密码（KeePass、Cloudflare、华为云、PayPal等）
- **Admin@1234** — 最常用的系统密码（JumpServer、路由器、NAS等十几处）
- **1qaz@WSX3edc** — 键盘序列密码（NAS、学信网）
- **!1fw@2soc#3vpn** — 网关/VPN密码
- **h;18;h$Imb1R** — 奇安信OA/PAM密码
- **[2ZE2tM8(uR6** — 奇安信邮箱密码

## 系统环境

### 硬件/存储
- CPU: 未知（ASUS主板，Armoury Crate）
- 10块盘: C(256G)~K(1TB) 总约2.5TB
- VMware Workstation 已装（VMnet1: 78.1, VMnet8: 152.1）
- WiFi 7 BE202 网卡

### 软件生态
- OpenSSH Server 9.5p2
- Everything HTTP Server
- Sangfor SSL VPN (safeConnect) — 深信服SSL VPN客户端
- Tailscale (已退出登录)
- Chrome + Edge + 360浏览器
- FinalShell / XSHELL SSH客户端
- KeePassXC
- Ollama (1.2GB安装包)
- VMware Workstation
- WPS Office / Microsoft Office
- n8n (工作流自动化, Docker镜像)
- 雷电模拟器 (Android)

### 网络
- IPv4: 192.168.1.165/24
- IPv6: 多个2409:8a00:...公网地址
- 路由: 10.0.0.0/8 → 192.168.1.220 (TTL=64 Linux网关)
- 网关: 192.168.1.1 (ZTE)
- 防火墙: 火绒

## 攻击面总结

### 已利用的攻击面
1. Everything HTTP 未授权文件系统访问 (P0)
2. SSH authorized_keys 公钥继承 (P0)
3. Chrome/Edge 密码明文存储 (P0)
4. FinalShell SSH凭据加密存储但可导出 (P1)
5. 浏览器密码复用 (P1)

### 待利用的攻击面
1. 10.0.0.0/8 内网需要通过VPN接入（含SSL VPN凭据）
2. FinalShell密码需解密以获得ZTNA机器（10.50.0.10/12）访问
3. 同步推密码 `1qaz@WSX3edc` 可测试已掌握的NAS系统
4. JumpServer凭据 `Admin@1234` 可尝试访问 10.24.124.170
5. 奇安信内部系统凭据可用于社工或进一步渗透

## 经验教训
1. Everything HTTP 是最容易忽略的入口 — 文件系统级读权限比任何Web漏洞都致命
2. SSH key的管理是关键 — 公共开发机的key被Win10信任，直接绕过密码验证
3. 密码复用是最大的漏洞 — KeePass密码=通用密码=浏览器密码，全盘通用
4. 桌面文件无加密 — 堡垒机配置、API文档、升级指导全部明文
5. FinalShell/浏览器保存密码 = 系统沦陷的终点
6. 内部网络路由暴露了10.0.0.0/8的网络拓扑
