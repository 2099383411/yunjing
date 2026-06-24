# 实战案例：Proxmox 宿主机 → 8个VM全发现 → NSG VFW磁盘篡改

> Level 2: 案例融合 / 实战案例
> 日期：2026-06-05
> 来源：开发服务器 → fnOS → 密码复用 → Proxmox SSH

---

## 一、攻击链总览

```
开发服务器(192.168.1.180) 已控
  │
  ├── KeePass破解 → 292*UoC[QP9h
  │
  ├── SSH root@192.168.1.201 (fnOS) → sudo → 双网卡发现
  │
  └── SSH root@192.168.1.220 (Proxmox/homepve)
      │
      └── qm list → 8个VM全部发现
          │
          ├── VM 100 VFW (NSG防火墙)
          │   ├── qm config 100 → 磁盘文件定位
          │   ├── 磁盘挂载 → sgbase.db → 管理员密码哈希篡改
          │   └── SSH/Web登录验证码阻塞
          │
          ├── VM 101 FnOs (完全冗余)
          ├── VM 102 Guesu-QAX
          ├── VM 103 XW-ZTNA (root/292*UoC[QP9h)
          ├── VM 104 moblic
          ├── VM 105 2026ZTNA (root/292*UoC[QP9h)
          ├── VM 106 1panel
          ├── VM 107 aikaifa (开发服务器克隆)
          └── VM 108 shentoucode
```

## 二、关键发现

### 2.1 Proxmox 宿主机

| 属性 | 值 |
|:----|:----|
| **主机名** | homepve |
| **IP** | 192.168.1.220 |
| **SSH** | root/292*UoC[QP9h ✅ 登录成功 |
| **版本** | Proxmox VE |
| **外部网络识别** | 曾被误认为 ASUS 设备（仅 SSH 22 端口开放判断） |

### 2.2 网桥拓扑

```
vmbr0  (192.168.1.x/24)  → 家庭网络 (ge1 接口)
server1 (10.20.0.x/24)  → 内部服务网 (ge2 接口)
untrust (10.50.0.x/24)  → ZTNA零信任网 (ge3 接口)
```

### 2.3 8个VM快照

| VM ID | 名称 | SSH/控制 | 状态 |
|:-----:|:-----|:---------|:----:|
| 100 | VFW | NSG防火墙 (密码哈希已改) | ⚠️ 验证码阻塞 |
| 101 | FnOs | 非主fnOS，未探索 | 待定 |
| 102 | Guesu-QAX | Guest-QAX/2000512 (KeePass) | ❌ 未验证 |
| 103 | XW-ZTNA | root/292*UoC[QP9h (KeePass) | ✅ SSH成功 |
| 104 | moblic | 未知 | 待定 |
| 105 | 2026ZTNA | root/292*UoC[QP9h (KeePass) | ✅ SSH成功 |
| 106 | 1panel | 面板管理工具 | 待定 |
| 107 | aikaifa | 开发服务器克隆 | ✅ 已控 |
| 108 | shentoucode | 渗透测试代码 | 待定 |

## 三、NSG VFW 分析

### 3.1 基本信息

- **版本**: NSG V3.6.6.0 (kernel 6.1.13)
- **接口**: ge1(192.168.1.230/231), ge2(10.20.0.254), ge3(10.50.0.254)
- **管理口**: HTTPS 443 + SSH 22
- **SSL 证书**: Subject=NSG, Issuer=NSGCA

### 3.2 磁盘篡改攻击

```bash
# 宿主机查看VM配置
qm config 100
→ scsi0: local-zfs:vm-100-disk-0,size=32G

# NSG防火墙内部关键文件
# /etc/sg-base/sgbase.db → SQLite密码库
# auth_user表 → password字段 = MD5(密码)

# 篡改方法
# 1. 停止VM
# 2. 挂载VM磁盘到宿主机
# 3. 打开sgbase.db → SELECT * FROM auth_user
# 4. UPDATE admin密码为已知MD5
# 5. 重启VM → 用已知密码登录
```

### 3.3 限制

- **验证码阻塞**: Web登录需要验证码（POST /login_submit 返回 99）
- **SSH密码未知**: 非sqlite存储的密码
- **qm terminal 100**: 需要交互式终端（无法通过单条命令自动化）

### 3.4 防火墙策略泄露

从配置文件中提取的 ACL 规则：
- 192.168.1.0/24 ←→ 10.20.0.0/24: **双向禁止**
- 192.168.1.0/24 ←→ 10.50.0.0/24: **双向禁止**
- 管理口 192.168.1.230: **ALLOW ANY**
- 注释: "禁止proxmox内部机器访问家庭网络"

## 四、提炼攻击模式

### 模式1：VM磁盘离线篡改

```
已控宿主机 → 停止目标VM → 挂载VM磁盘 → 
修改SQLite密码库 → 重启VM → 用已知密码登录
```

- **适用条件**: 目标在虚拟化平台上运行（Proxmox/VMware/Xen）
- **难度**: 低（需要宿主机root权限）
- **不可防御**: 除非加密VM磁盘

### 模式2：设备识别通过SSL证书

```
比nmap/端口猜测更可靠
SSL证书 Subject/Issuer → 快速确认设备类型

NSG:    CN=NSG, Issuer=NSGCA
ASUS:   CN=RT-AX*, Issuer=ASUS
Ubiquiti: CN=UniFi*, Issuer=UI
```

### 模式3：密码复用链突破

```
KeePass(1处) → 8条条目(7条同密码) → 
Proxmox SSH → 所有VM全控制

关键: 同一密码 292*UoC[QP9h 出现在
KeePass(7/8) + 浏览器(大量) + Authentik + SSH
```

## 五、待完成

- [ ] 破解NSG验证码机制（逆向 JS/验证码生成算法）
- [ ] 启动已关机的VM（如10.50.0.10 ZTNA）并控制
- [ ] 渗透VM 104 (moblic) 和 106 (1panel)
- [ ] 从 ZTNA VM (10.50.0.x) 访问内部服务

## 六、知识库关联

- **关联知识库**: `network/05-nsg-firewall-security.md` — NSG防火墙详解
- **关联知识库**: `network/04-ztna-zero-trust-security.md` — ZTNA攻击面
- **关联知识库**: `network/03-docker-container-security.md` — Docke容器安全
- **关联案例**: `case-fnos-double-nic-pivot.md` — 双网卡跳板
- **关联知识库**: `crypto/06-password-storage-security.md` — KeePass/KDBX
