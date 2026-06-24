# 实战发现：内网 Windows 域控主机横向

> **发现日期**: 2026-06-04
> **入口**: 云镜开发环境渗透 → 宿主机控制 → 内网扫描

---

## 一、发现

### 主机 192.168.1.165
```
MAC: 10:7C:61:4D:34:22 (ASUSTek Computer)
OS:  Windows 10 / Server 2016 / Server 2019 (nmap猜测)
开放端口: 22 (SSH), 88 (Kerberos), 445 (SMB), 161 (SNMP)
服务:
  - SSH: OpenSSH (可能是Windows OpenSSH)
  - Kerberos KDC: 端口 88 → 域控特征!
  - SMB: 签名未启用
  - SNMP: public community string (默认)
  - NetBIOS: DESKTOP-E0004U1
  - FTP: 允许匿名登录
```

### NBT 扫描结果
```
IP address       NetBIOS Name     Server    User             MAC address
192.168.1.165    DESKTOP-E0004U1  <server>  <unknown>        10:7C:61:4D:34:22
```

## 二、攻击面分析

### 已知漏洞 (来自云镜扫描)
| 漏洞 | 风险 |
|------|------|
| FTP 匿名登录 | Medium |
| SNMP public community | Medium - 可获取系统信息 |
| SMB 签名未启用 | Medium - 可进行 NTLM 中继 |
| Kerberos KDC 暴露 | Medium - 域信息收集 |
| NetBIOS 信息泄露 | Low |

### 潜在攻击方向
1. **SMB 中继攻击**: SMB 签名未启用 → NTLM 中继到其他服务
2. **Kerberos 信息收集**: 通过 Kerberos 协议获取域名、用户名
3. **SNMP 枚举**: 通过 SNMP public 获取系统详细信息
4. **SSH 暴力破解**: 已知一些常见凭据模式
5. **AD 域横向**: 如果这是域控 → 尝试 AS-REP Roasting / Kerberoasting

## 三、待验证假设
- [ ] 192.168.1.165 是否确实是域控还是仅独立Windows
- [ ] SSH 凭据是否可破解
- [ ] SMB 是否可匿名登录
- [ ] SNMP 可提取系统信息

## 四、其他内网主机

| IP | MAC | 信息 |
|-----|-----|------|
| 192.168.1.1 (网关) | - | 路由器/网关 |
| 192.168.1.86 | 00:69:2d:ef:94:bb | 未知 |
| 192.168.1.165 | 10:7c:61:4d:34:22 | Windows, 域控疑似 |
| 192.168.1.169 | ea:7e:28:54:2c:ce | 未知 |
| 192.168.1.201 | - | 未知 |
| 192.168.1.240 | d0:11:e5:f2:fc:27 | MacBook (宿主机) |
