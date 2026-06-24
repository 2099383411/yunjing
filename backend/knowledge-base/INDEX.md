# 云镜知识库（第二大脑）

> 目标：从底层原理理解系统脆弱性，而非记忆已知漏洞。
> 路线：硬件 → 操作系统 → 网络 → Web → 开发 → 密码学 → 架构

---

## 📂 知识库结构

### Level 0：基础原理（当前层级）
| 目录 | 文件 | 内容 | 状态 |
|------|------|------|------|
| `os-kernel/` | `01-memory-management-security.md` | 虚拟内存、MMU、页表、syscall、KPTI、SMAP/SMEP | ✅ 完成 |
| `os-kernel/` | `02-process-permission-security.md` | Linux权限模型三层架构、DAC、Capabilities、LSM、SUID | ✅ 完成 |
| `network/` | `01-network-stack-security.md` | Linux网络栈、sk_buff、内核参数安全、容器隔离 | ✅ 完成 |
| `network/` | `02-http-protocol-security.md` | HTTP/1.1协议规范、消息体长度、请求走私、Cookie安全、CORS | ✅ 完成 |
| `web-security/` | `01-browser-security-model.md` | SOP、CORS、CSP、XSS原理、CSRF、点击劫持 | ✅ 完成 |
| `web-security/` | `02-xss-and-injection-security.md` | XSS三类、注入攻击统一模型、CSP绕过、SSTI、点击劫持 | ✅ 完成 |
| `web-security/` | `03-cors-csrf-auth-security.md` | CORS配置错误、Cookie/JWT认证、OAuth 2.0攻击面、SSO安全 | ✅ 完成 |
| `dev-security/` | `01-c-language-memory-safety.md` | C内存布局、栈溢出、堆（UAF/DF/溢出）、ROP、7层防御机制、攻击面（14KB） | ✅ 完成 |
| `dev-security/` | `02-rust-memory-safety.md` | 所有权/借用/生命周期、Safe vs Unsafe、消除的漏洞类型、局限性（12KB） | ✅ 完成 |
| `dev-security/` | `03-common-vulnerability-patterns.md` | 注入统一模型、反序列化、SSRF、路径遍历、代码审计方法论、信任模型（14KB） | ✅ 完成 |
| `dev-security/` | `04-supply-chain-security.md` | 依赖混淆、typosquatting、SolarWinds/XZ案例、CI/CD安全、SBOM、SLSA（9KB） | ✅ 完成 |
| `crypto/` | `05-cryptography-security.md` | 对称/非对称加密、AEAD、哈希/长度扩展攻击、签名、证书PKI、填充预言/时序侧信道/随机数攻击、后量子密码（15KB） | ✅ 完成 |
| `crypto/` | `06-password-storage-security.md` | KeePass KDBX格式、KDF推导、离线破解、剪贴板监控、内存转储、各SSH客户端密码存储（8KB） | ✅ 完成 (2026-06-05) |
| `network/` | `03-docker-container-security.md` | Docker隔离机制、Capabilities、6大逃逸技术、容器内网扁平化、安全配置错误（10KB） | ✅ 完成 (2026-06-05) |
| `network/` | `04-ztna-zero-trust-security.md` | ZTNA架构、Headscale/Authentik攻击、FRP隧道、预认证Key泄露、节点注入（7KB） | ✅ 完成 (2026-06-05) |
| `network/` | `05-nsg-firewall-security.md` | NSG防火墙识别（SSL证书CN=NSG）、Web管理攻击、验证码绕过、磁盘离线篡改、策略解读（7KB） | ✅ 完成 (2026-06-05) |
| `web-security/` | `04-browser-password-security.md` | Chrome/Edge密码存储机制、DPAPI+AES-GCM解密、远程提取工具（SharpChrome/dploot）、攻击面（8KB） | ✅ 完成 (2026-06-05) |
| `web-security/` | `05-everything-http-security.md` | Everything HTTP无认证文件系统暴露、搜索策略、利用链、实战案例映射（6KB） | ✅ 完成 (2026-06-05) |
| `protocols/` | `07-financial-security-hardware.md` | 税控UKey日志泄露、银行UKey攻击面、PIN绕过、数字签名滥用（3KB） | ✅ 完成 (2026-06-05) |
| `protocols/` | `03-tls-protocol-security.md` | TLS 1.2/1.3 握手、记录层、证书链、攻击面（16KB） | ✅ 完成 |
| `protocols/` | `04-dns-protocol-security.md` | DNS 层级、消息格式、缓存污染、Kaminsky、DNSSEC、攻击面（7KB） | ✅ 完成 |
| `protocols/` | `05-ssh-protocol-security.md` | SSH 握手、公钥认证、端口转发、暴力破解、Agent 转发、攻击面（7KB） | ✅ 完成 |
| `protocols/` | `06-smb-protocol-security.md` | SMB 版本、握手、NTLM认证、IPC$管道、EternalBlue/Relay/PtH、攻击面（16KB） | ✅ 完成 |

### Level 1：攻击面分析 ✅ 完成
| `level1-attack-surface-derivation.md` | 全领域攻击面推导：从 OS 内核到密码学，每层的信任假设、可推导攻击方向、交叉攻击面（14KB） | ✅ 完成 |
| `level1-kernel-attack-surface.md` | OS内核攻击面深挖：虚拟内存、权限模型、进程隔离、capabilities、命名空间的信任假设与攻击向量 | ✅ 完成 |
| `level1-network-attack-surface.md` | 网络协议攻击面深挖：TCP/IP序列号、IP源地址、DNS缓存、HTTP请求走私/认证、TLS降级/证书、SSH/SMB的信任假设与攻击向量 | ✅ 完成 |
| `level1-web-attack-surface.md` | Web攻击面深挖：SOP/DNS rebinding、CORS误配、注入攻击统一模型、JWT/OAuth/Session、IDOR/SSRF的信任假设与推理链 | ✅ 完成 |
| `level1-crypto-attack-surface.md` | 密码学攻击面深挖：密钥管理、对称加密nonce重用/AEAD、非对称密钥大小/PFS、哈希碰撞/长度扩展、证书PKI、随机数的信任假设与攻击向量 | ✅ 完成 |
| `level1-dev-attack-surface.md` | 开发安全攻击面深挖：C/C++内存安全（栈/堆/UAF/ROP）、Rust不安全的限、注入统一模式、供应链攻击（XZ模式）、构建信任的信任假设与推理链 | ✅ 完成 |

### Level 2：案例融合 ✅ 完成
| `level2-case-fusion.md` | 12 大案例推理链标注：EternalBlue/CVE-27666/DirtyPipe（内核×3）、Log4Shell/ProxyShell/Heartbleed/Shellshock（Web/代码×4）、Escape/PetitPotam/ZeroLogon/PrintNightmare（AD/Windows×4）、XZ后门（供应链×1）。每步标注底层原理，提炼6种通用攻击模式（~40KB） | ✅ 完成 |
| `case-yunjing-dev-env-full-penetration.md` | 实战案例：云镜开发环境全面渗透 — 从 DVWA 入口到 Redis 无密码到后端 API JWT 到系统完全控制。提炼4种攻击模式（容器内网Redis跳板/Swagger UI信息泄露/通用凭据复用/Docker内部网络扁平化），暴露点交叉利用统计，防御建议（~8KB） | ✅ 完成 (2026-06-04) |
| `case-container-escape-docker-socket.md` | 实战案例：Docker Socket 容器逃逸 — 从 DVWA → Redis → Worker容器 → docker.sock → 宿主机全控。提炼3种新攻击模式（Docker Socket批量挂载/Celery+Redis→Worker控制/docker-compose.yml泄露），累计7种攻击模式（~6KB） | ✅ 完成 (2026-06-04) |
| `case-windows-domain-discovery.md` | 实战发现：内网 Windows 域控主机 — 192.168.1.165 发现 Kerberos 88端口 + SMB + SNMP public + NetBIOS 信息，疑似域控/Windows Server。待验证攻击方向（~2KB） | ✅ 完成 (2026-06-04) |
| `case-win10-full-breach.md` | Windows 10 全面渗透 — Everything HTTP → SSH Key → Administrator Shell → 141条浏览器密码 → KeePass破解 → FinalShell ZTNA凭据 → 10.0.0.0/8路由发现。6种攻击模式提炼（~12KB） | ✅ 完成 (2026-06-05) |
| `case-win10-password-analysis.md` | Win10 141条密码分类分析与攻击面推演（~4KB） | 🟡 编写中 |
| `case-proxmox-nsg-breach.md` | Proxmox宿主机→8个VM全发现→NSG VFW磁盘篡改→密码哈希修改（~6KB） | 🟡 编写中 |
| `case-fnos-double-nic-pivot.md` | fnOS双网卡跳板→10.20.0.x内网→SSL VPN→10.0.0.0/8发现（~4KB） | 🟡 编写中 |

### 学习资源
| `github-case-study-resources.md` | GitHub 渗透测试案例仓库精选指南 — 含 htb-writeups/Offensive-Resources/medium-writeups/RedAmon/LLM4Pentest 等顶级仓库推荐（7KB） | ✅ 完成 (2026-06-05) |

### Level 3：自主推演（远期目标）
- 给定目标信息，AI 自主提出攻击假设
- 执行验证 → 学习 → 迭代

---

## 🧠 学习路线图

```
Phase 1: 操作系统内核 ✅ (完成)
  └── 内存管理 ✅ → 进程权限 ✅
       ↓
Phase 2: 网络协议栈 ✅ (完成)
  └── TCP/IP ✅ → HTTP ✅ → TLS ✅ → DNS ✅ → SSH ✅ → SMB ✅
  └── 新增: Docker容器安全 ✅ → ZTNA零信任安全 ✅ → NSG防火墙安全 ✅
       ↓
Phase 3: Web 安全模型 ✅ (完成)
  └── 浏览器安全 ✅ → XSS/注入 ✅ → CORS/认证 ✅
  └── 新增: 浏览器密码存储 ✅ → Everything HTTP安全 ✅
       ↓
Phase 4: 开发安全 ✅ (完成)
  └── C 内存安全 ✅ → Rust ✅ → 漏洞模式 ✅ → 供应链 ✅
       ↓
Phase 5: 密码学 ✅ (完成)
  └── 对称加密 ✅ → 非对称（RSA/ECC/DH）✅ → 哈希 ✅ → 签名 ✅ → 证书PKI ✅ → 攻击 ✅
  └── 新增: KeePass KDBX + 密码存储安全 ✅
       ↓
Phase 6: 硬件/设备安全 ✅ (新增)
  └── 税控UKey/金融硬件安全 ✅
       ↓
Level 1: 攻击面推导 ✅ (完成)
  └── 全领域攻击面地图 ✅
       ↓
Level 2: 案例融合 ✅ (完成)
  └── EternalBlue ✅ → CVE-27666 ✅ → XZ后门 ✅ → Log4Shell ✅ → Escape(AD) ✅
  └── PrintNightmare ✅ → ProxyShell ✅ → DirtyPipe ✅ → ZeroLogon ✅
  └── Heartbleed ✅ → Shellshock ✅ → PetitPotam ✅ → 6种攻击模式提炼 ✅
  └── Win10全面渗透案例 ✅（Everything HTTP→SSH Key→浏览器密码141条→FinalShell ZTNA凭据→10.0.0.0/8路由发现）
  └── 待写: Proxmox/NSG案例 ✅ → fnOS双网卡跳板案例 ✅
```
| 文档 | 内容 | 状态 |
|------|------|------|
| `cases/win10-browser-passwords-full.json` | Chrome 30条 + Edge 111条 全量导出密码（JSON） | ✅ 已保存 |
| `cases/case-win10-full-breach.md` | Windows 10 全面渗透案例文档 | 🟡 编写中 |
| `cases/case-win10-password-analysis.md` | 密码分类分析与攻击面推演 | 🟡 编写中 |

---

## 🔑 核心原则

**记住的目标不是学完所有知识，而是建立"从原理推导脆弱性"的思维框架。**

每个知识点要回答：
1. ✏️ 这个机制**正常应该怎么工作**？
2. 🔓 如果绕过/破坏它，**攻击者能得到什么**？
3. 🛡️ 现有的安全机制**为什么还不够**？
4. 💡 基于这个理解，**我们能想到什么新的攻击方向**？

---

## 📝 笔记规范

- 每个文件开头标注层级、来源
- 保持结构化：概念 → 原理 → 安全映射 → 攻击思路
- 重要的漏洞/案例添加来源链接

## 🔬 LLM 推理段（新增 — 2026-06-07）

### 用途
每个知识库文件末尾追加了结构化的 LLM 推理段，供 Qwen 14B 推理时直接检索使用。
包含：触发条件、检测信号、验证步骤、利用链扩展、关联攻击面、常见误判。

### 已升级的 P0 文件
| 文件 | 新增内容 | 状态 |
|------|---------|------|
| `web-security/02-xss-and-injection-security.md` | XSS + CSRF + SSTI 推理段 | ✅ |
| `web-security/03-cors-csrf-auth-security.md` | CORS配置错误 + 认证绕过推理段 | ✅ |
| `network/02-http-protocol-security.md` | 请求走私 + 安全头 + Cookie安全推理段 | ✅ |
| `dev-security/03-common-vulnerability-patterns.md` | 注入统一检测 + SSRF + 反序列化推理段 | ✅ |
| `network/03-docker-container-security.md` | 容器逃逸 + 不安全配置推理段 | ✅ |
| `protocols/03-tls-protocol-security.md` | TLS/SSL检查 + 中间人攻击推理段 | ✅ |
| `os-kernel/02-process-permission-security.md` | Linux提权 + 权限维持推理段 | ✅ |
| `level1-attack-surface-derivation.md` | 综合侦查推理流程 + 优先级排序 | ✅ |

### 新增参考文件
| 文件 | 内容 |
|------|------|
| `REASONING-TEMPLATE.md` | LLM推理段标准模板 | ✅ |

| `network/` | `06-kerberos-security.md` | Kerberos协议架构、六步握手、PAC验证、AS-REP Roasting/Kerberoasting/黄金白银票据/DCSync/委派攻击、加密类型、检测防御（14KB） | ✅ 新增 (2026-06-08) |
| `network/` | `07-ntlm-security.md` | NTLMv1/v2协议、挑战-响应流程、Pass-the-Hash/NTLM Relay/LLMNR投毒/NTLMv1降级/ADCS中继、利用链、检测防御（12KB） | ✅ 新增 (2026-06-08) |
| `network/` | `08-active-directory-security.md` | AD架构、NTDS.DIT、域信任、ACL滥用/GPO/GPP/RBCD/SID History、完整攻击链5阶段、BloodHound查询、事件监控（16KB） | ✅ 新增 (2026-06-08) |
| `os-kernel/` | `03-windows-security.md` | Windows安全主体、Access Token结构、UAC/UIPI、进程注入6技术、服务漏洞4大类、LSASS/SAM/DPAPI凭据窃取、横向移动5方法（15KB） | ✅ 新增 (2026-06-08) |
