# Linux 网络协议栈与安全

> 知识库层级：Level 1 - 网络基础
> 日期：2026-06-04
> 来源：Linux Kernel Docs, USENIX ATC 25, openSUSE Security Guide

## 一、网络栈架构

### 1.1 Linux 内核网络栈分层

Linux 内核实现了一个完整的 TCP/IP 栈，所有网络包在内核空间经过多层处理：

```
应用层 (用户态)
    │  system call (read/write/send/recv)
    ▼
Socket 层 (内核态)        ← 通用 socket 接口
    │
传输层 (TCP/UDP)          ← TCP 状态机、拥塞控制、分段
    │
网络层 (IP)               ← 路由、分片、ICMP
    │
链路层 (Device + Driver)  ← MAC 地址、ARP、NIC 驱动
    ▼
物理网卡 (NIC)
```

**核心数据结构：sk_buff（socket buffer）**

每个网络包在内核中表示为 `struct sk_buff`：

```c
struct sk_buff {
    // 指针定位
    unsigned char *head;    // 缓冲区起始
    unsigned char *data;    // 数据起始（随协议层移动）
    unsigned char *tail;    // 数据结束
    unsigned char *end;     // 缓冲区结束
    
    // 协议信息
    __be16 protocol;        // 上层协议
    struct net_device *dev; // 关联的网卡设备
    
    // 元数据
    __u32 len;              // 数据长度
    __u32 truesize;         // 实际占用内存（含结构体开销）
    struct sock *sk;        // 关联的 socket
    // ...
};
```

**安全关键：** sk_buff 的 `data` 指针在协议栈传递过程中不断前移——链路层指向 MAC 头，网络层指向 IP 头，传输层指向 TCP 头。如果内核在处理 sk_buff 时没有正确校验长度，就可能导致缓冲区溢出漏洞。

### 1.2 数据发送路径

```
应用调用 send() → 系统调用进入内核
    → 数据从用户空间拷贝到内核 socket 缓冲区
    → TCP 层创建 skb，填充 TCP 头（端口、序列号、校验和）
    → IP 层填充 IP 头（源/目标地址、TTL、校验和）
    → 网卡驱动通过 DMA 从内核缓冲区直接读取数据
    → 网卡硬件发送
```

**关键性能机制：**
- **TSO/GRO：** TCP 分段卸载，大段送到网卡后再由硬件分割成 MTU 大小的包
- **DMA：** 网卡可以直接从内存读取数据，不需要 CPU 逐字节拷贝

### 1.3 数据接收路径

```
网卡接收数据 → DMA 写入内存
    → 网卡触发硬件中断
    → 内核在 softirq（软中断）上下文中处理
    → 链路层校验 → 网络层路由 → 传输层 TCP 状态机
    → 数据放入 socket 接收缓冲区
    → 应用 read() 系统调用将数据拷贝到用户空间
```

## 二、内核网络参数与安全的交叉

Linux 网络协议栈有数百个可调参数（通过 sysctl 接口）。以下是与安全密切相关的关键参数：

### 2.1 TCP 连接管理

| 参数 | 安全作用 | 攻击场景 |
|------|----------|----------|
| `tcp_syncookies`=1 | 启用 SYN Cookie，防 SYN 泛洪攻击 | DDoS |
| `tcp_max_syn_backlog` | SYN 半连接队列大小 | SYN 泛洪时保护 |
| `tcp_rfc1337`=0 | 防止 TIME_WAIT 被篡改 | RST 攻击关闭连接 |
| `tcp_tw_reuse` | 回收 TIME_WAIT 套接字 | 端口耗尽后的恢复 |

### 2.2 IP 层安全

| 参数 | 安全作用 |
|------|----------|
| `ip_forward`=0 | 禁用 IP 转发（不作路由器） |
| `accept_source_route`=0 | 拒绝源路由包（防止 IP 重定向） |
| `rp_filter`=1 | 反向路径过滤（防 IP 欺骗） |
| `icmp_echo_ignore_broadcasts`=1 | 忽略 ICMP 广播（防 SMURF 攻击） |
| `secure_redirects`=1 | 只接受来自网关的重定向 |

### 2.3 socket buffer 大小控制

```bash
tcp_rmem = 4096 131072 6291456  # 接收缓冲区：最小/默认/最大
tcp_wmem = 4096 16384 4194304   # 发送缓冲区：最小/默认/最大
```

**漏洞关系：** 如果某服务的 TCP 接收缓冲区太小，在高流量下会发生缓冲区溢出（应用层的，不是内核的）。这就是为什么 `tcp_rmem` 调大可以缓解某些 DoS 场景。

## 三、内核绕过（Kernel Bypass）

### 3.1 为什么有 Kernel Bypass？

内核网络栈的性能瓶颈：
1. **上下文切换：** 每次系统调用需要在用户态/内核态之间切换
2. **数据拷贝：** 数据在用户态和内核态之间至少拷贝两次
3. **中断处理：** 每个包都会触发中断 → 上下文切换

**解决方案对比：**

| 技术 | 原理 | 适用场景 | 安全影响 |
|------|------|----------|----------|
| DPDK | 用户态轮询网卡，完全绕过内核 | 高性能包处理（>10Gbps） | 放弃了内核安全隔离，应用直接操作硬件 |
| RDMA | 网卡直接读写应用内存 | 高性能存储/计算集群 | 内存暴露给硬件，需要严格保护 |
| XDP/eBPF | 在内核入口处执行用户自定义代码 | 包过滤、负载均衡 | eBPF 校验器确保安全，不能执行危险操作 |
| io_uring | 共享环形缓冲区代替系统调用 | 高性能 I/O | 减少 syscall 次数，但在内核的监管下 |

**安全启示：** 高性能解决方案往往伴随着安全权衡。DPDK 应用如果被攻破，攻击者可以直接控制网卡硬件，绕过所有内核安全机制。

### 3.2 eBPF 的安全模型

eBPF 允许用户态程序安全地在内核中执行：

```
用户态编写 C 代码 → eBPF 编译器生成字节码
    → 内核 eBPF 校验器验证：
        - 循环必须有界（每次必须终止）
        - 不能访问任意内核内存
        - 指针必须经过边界检查
    → JIT 编译为本地机器码
    → 挂载到内核钩子（网络、跟踪、安全等）
```

**限制：** eBPF 不能随意访问内核内存，不能执行无限循环，不能超出栈帧限制。这是刻意设计的安全边界。

## 四、容器隔离：Namespace 和 Cgroup

### 4.1 Namespace — 控制"能看到什么"

Linux 目前支持 8 种 Namespace：

| Namespace | 隔离的资源 | 安全问题 |
|-----------|-----------|----------|
| `mnt` | 文件系统挂载点 | mount 释放后可能被利用 |
| `pid` | 进程 ID 空间 | 父 namespace 能看到子 namespace 的所有进程 |
| `net` | 网络栈（IP、路由、端口） | 共享宿主机内核，网络设备可能泄漏 |
| `ipc` | System V IPC/Posix 消息队列 | 共享内存可能被跨 namespace 访问 |
| `uts` | 主机名和域名 | 信息泄漏 |
| `user` | UID/GID 映射 | 关键——容器内 root 在宿主机上可能是普通用户 |
| `cgroup` | cgroup 层次结构 | 信息泄漏 |
| `time` | 系统时间 | 时间偏移可能影响日志审计 |

**关键安全原则：**
> **Namespaces 不是安全边界。它们是为了管理而设计的资源隔离机制，不是安全沙箱。**

Hacker News 上有个经典评论：
> "Namespaces and cgroups provide resource accounting and some limited isolation between TRUSTED workloads. They're NOT considered a sandbox or security boundary because the processes have full access to the Linux kernel APIs, which are not well-hardened."

**核心问题：** 
- 容器和宿主机共享**同一个内核**
- Namespace 只限制了"能看到什么"，不限制"能做什么"
- 如果存在内核漏洞，容器内触发漏洞 → 宿主机沦陷

### 4.2 Cgroup — 控制"能用多少"

Cgroups 控制进程组的资源使用上限：

| 子系统 | 控制内容 | 安全作用 |
|--------|----------|----------|
| `cpu` | CPU 时间片比例 | 防止单个容器耗尽 CPU |
| `memory` | 内存上限 | 防止内存泄漏影响其他容器 |
| `blkio` | 磁盘 I/O 带宽 | 防止 I/O 争抢 |
| `net_prio` | 网络流量优先级 | 服务质量控制 |
| `devices` | 设备访问权限 | 限制对 /dev/sda 等设备的访问 |
| `pids` | 进程数上限 | 防止 fork bomb |

### 4.3 安全增强层

Namespaces + Cgroups 本身是不够的。真正提供安全边界的是额外的层：

| 机制 | 原理 | 应用 |
|------|------|------|
| **Seccomp** | 系统调用白名单，限制容器内可用的 syscall | Docker 默认屏蔽 44 个危险 syscall |
| **AppArmor/SELinux** | 强制访问控制（MAC），细粒度限制进程行为 | 限制容器内进程只能访问特定文件 |
| **Capabilities** | 将 root 权限拆分为独立的能力，按需授予 | 容器默认去除 SYS_MODULE、SYS_RAWIO 等 |
| **gVisor** | 用户态内核，拦截系统调用并在用户态处理 | Google Cloud Run 使用 |
| **Firecracker** | 微型 VM，提供硬件级隔离 | AWS Lambda 和 Fargate 使用 |

### 4.4 容器逃逸的分类

```
┌───────────────────────────────────────────────┐
│  容器逃逸攻击分类                               │
├───────────────────────────────────────────────┤
│  Type 1: 内核漏洞逃逸                          │
│  原理：容器内触发内核漏洞 → 突破 namespace      │
│  典型：DirtyPipe (CVE-2022-0847)               │
│                                               │
│  Type 2: 配置错误逃逸                          │
│  原理：容器被授予了过多权限（如 --privileged）    │
│  典型：挂载宿主机 /proc → mount 宿主文件系统     │
│                                               │
│  Type 3: 危险挂载逃逸                          │
│  原理：容器可以访问宿主机敏感路径               │
│  典型：挂载 /var/run/docker.sock → 控制宿主机   │
│                                               │
│  Type 4: 共享路径 / 卷逃逸                     │
│  原理：利用容器和宿主共享的目录写篡改攻击        │
│  典型：假设宿主机 cron 定时读取共享目录          │
└───────────────────────────────────────────────┘
```

## 五、从底层理解到攻击思路

### 5.1 每个底层机制都能对应一个攻击面

| 底层机制 | 安全边界 | 可能的绕过方向 |
|----------|----------|---------------|
| 虚拟内存/MMU | 进程间内存隔离 | 侧信道（Meltdown/Spectre） |
| 系统调用 | 用户态→内核态入口 | 漏洞 syscall、seccomp 绕过 |
| TCP/IP 栈 | 网络数据完整性 | 协议实现 bug、状态机攻击 |
| socket buffer | 内核内存管理 | skb 长度校验错误 → 溢出 |
| namespace | 进程可见性 | 内核漏洞突破命名空间 |
| cgroup | 资源限制 | 资源共享绕过（如 /proc/1 泄漏） |
| file descriptor | 文件访问权限 | FD 传递 + 竞态条件 |

### 5.2 渗透测试中的实际应用

**场景：Web 应用存在文件上传漏洞，上传了 WebShell，尝试提权**

```
传统思路：
WebShell → 执行命令 → sudo -l → 发现 NOPASSWD 脚本 → sudo 提权

底层理解：
WebShell 本质是能执行系统调用的代码片段
→ sudo 的实质是 setuid 系统调用
→ NOPASSWD 意味着 pam 模块跳过了密码验证
→ 更关键的是理解这个脚本在干什么
   → 脚本可能调用了危险的系统调用组合
   → 即使不是明显提权，也可能利用竞态条件
```

---

**下一层：** 理解网络栈后，下一步是"Web 安全协议"——HTTP 协议规范、TLS 握手细节、WebSocket 安全模型。
