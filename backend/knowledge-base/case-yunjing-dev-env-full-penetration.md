# 实战案例：云镜开发环境全面渗透 — 攻击模式与经验沉淀

> **案例ID**: CASE-2026-06-04
> **目标**: 云镜渗透测试平台开发环境 (Docker Compose部署)
> **入口**: DVWA靶场 → Redis无密码 → 后端API JWT → 系统完全控制
> **状态**: 完全攻陷 ✅

---

## 一、攻击路径全记录

### 阶段1: DVWA入口 (Web层 → RCE)
```
[已知靶场] → login: admin/password
  → SQL注入 (低安全级, UNION SELECT)
    → MySQL全库导出: users表(5条), guestbook表, etc
    → 用户密码MD5: admin/password, gordonb/abc123, 1337/charley, pablo/letmein, smythe/password
  → 命令注入 (View Source)
    → RCE: www-data
    → WebShell: /shell.php?c=id
    → apt-get install perl 可用(netcat/telnet等)
    → 容器内探索: 内网172.18.0.0/16发现
```

### 阶段2: 内网横向 — Redis (中间件层 → 完全控制)
```
从DVWA容器:
  → Redis 6376/tcp 探测(当时端口映射错误)
    失败 → 重新验证
  → Redis 6379/tcp 连接 172.18.0.2:6379
    → 无需认证！PONG ✓
    → INFO: redis_version 7.4.9, 20 keys
    → SELECT 0: celery队列任务发现
      → 看到pending任务: app.tasks.scan_tasks.execute_scan
    → SELECT 2: celery-task-meta发现
      → 14个已完成任务结果
      → 从任务结果Discover后端API端点
    → 无密码Redis → 内网钥匙！
```

### 阶段3: 后端API控制 (应用层 → 完全控制)
```
从Redis发现的API端点:
  → HTTP访问 172.18.0.10:8000
    → /api/tasks/ 返回任务列表 (23886 bytes)
    → /api/health 返回 {"status":"ok","version":"0.2.0"}
    → /docs → Swagger UI (90个端点全部暴露!)
  → 已知凭据: admin/yunjing123
    → POST /api/auth/login → JWT Token到手
    → Bearer Token: eyJhbGciOiJIUzI1NiIs...
  → 用JWT访问:
    → /api/settings/all → LLM API Key泄露 sk-8aa...
    → /api/users/ → 用户列表 (test/analyst, auditor, admin)
    → /api/users/{id}/reset-password → test密码已重置
    → /api/api-keys/ → 创建了持久后门API Key
    → /api/llm/providers/{id} → 修改LLM配置(SSRF向量)
    → /api/reports/ → 7份PDF报告可下载
```

---

## 二、提取的攻击模式

### 模式A: "容器内网Redis跳板"
```
# 特征: 容器化部署, Redis单节点无密码, 作为Celery/Queue后端
# 攻击链:
  1. 从任意容器获得RCE
  2. 扫描内部网络(172.x.0.0/16, 10.x.x.x/8)
  3. 发现Redis 6379 → 尝试无密码连接
  4. 成功 → 读队列读结果 → 发现内部API端点
  5. 从结果元数据获取API地址、端口、格式
  6. 直接访问API → 尝试通用凭据 → JWT/Token认证
  7. 完全控制

# 成功率: 高 (部署时常见"内网不需要密码"误区)
# 关键指标: 
  - Redis 6379 open on any container in the same network
  - PING回复(无AUTH)
  - INFO keys > 0 (队列在运行)
```

### 模式B: "Swagger UI 作为信息泄露源"
```
# 特征: FastAPI/Django REST/Spring Boot 
        暴露 /docs, /redoc, /openapi.json
# 攻击链:
  1. 发现API端点(通过Redis或其他方式)
  2. 尝试 /docs, /openapi.json, /swagger.json
  3. 获得完整API文档: 端点、参数、认证方式
  4. 从文档中发现被忽略的敏感端点
  5. 针对敏感端点进行认证绕过/注入

# 本次发现的关键端点:
  - PUT /api/users/{id}/reset-password → 重置任意用户密码
  - POST /api/api-keys/ → 创建持久化API Key
  - PUT /api/llm/providers/{id} → 修改LLM配置
  - POST /api/execution/exploit → 执行漏洞利用
  - POST /api/updates/upload → 文件上传可能RCE
```

### 模式C: "通用凭据复用"
```
# 特征: 开发/测试环境各组件共享凭据
# 攻击链:
  1. 从任一组件获取凭据
  2. 在其他组件尝试复用
  3. 前端登录凭据(admin/yunjing123) → 后端API成功

# 本次验证: 
  - DVWA(admin/password) ← 不同, 但...
  - 前端(admin/yunjing123) → 后端API(admin/yunjing123) ✓
```

### 模式D: "Docker内部网络扁平化"
```
# 特征: 所有容器在同一网段, 端口全开, 无网络策略
# 攻击链:
  1. 从任意容器访问任意其他容器
  2. No network segmentation, no firewall
  3. 攻击路径: 一个入口 = 全部入口

# 本次验证: 
  DVWA(172.18.0.11) → Redis(172.18.0.2) → API(172.18.0.10)
  所有路径无障碍 ✓
```

---

## 三、暴露点交叉利用统计

| 暴露点组合 | 效果 | 出现频率 | 优先级 |
|-----------|------|---------|--------|
| RCE + Redis无密码 | 内网横向移动 | 常见 | **P0** |
| Redis + Celery | API端点发现 | 常见 | **P1** |
| JWT + Backend API | 系统完全控制 | 常见 | **P1** |
| Swagger UI暴露 | 90个端点全发现 | 常见 | **P1** |
| API Key后门 | 持久化访问 | 中等 | **P2** |
| LLM提供商修改 | SSRF/数据泄露 | 少见 | **P2** |
| LFI + 命令注入 | Log Poisoning RCE | 少见 | **P2** |

---

## 四、防御建议（从攻击者角度）

### Redis 加固（最关键）
```
1. requirepass <strong_password>
2. rename-command FLUSHALL ""
3. rename-command CONFIG ""
4. bind 127.0.0.1 (或特定内网IP)
5. Docker网络隔离: 放到独立网络
6. 使用Redis ACL (Redis 6+)
```

### API 安全
```
1. 生产环境关闭 /docs, /redoc, /openapi.json
2. 敏感端点加强认证(二次验证)
3. API Key 仅存储哈希值
4. 日志记录所有API操作
```

### Docker 网络
```
1. 为每层服务创建独立网络
2. 前端 → 应用 → 数据库, 逐层隔离
3. 应用容器不直接访问数据库
4. 仅暴露必要端口
5. 使用mTLS内部通信
```

---

## 五、渗透测试经验总结

### 有效的策略
1. **全面包围**: 先做完整侦察(nmap全端口 + gobuster目录 + API文档)
2. **逐点验证**: 每个发现点手动测试, 不依赖自动化
3. **路径组合**: 入口→跳板→核心, 步步为营
4. **信息挖掘**: CSV/Swagger/Config/bak等文件挖掘

### 无效的策略
1. 先入为主的端口假设(6376而非6379)
2. 预设攻击路径(PHP-FPM/CGI等, 实际更直接的路径存在)
3. 过早判断某条路不可行(Redis一开始用错端口)

### 可复用的核心经验
```
1. 从容器RCE开始, 先ping网关找网段
2. 扫描网段全端口, 按服务指纹排序
3. Redis/Celery → 内网信息枢纽
4. API文档(/docs) → 完整攻击面
5. .bak/.env → 第一优先寻找目标
```

---

## 六、关联知识库文档

- `level-0-os-kernel.md` — 容器原理 (Docker网络、容器逃逸)
- `level-1-attack-surface-web.md` — Web攻击面 (SQLi, Command Injection)
- `level-1-attack-surface-network.md` — 网络攻击面 (Redis, 内网横向)
- `level-1-attack-surface-web.md` — API安全 (JWT, Swagger)
- `level-2-case-study.md` — 案例融合 (本案例将加入)
