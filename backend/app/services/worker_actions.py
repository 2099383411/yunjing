"""
Worker 可用动作注册表 — 给 LLM 决策时参考
"""
WORKER_ACTIONS = [
    {
        "id": "quick_port_scan",
        "name": "快速端口扫描",
        "description": "扫描目标最常见的1000个端口，耗时约1-2分钟",
        "params": {},
        "when_to_use": "初始阶段，发现目标有哪些开放端口"
    },
    {
        "id": "full_port_scan",
        "name": "全端口扫描",
        "description": "扫描全部65535个端口，耗时5-15分钟",
        "params": {},
        "when_to_use": "快速扫描未发现明显服务，或需要全面资产发现"
    },
    {
        "id": "service_detect",
        "name": "服务版本检测",
        "description": "对已发现端口进行服务识别和版本探测（nmap -sV）",
        "params": {"ports": "list[int] 要探测的端口列表"},
        "when_to_use": "已发现端口，需要了解运行的服务和版本"
    },
    {
        "id": "vuln_scan",
        "name": "漏洞扫描",
        "description": "用Nuclei扫描已知漏洞，可按模板类型过滤",
        "params": {"tags": "可选，nuclei模板标签如'cve,apache'"},
        "when_to_use": "已识别服务和版本，需要发现已知漏洞"
    },
    {
        "id": "dir_bruteforce",
        "name": "目录爆破",
        "description": "对Web服务进行目录枚举（gobuster），发现隐藏路径",
        "params": {"url": "str 完整的URL如 http://192.168.1.180:8080"},
        "when_to_use": "发现HTTP服务后，探索Web应用结构"
    },
    {
        "id": "web_tech_detect",
        "name": "Web技术栈识别",
        "description": "识别Web服务器使用的技术栈和框架（whatweb）",
        "params": {"url": "str 完整的URL"},
        "when_to_use": "发现HTTP服务，需要了解其技术栈"
    },
    {
        "id": "nikto_scan",
        "name": "Web服务器深度扫描",
        "description": "运行nikto对Web服务器进行全面安全检查",
        "params": {"url": "str 完整的URL"},
        "when_to_use": "Web服务已发现，需要全面检查服务器配置问题"
    },
    {
        "id": "credential_test",
        "name": "凭据测试",
        "description": "尝试用户名/密码登录服务",
        "params": {
            "service": "str 服务类型",
            "username": "str 用户名",
            "password": "str 密码",
            "url": "str 登录URL（如果是Web服务）"
        },
        "when_to_use": "有推测的凭据需要验证，或漏洞提示了默认凭据"
    },
    {
        "id": "sql_injection_test",
        "name": "SQL注入检测",
        "description": "测试URL参数是否存在SQL注入漏洞",
        "params": {"url": "str 带参数的完整URL"},
        "when_to_use": "发现带参数的URL端点，或漏洞扫描提示了SQL注入可能"
    },
    {
        "id": "auth_bypass_test",
        "name": "认证绕过检测",
        "description": "测试认证机制是否存在绕过漏洞",
        "params": {"url": "str 登录页面URL"},
        "when_to_use": "发现登录页面，需要尝试绕过认证"
    },
    {
        "id": "web_fuzz",
        "name": "Web参数模糊测试",
        "description": "对Web端点进行参数模糊测试（wfuzz）",
        "params": {"url": "str 带FUZZ占位符的URL"},
        "when_to_use": "需要发现隐藏参数或测试参数安全性"
    },
    {
        "id": "api_scan",
        "name": "API安全扫描",
        "description": "扫描API端点的安全漏洞（nuclei API模板）",
        "params": {"url": "str API基础URL"},
        "when_to_use": "发现API端点（如 /api/、/graphql 等）"
    },
    {
        "id": "smb_enum",
        "name": "SMB枚举",
        "description": "枚举SMB共享和用户信息（enum4linux）",
        "params": {},
        "when_to_use": "发现445端口或SMB服务"
    },
    {
        "id": "ssh_bruteforce",
        "name": "SSH暴力破解",
        "description": "对SSH服务进行密码暴力破解（hydra）",
        "params": {"username": "str 用户名", "password_list": "str 密码列表"},
        "when_to_use": "发现SSH服务且有用户名线索"
    },
    {
        "id": "lateral_probe",
        "name": "横向探测",
        "description": "扫描已发现网段的其他主机",
        "params": {"subnet": "str 子网如 192.168.1.0/24"},
        "when_to_use": "需要探索内网其他资产"
    },

    {
        "id": "exploit",
        "name": "漏洞利用",
        "description": "基于扫描发现的漏洞进行自动利用，尝试建立会话。支持SSH/HTTP/SMB/SQL等常见协议的漏洞利用",
        "params": {"vuln_filter": "str 可选: 指定漏洞类型, 如 cve/hydra/sqlmap"},
        "when_to_use": "扫描结束后已发现漏洞/弱口令，需要尝试实际利用获取目标控制权"
    },
    {
        "id": "post_exploit",
        "name": "后渗透操作",
        "description": "在已建立的会话上执行后渗透操作，包括信息收集、凭据提取、内网路由发现",
        "params": {"session_id": "str 可选: 指定会话ID，不指定则使用全部活动会话"},
        "when_to_use": "已成功建立会话，需要深入获取目标信息、提取凭据、探索内网拓扑"
    },
]
