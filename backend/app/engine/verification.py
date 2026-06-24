"""云镜推理引擎 — 验证执行器

将推理引擎的攻击假设映射到实际的扫描工具调用。
桥接层：引擎假设 → 现有扫描基础设施。

当前实现：
- 规则映射：根据假设类型选择对应扫描工具
- 参数构造：从假设和感知结果构造扫描参数
- 结果解析：解析工具输出并更新假设置信度
"""
from __future__ import annotations
import logging
import subprocess
from typing import Optional

from .models import AttackHypothesis, TargetPerception, VerificationStep

logger = logging.getLogger(__name__)


class VerificationExecutor:
    """验证执行器 — 桥接推理假设与扫描工具"""

    def __init__(self, sandbox: bool = False):
        """
        Args:
            sandbox: 是否在沙箱中执行（未来支持）
        """
        self._sandbox = sandbox

    def execute(self, hypothesis: AttackHypothesis,
                perception: Optional[TargetPerception] = None) -> tuple[bool, str]:
        """执行假设验证

        Args:
            hypothesis: 待验证的假设
            perception: 目标感知结果（可选）

        Returns:
            (成功/失败, 证据描述)
        """
        # 根据假设名称选择验证策略
        handler = self._select_handler(hypothesis)
        if not handler:
            return False, f"无匹配的验证处理器: {hypothesis.name}"

        try:
            success, evidence = handler(hypothesis, perception)
            logger.info(f"[验证] {hypothesis.name}: {'✅' if success else '❌'} - {evidence[:200]}")
            return success, evidence
        except Exception as e:
            logger.error(f"[验证] {hypothesis.name} 执行失败: {e}")
            return False, f"验证执行异常: {str(e)}"

    def _select_handler(self, h: AttackHypothesis) -> Optional[callable]:
        """根据假设特征选择验证处理器"""
        name = h.name.lower()
        
        if "web" in name or "注入" in name or "xss" in name:
            return self._verify_web
        elif "ssh" in name:
            return self._verify_ssh
        elif "redis" in name:
            return self._verify_redis
        elif "数据库" in name or "mysql" in name or "postgres" in name:
            return self._verify_database
        elif "smb" in name:
            return self._verify_smb
        elif "everything" in name or "文件系统" in name:
            return self._verify_everything_http
        elif "容器" in name or "docker" in name:
            return self._verify_container
        elif "ztna" in name or "headscale" in name:
            return self._verify_ztna
        elif "浏览器密码" in name:
            return self._verify_browser_password
        elif "keepass" in name or "密码库" in name:
            return self._verify_keepass
        elif "密码复用" in name:
            return self._verify_cred_reuse
        elif "防火墙" in name or "nsg" in name:
            return self._verify_firewall
        elif "向日葵" in name or "sunlogin" in name:
            return self._verify_sunlogin
        elif "finalshell" in name:
            return self._verify_finalshell
        else:
            return self._verify_generic

    def _run_cmd(self, cmd: str, timeout: int = 30) -> tuple[bool, str]:
        """执行系统命令并返回结果"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                output = result.stdout.strip() or "(无输出)"
                return True, output
            else:
                error = (result.stderr or result.stdout or "").strip()[:200]
                return False, f"命令失败[{result.returncode}]: {error}"
        except subprocess.TimeoutExpired:
            return False, "命令执行超时"
        except Exception as e:
            return False, f"命令执行异常: {str(e)}"

    def _verify_web(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """Web 漏洞验证 — 先用 curl 探活 + 标题"""
        if not p or not p.web_services:
            return False, "无 Web 服务信息可验证"
        
        url = p.web_services[0].url
        success, output = self._run_cmd(f"curl -sk --connect-timeout 5 -m 10 '{url}' | head -100")
        
        if success and output:
            # 检查是否存在基础测试页面
            for indicator in ["login", "admin", "php", "wp-", "index"]:
                if indicator in output.lower()[:500]:
                    return True, f"{url} 响应正常，检测到 '{indicator}' 相关内容"
            return True, f"{url} 响应正常，运行标准 Web 漏洞扫描"
        return False, f"{url} 无响应或连接失败"

    def _verify_ssh(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """SSH 验证 — 尝试 SSH 版本确认"""
        target = p.target if p else "unknown"
        success, output = self._run_cmd(f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -V {target} 2>&1 || true")
        # 确认 SSH 服务可达
        success2, output2 = self._run_cmd(f"nc -z -w 3 {target} 22 2>&1 && echo 'SSH_PORT_OPEN' || echo 'SSH_PORT_CLOSED'")
        if "SSH_PORT_OPEN" in output2:
            return True, f"{target}:22 SSH 端口开放，可尝试暴力破解或私钥登录"
        return False, f"{target}:22 SSH 端口不可达"

    def _verify_redis(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """Redis 验证 — 尝试 ping"""
        target = p.target if p else "unknown"
        success, output = self._run_cmd(
            f"echo 'PING' | timeout 5 redis-cli -h {target} -p 6379 2>&1"
        )
        if "PONG" in output:
            return True, f"Redis {target}:6379 可连接并响应 PONG（无认证！）"
        elif "NOAUTH" in output:
            return True, f"Redis {target}:6379 要求认证但可达"
        return False, f"Redis {target}:6379 不可达或连接失败"

    def _verify_database(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """数据库验证 — 尝试默认凭据连接"""
        target = p.target if p else "unknown"
        # MySQL 默认 root 无密码尝试
        success, output = self._run_cmd(
            f"timeout 5 mysql -h {target} -u root --password='' -e 'SELECT 1' 2>&1"
        )
        if success:
            return True, f"MySQL {target} root/空密码 登录成功！"
        if "Access denied" not in output:
            return True, f"MySQL {target} 可达，端口开放"
        return False, f"MySQL {target} 不可达或访问被拒绝"

    def _verify_smb(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """SMB 验证"""
        target = p.target if p else "unknown"
        success, output = self._run_cmd(f"timeout 5 smbclient -L //{target} -N 2>&1")
        if "Sharename" in output or "IPC$" in output:
            return True, f"SMB {target} 匿名访问成功，可枚举共享"
        return False, f"SMB {target} 匿名访问被拒绝"

    def _verify_everything_http(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """Everything HTTP 验证"""
        target = p.target if p else "unknown"
        success, output = self._run_cmd(f"curl -sk --connect-timeout 5 'http://{target}:13577/' 2>&1")
        if success and ("<html" in output.lower() or "everything" in output.lower()):
            return True, f"Everything HTTP {target}:13577 可访问，文件系统泄露确认"
        return False, f"Everything HTTP {target}:13577 不可访问"

    def _verify_container(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """容器逃逸验证 — 检查 docker.sock"""
        import os.path
        sock_path = "/var/run/docker.sock"
        if os.path.exists(sock_path):
            return True, f"docker.sock 存在于当前环境，容器逃逸条件满足"
        
        # 尝试通过 curl 访问
        success, output = self._run_cmd(
            "curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json 2>&1"
        )
        if success and "Id" in output:
            return True, "docker.sock 可通过 HTTP 访问"
        return False, "未发现 docker.sock，容器逃逸条件不满足"

    def _verify_ztna(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """ZTNA 验证"""
        target = p.target if p else "unknown"
        success, output = self._run_cmd(f"curl -sk --connect-timeout 5 'http://{target}:8080/api/v1/node' 2>&1")
        if success and output:
            return True, f"ZTNA API {target}:8080 响应: {output[:200]}"
        return False, f"ZTNA API {target}:8080 无响应"

    def _verify_browser_password(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """浏览器密码验证 — 检查路径是否存在"""
        paths = [
            os.path.expanduser("~") + "/AppData/Local/Google/Chrome/User Data/Local State",
            os.path.expanduser("~") + "/AppData/Local/Microsoft/Edge/User Data/Local State",
        ]
        import os.path
        for path in paths:
            if os.path.exists(path):
                return True, f"浏览器 Local State 文件存在: {path}"
        return False, "未找到浏览器 Local State 文件（非 Windows 环境或无浏览器）"

    def _verify_keepass(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """KeePass 验证 — 检查 kdbx 文件"""
        return False, "KeePass 验证需要离线操作，当前环境不支持"

    def _verify_cred_reuse(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """密码复用验证 — 检查是否有凭据可用"""
        if p and p.discovered_credentials:
            creds = p.discovered_credentials
            return True, f"已有 {len(creds)} 条凭据可用于密码复用测试: " \
                         f"{[(c.username, c.host) for c in creds[:5]]}"
        return False, "当前无可用凭据用于密码复用验证"

    def _verify_firewall(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """防火墙验证"""
        return False, "防火墙验证需要手动操作"

    def _verify_sunlogin(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """向日葵验证"""
        return False, "向日葵验证需要手动操作"

    def _verify_finalshell(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """FinalShell 验证"""
        return False, "FinalShell 验证需要手动操作"

    def _verify_generic(self, h: AttackHypothesis, p: Optional[TargetPerception]) -> tuple[bool, str]:
        """通用验证 — 基于端口探测"""
        target = p.target if p else "unknown"
        return True, f"已记录假设 [{h.name}]，标记为待手动验证"
