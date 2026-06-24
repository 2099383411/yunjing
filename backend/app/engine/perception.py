"""云镜推理引擎 — 感知层

将各类扫描工具的输出格式化为推理引擎的标准数据结构。
支持从 nmap、nuclei、HTTP 探测、自定义扫描结果等来源接入。
"""
from __future__ import annotations
import json
import re
import logging
from typing import Any, Optional

from .models import (
    TargetPerception, PortInfo, WebInfo, FileInfo, CredentialInfo,
)

logger = logging.getLogger(__name__)


class PerceptionLayer:
    """感知层：扫描结果格式化器"""

    @staticmethod
    def from_nmap_scan(target: str, nmap_findings: list[dict]) -> TargetPerception:
        """从 nmap 扫描结果创建感知对象"""
        perception = TargetPerception(target=target)

        for finding in nmap_findings:
            port = finding.get("port", 0)
            if port:
                info = PortInfo(
                    port=int(port),
                    protocol=finding.get("protocol", "tcp"),
                    service=finding.get("service", ""),
                    service_version=finding.get("version", ""),
                    state=finding.get("state", "open"),
                    banner=finding.get("banner", ""),
                    confidence=finding.get("confidence", 0.5),
                )
                perception.open_ports.append(info)

                # 识别 Web 服务
                if port in (80, 443) or info.service.lower() in ("http", "https"):
                    scheme = "https" if port == 443 or "ssl" in finding.get("service", "").lower() else "http"
                    web_info = WebInfo(
                        url=f"{scheme}://{target}:{port}",
                        server=finding.get("server", ""),
                        technologies=finding.get("technologies", []),
                    )
                    perception.web_services.append(web_info)

            # 操作系统信息
            if finding.get("os"):
                perception.os_info = finding.get("os", "")

            # 主机名
            if finding.get("hostname"):
                perception.hostname = finding.get("hostname", "")

        perception.metadata["source"] = "nmap"
        perception.metadata["finding_count"] = len(nmap_findings)
        
        logger.info(f"[感知] nmap 格式化: {len(perception.open_ports)} 端口, "
                    f"{len(perception.web_services)} Web 服务")
        return perception

    @staticmethod
    def from_nuclei_scan(target: str, nuclei_findings: list[dict]) -> TargetPerception:
        """从 nuclei 扫描结果创建感知对象"""
        perception = TargetPerception(target=target)

        for finding in nuclei_findings:
            info = {
                "template": finding.get("template_id", ""),
                "name": finding.get("info", {}).get("name", ""),
                "severity": finding.get("info", {}).get("severity", "info"),
                "matched_at": finding.get("matched_at", ""),
                "extracted_results": finding.get("extracted_results", []),
                "curl_command": finding.get("curl_command", ""),
            }
            # 提取端口
            matched = finding.get("matched_at", "")
            port_match = re.search(r":(\d+)", matched)
            if port_match:
                info["port"] = int(port_match.group(1))

            perception.raw_findings.append(info)

        perception.metadata["source"] = "nuclei"
        perception.metadata["finding_count"] = len(nuclei_findings)
        
        logger.info(f"[感知] nuclei 格式化: {len(nuclei_findings)} 发现")
        return perception

    @staticmethod
    def from_gobuster_scan(target: str, gobuster_findings: list[dict]) -> TargetPerception:
        """从 gobuster 目录扫描结果创建感知对象"""
        perception = TargetPerception(target=target)

        for finding in gobuster_findings:
            url = finding.get("url", "")
            status = finding.get("status", 0)
            size = finding.get("size", 0)
            
            info = WebInfo(
                url=url,
                status_code=status,
                title=finding.get("title", ""),
            )
            perception.web_services.append(info)

            # 可访问的文件/目录
            if 200 <= status < 400:
                file_info = FileInfo(
                    path=url,
                    accessible=True,
                    size=size,
                )
                perception.accessible_files.append(file_info)

        perception.metadata["source"] = "gobuster"
        perception.metadata["finding_count"] = len(gobuster_findings)
        
        logger.info(f"[感知] gobuster 格式化: {len(gobuster_findings)} 路径")
        return perception

    @staticmethod
    def from_xray_scan(target: str, xray_findings: list[dict]) -> TargetPerception:
        """从 xray 扫描结果创建感知对象"""
        perception = TargetPerception(target=target)

        for finding in xray_findings:
            info = {
                "vuln_name": finding.get("vuln_class", ""),
                "url": finding.get("target", ""),
                "detail": finding.get("detail", ""),
                "payload": finding.get("payload", ""),
                "type": "xray",
            }
            perception.raw_findings.append(info)

        perception.metadata["source"] = "xray"
        perception.metadata["finding_count"] = len(xray_findings)
        
        logger.info(f"[感知] xray 格式化: {len(xray_findings)} 发现")
        return perception

    @staticmethod
    def from_curls_http_check(target: str, port: int, http_result: dict) -> TargetPerception:
        """从 curl HTTP 探测结果创建感知对象"""
        perception = TargetPerception(target=target)
        url = http_result.get("url", f"http://{target}:{port}")

        web_info = WebInfo(
            url=url,
            title=http_result.get("title", ""),
            server=http_result.get("server_header", ""),
            status_code=http_result.get("status_code", 0),
            technologies=http_result.get("technologies", []),
            security_headers=http_result.get("headers", {}),
            cookies=http_result.get("cookies", []),
        )
        perception.web_services.append(web_info)

        perception.metadata["source"] = "http_probe"
        logger.info(f"[感知] HTTP 探测: {url} → {web_info.status_code}")
        return perception

    @staticmethod
    def from_credentials(creds: list[CredentialInfo]) -> TargetPerception:
        """从已发现的凭据创建感知对象"""
        if not creds:
            return TargetPerception(target="unknown")

        perception = TargetPerception(target=creds[0].host or "unknown")
        perception.discovered_credentials = creds
        perception.metadata["source"] = "credential_discovery"
        logger.info(f"[感知] 凭据导入: {len(creds)} 条")
        return perception

    @staticmethod
    def merge(perceptions: list[TargetPerception]) -> TargetPerception:
        """合并多个感知结果为一个完整视图"""
        if not perceptions:
            return TargetPerception(target="unknown")
        if len(perceptions) == 1:
            return perceptions[0]

        base = perceptions[0]
        seen_ports = {p.port for p in base.open_ports}
        seen_urls = {w.url for w in base.web_services}

        for p in perceptions[1:]:
            # 合并端口
            for port_info in p.open_ports:
                if port_info.port not in seen_ports:
                    base.open_ports.append(port_info)
                    seen_ports.add(port_info.port)

            # 合并 Web 服务
            for web_info in p.web_services:
                if web_info.url not in seen_urls:
                    base.web_services.append(web_info)
                    seen_urls.add(web_info.url)

            # 合并文件
            base.accessible_files.extend(p.accessible_files)

            # 合并凭据
            base.discovered_credentials.extend(p.discovered_credentials)

            # 合并原始发现
            base.raw_findings.extend(p.raw_findings)

        base.metadata["merged_count"] = len(perceptions)
        base.metadata["source"] = "merged"
        
        logger.info(f"[感知] 合并完成: {len(base.open_ports)} 端口, "
                    f"{len(base.web_services)} Web, "
                    f"{len(base.accessible_files)} 文件")
        return base
