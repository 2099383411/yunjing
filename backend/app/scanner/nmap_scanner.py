from app.scanner.base import ToolWrapper

class NmapScanner(ToolWrapper):
    tool_name = "nmap"
    timeout = 600

    def build_command(self, target: str, **params) -> list[str]:
        ports = params.get("ports", "1-1000")
        timing = params.get("timing", "T4")
        return ["nmap", "-sV", "-sC", f"-p{ports}", f"-{timing}", "-oX", "-", target]

    def parse_output(self, raw_output: str) -> list[dict]:
        findings = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw_output)
            for host in root.findall("host"):
                ip = host.find("address").get("addr") if host.find("address") is not None else "unknown"
                for port in host.findall(".//port"):
                    state = port.find("state")
                    service = port.find("service")
                    if state is not None and state.get("state") == "open":
                        findings.append({"type": "open_port", "ip": ip,
                            "port": int(port.get("portid")), "protocol": port.get("protocol"),
                            "service": service.get("name") if service is not None else "unknown",
                            "product": service.get("product","") if service is not None else "",
                            "version": service.get("version","") if service is not None else ""})
        except Exception: pass
        return findings
