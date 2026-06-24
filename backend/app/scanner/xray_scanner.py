from app.scanner.base import ToolWrapper

class XrayScanner(ToolWrapper):
    tool_name = "xray"
    timeout = 1800

    def build_command(self, target: str, **params) -> list[str]:
        return ["/opt/xray/xray", "webscan", "--url", target, "--json-output", "/tmp/xray_output.json"]

    def parse_output(self, raw_output: str) -> list[dict]:
        findings = []
        try:
            import json
            with open("/tmp/xray_output.json") as f:
                data = json.load(f)
            for vuln in (data if isinstance(data, list) else []):
                findings.append({"type": "web_vulnerability", "plugin": vuln.get("plugin",""),
                    "target": vuln.get("target",{}).get("url",""), "detail": vuln.get("detail",{})})
        except Exception: pass
        return findings
