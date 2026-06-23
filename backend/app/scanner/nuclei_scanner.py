import json
from app.scanner.base import ToolWrapper

class NucleiScanner(ToolWrapper):
    tool_name = "nuclei"
    timeout = 1800

    def build_command(self, target: str, **params) -> list[str]:
        severity = params.get("severity", "medium,high,critical")
        cmd = ["nuclei", "-target", target, "-severity", severity, "-jsonl", "-no-interactsh", "-timeout", "10", "-retries", "2"]
        if tags := params.get("tags"): cmd.extend(["-tags", tags])
        return cmd

    def parse_output(self, raw_output: str) -> list[dict]:
        findings = []
        for line in raw_output.strip().split("\n"):
            if not line.strip().startswith("{"): continue
            try:
                entry = json.loads(line.strip())
                info = entry.get("info", {})
                findings.append({"type": "vulnerability", "template_id": entry.get("template-id",""),
                    "name": info.get("name",""), "severity": info.get("severity","unknown"),
                    "description": info.get("description",""), "remediation": info.get("remediation",""),
                    "matched_at": entry.get("matched-at",""),
                    "cve_id": (entry.get("classification",{}) or {}).get("cve-id",[None])[0],
                    "cvss_score": (entry.get("classification",{}) or {}).get("cvss-score"),
                    "references": info.get("reference",[])})
            except (json.JSONDecodeError, KeyError): continue
        return findings
