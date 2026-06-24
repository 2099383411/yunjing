from app.scanner.base import ToolWrapper

class SqlmapScanner(ToolWrapper):
    tool_name = "sqlmap"
    timeout = 900

    def build_command(self, target: str, **params) -> list[str]:
        cmd = ["python3", "/opt/sqlmap/sqlmap.py", "-u", target, "--batch", "--random-agent", "--level", "3", "--risk", "2"]
        if params.get("method","GET").upper() == "POST": cmd.extend(["--data", params.get("data","")])
        return cmd

    def parse_output(self, raw_output: str) -> list[dict]:
        if "is vulnerable" in raw_output.lower() or "sql injection" in raw_output.lower():
            return [{"type": "sql_injection", "tool": "sqlmap", "raw_summary": raw_output[-500:]}]
        return []
