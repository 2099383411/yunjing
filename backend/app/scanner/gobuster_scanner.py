from app.scanner.base import ToolWrapper
import os

class GobusterScanner(ToolWrapper):
    tool_name = "gobuster"
    timeout = 600

    def build_command(self, target: str, **params) -> list[str]:
        # Auto-detect wordlist path
        paths = [
            "/usr/share/dirb/wordlists/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/small.txt",
        ]
        wordlist = params.get("wordlist", "")
        if not wordlist or not os.path.exists(wordlist):
            for p in paths:
                if os.path.exists(p):
                    wordlist = p
                    break
            if not wordlist:
                # Last resort: generate a small inline wordlist
                import tempfile
                tf = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
                tf.write("admin\nlogin\nwp-admin\napi\ntest\nbackup\n\.git\nconfig\ndebug\n")
                tf.close()
                wordlist = tf.name
        return ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-t", "10"]

    def parse_output(self, raw_output: str) -> list[dict]:
        findings = []
        for line in raw_output.strip().split("\n"):
            if line.strip() and "/" in line and ("(" in line or "Status" in line):
                findings.append({"type": "directory", "path": line.strip()})
        return findings
