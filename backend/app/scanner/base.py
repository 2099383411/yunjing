import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class ScanResult:
    tool_name: str
    target: str
    success: bool
    raw_output: str = ""
    findings: list[dict] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

class ToolWrapper(ABC):
    tool_name: str = "base"
    timeout: int = 300
    retry: int = 2

    @abstractmethod
    def build_command(self, target: str, **params) -> list[str]: ...
    @abstractmethod
    def parse_output(self, raw_output: str) -> list[dict]: ...

    def execute(self, target: str, **params) -> ScanResult:
        import time
        start = time.time()
        cmd = self.build_command(target, **params)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            output = result.stdout or result.stderr
            findings = self.parse_output(output)
            return ScanResult(tool_name=self.tool_name, target=target,
                success=result.returncode == 0, raw_output=output, findings=findings,
                duration=time.time() - start,
                error=None if result.returncode == 0 else f"exit:{result.returncode}")
        except subprocess.TimeoutExpired:
            return ScanResult(tool_name=self.tool_name, target=target,
                success=False, error=f"timeout {self.timeout}s", duration=time.time() - start)
        except Exception as e:
            return ScanResult(tool_name=self.tool_name, target=target,
                success=False, error=str(e), duration=time.time() - start)
