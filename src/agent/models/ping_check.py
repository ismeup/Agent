import platform
import subprocess
from agent.interfaces.checker import Checker

class PingCheck(Checker):
    MAX_FAIL_CHECK = 3

    def __init__(self):
        self.host = ""
        self.status = False
        self.fail_counter = 0

    def run_check(self, params: dict):
        self.host = params.get("host", "")
        
        while not self.status and self.fail_counter < self.MAX_FAIL_CHECK:
            try:
                cmd = ["ping", "-n", "1", self.host] if platform.system().lower() == "windows" else ["ping", "-c", "1", self.host]
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                self.status = (result.returncode == 0)
            except Exception:
                self.status = False
                
            if not self.status:
                self.fail_counter += 1
                
    def get_operation_result(self) -> dict:
        return {"status": self.status}
