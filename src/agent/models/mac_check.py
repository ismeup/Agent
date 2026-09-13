import platform
import re
import socket
import subprocess
from agent.config import ENABLE_WOL
from agent.interfaces.checker import Checker

class MacCheck(Checker):
    MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}){5}[0-9a-fA-F]{2}")

    def __init__(self):
        self.host = ""
        self.status = False
        self.mac = ""
        self.error = ""

    def run_check(self, params: dict):
        if not ENABLE_WOL:
            self.error = "get mac is disabled, set ENABLE_WOL=1 to enable it"
            return
        self.host = params.get("host", "")
        if not self.host:
            return
        try:
            ip = socket.gethostbyname(self.host)
        except Exception:
            return
        try:
            cmd = ["ping", "-n", "1", "-w", "1000", ip] if platform.system().lower() == "windows" else ["ping", "-c", "1", "-W", "1", ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            pass
        self.mac = self._get_mac(ip)
        self.status = self.mac != ""

    def _get_mac(self, ip: str) -> str:
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(["arp", "-a", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
                output = result.stdout.decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == ip:
                        mac = parts[1].replace("-", ":").lower()
                        if mac != "00:00:00:00:00:00":
                            return mac
            else:
                with open("/proc/net/arp", "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip:
                            mac = parts[3].lower()
                            if mac != "00:00:00:00:00:00":
                                return mac
        except Exception:
            pass
        return ""

    def get_operation_result(self) -> dict:
        result: dict = {"status": self.status, "mac": self.mac}
        if self.error:
            result["error"] = self.error
        return result
