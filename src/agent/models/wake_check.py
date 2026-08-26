import platform
import re
import socket
import struct
import subprocess
from agent.interfaces.checker import Checker

class WakeOnLanCheck(Checker):
    MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    IPV4_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

    def __init__(self):
        self.mac = ""
        self.status = False

    def run_check(self, params: dict):
        self.mac = (params.get("mac", "") or "").lower().replace("-", ":")
        if not self.MAC_RE.match(self.mac):
            return
        host = params.get("host", "") or ""
        packet = b"\xff" * 6 + bytes.fromhex(self.mac.replace(":", "")) * 16
        broadcast = self._get_broadcast_address(host)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                for port in (9, 7):
                    sock.sendto(packet, (broadcast, port))
            finally:
                sock.close()
            self.status = True
        except Exception:
            self.status = False

    def _get_broadcast_address(self, host: str) -> str:
        ip = ""
        if host:
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = ""
        try:
            if platform.system().lower() == "windows":
                return self._get_broadcast_windows(ip)
            return self._get_broadcast_linux(ip)
        except Exception:
            return "255.255.255.255"

    def _get_broadcast_linux(self, ip: str) -> str:
        if not ip:
            return "255.255.255.255"
        route = subprocess.run(["ip", "route", "get", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        m = re.search(r"dev\s+(\S+)", route.stdout.decode("utf-8", errors="ignore"))
        if not m:
            return "255.255.255.255"
        iface = m.group(1)
        addr = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", "dev", iface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        m2 = re.search(r"(?:brd|broadcast)\s+(\S+)", addr.stdout.decode("utf-8", errors="ignore"))
        if m2:
            return m2.group(1)
        return "255.255.255.255"

    def _get_broadcast_windows(self, ip: str) -> str:
        if not ip:
            return "255.255.255.255"
        try:
            route = subprocess.run(["route", "print", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            return "255.255.255.255"
        output = route.stdout.decode("utf-8", errors="ignore")
        best = None
        best_mask_bits = -1
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and self.IPV4_RE.match(parts[0]) and self.IPV4_RE.match(parts[1]):
                network, mask = parts[0], parts[1]
                if self._ip_in_subnet(ip, network, mask):
                    mask_bits = bin(self._ip_to_int(mask)).count("1")
                    if mask_bits > best_mask_bits:
                        best_mask_bits = mask_bits
                        best = (network, mask)
        if best != None:
            return self._subnet_broadcast(best[0], best[1])
        return "255.255.255.255"

    def _ip_to_int(self, ip: str) -> int:
        return struct.unpack("!I", socket.inet_aton(ip))[0]

    def _ip_in_subnet(self, ip: str, network: str, mask: str) -> bool:
        try:
            return (self._ip_to_int(ip) & self._ip_to_int(mask)) == (self._ip_to_int(network) & self._ip_to_int(mask))
        except Exception:
            return False

    def _subnet_broadcast(self, network: str, mask: str) -> str:
        try:
            broadcast = self._ip_to_int(network) | (self._ip_to_int(mask) ^ 0xFFFFFFFF)
            return socket.inet_ntoa(struct.pack("!I", broadcast))
        except Exception:
            return "255.255.255.255"

    def get_operation_result(self) -> dict:
        return {"status": self.status}
