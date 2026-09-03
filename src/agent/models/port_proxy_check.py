from typing import Any, Dict

from agent.interfaces.checker import Checker
from agent.port_proxy.tunnel import PortProxyTunnel, READY_TIMEOUT


class PortProxyCheck(Checker):
    def __init__(self):
        self.uid = ""
        self.status = False
        self.error = ""
        self.tunnel: PortProxyTunnel | None = None

    def run_check(self, params: Dict[str, Any]) -> None:
        self.uid = str(params.get("uid", ""))
        proxy_host = str(params.get("proxy_ip", ""))
        proxy_port = params.get("proxy_port", 0)
        proxy_public_key = str(params.get("proxy_public_key", ""))
        routing = params.get("routing", {}) or {}

        if not self.uid or not proxy_host or not proxy_port or not proxy_public_key:
            self.status = False
            self.error = "missing required params: uid, proxy_ip, proxy_port, proxy_public_key"
            return

        try:
            tunnel = PortProxyTunnel(self.uid, proxy_host, int(proxy_port), proxy_public_key, routing)
        except (TypeError, ValueError) as e:
            self.status = False
            self.error = str(e)
            return

        self.tunnel = tunnel
        tunnel.start()
        if not tunnel.wait_ready(READY_TIMEOUT):
            self.status = False
            self.error = tunnel.error or "tunnel did not become ready"
            tunnel.stop()
            return
        self.status = True

    def get_operation_result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"status": self.status, "uid": self.uid}
        if not self.status and self.error:
            result["error"] = self.error
        return result
