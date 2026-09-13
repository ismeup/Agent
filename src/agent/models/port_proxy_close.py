from typing import Any, Dict

from agent.interfaces.checker import Checker
from agent.port_proxy.tunnel import get_tunnel


class PortProxyCloseCheck(Checker):

    def __init__(self):
        self.uid = ""
        self.status = False
        self.error = ""

    def run_check(self, params: Dict[str, Any]) -> None:
        self.uid = str(params.get("uid", ""))
        if not self.uid:
            self.status = False
            self.error = "missing required param: uid"
            return

        tunnel = get_tunnel(self.uid)
        if tunnel is None:
            self.status = True
            return

        tunnel.stop()
        self.status = True

    def get_operation_result(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"status": self.status, "uid": self.uid}
        if not self.status and self.error:
            result["error"] = self.error
        return result
