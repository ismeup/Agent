import socket
from agent.interfaces.checker import Checker

class PortCheck(Checker):
    def __init__(self):
        self.host = ""
        self.port = 0
        self.not_empty = False
        self.status = False

    def run_check(self, params: dict):
        self.host = params.get("host", "")
        self.port = int(params.get("port", 0))
        self.not_empty = bool(params.get("notEmpty", False))
        
        sock = None
        try:
            sock = socket.create_connection((self.host, self.port), timeout=2.0)
            if self.not_empty:
                sock.settimeout(2.0)
                data = sock.recv(1)
                self.status = len(data) > 0
            else:
                self.status = True
        except Exception:
            self.status = False
        finally:
            if sock:
                sock.close()

    def get_operation_result(self) -> dict:
        return {"status": self.status}
