from agent.interfaces.checker_monitor import CheckerMonitor

class UptimeCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.remote_uptime = -1
        self.request_uptime = 0
        self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status, "uptime": self.remote_uptime}

    def get_operation_name(self) -> str:
        return "uptime"

    def parse_result(self, result: str):
        self.remote_uptime = int(result)
        self.status = self.remote_uptime > self.request_uptime

    def parse_check_parameters(self, check_operation_parameter: dict):
        self.request_uptime = int(check_operation_parameter.get("uptime", 0))
