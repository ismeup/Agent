from agent.interfaces.checker_monitor import CheckerMonitor

class DiskUsageCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.disk = ""
        self.limit = 0
        self.status = False
        self.usage = -1

    def get_operation_result(self) -> dict:
        return {"status": self.status, "usage": self.usage}

    def get_operation_name(self) -> str:
        return "disk"

    def parse_result(self, result: str):
        self.usage = int(result)
        self.status = 0 < self.usage < self.limit

    def parse_check_parameters(self, check_operation_parameter: dict):
        self.disk = check_operation_parameter.get("disk", "")
        self.limit = int(check_operation_parameter.get("limit", 0))

    def get_request_json(self) -> dict:
        return {"disk": self.disk}
