from agent.interfaces.checker_monitor import CheckerMonitor

class MemoryCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.limit = 0
        self.status = False
        self.got_value = -1

    def get_operation_result(self) -> dict:
        return {"status": self.status, "usage": self.got_value}

    def get_operation_name(self) -> str:
        return "mem"

    def parse_result(self, result: str):
        self.got_value = int(result)
        self.status = self.got_value <= self.limit

    def parse_check_parameters(self, check_operation_parameter: dict):
        self.limit = int(check_operation_parameter.get("limit", 0))
