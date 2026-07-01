from agent.interfaces.checker_monitor import CheckerMonitor

class CustomDoubleCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.name = ""
        self.limit = 0.0
        self.direction = 1
        self.value = -1.0
        self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status, "value": self.value}

    def get_operation_name(self) -> str:
        return "custom"

    def parse_result(self, result: str):
        self.value = float(result)
        if self.direction == 1:
            self.status = self.value != -1.0 and self.value > self.limit
        else:
            self.status = self.value != -1.0 and self.value < self.limit

    def parse_check_parameters(self, check_operation_parameter: dict):
        self.name = check_operation_parameter.get("name", "")
        self.limit = float(check_operation_parameter.get("limit", 0.0))
        self.direction = int(check_operation_parameter.get("direction", 1))

    def get_request_json(self) -> dict:
        return {"name": self.name}
