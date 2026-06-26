from agent.interfaces.checker_monitor import CheckerMonitor

class CustomBooleanCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.name = ""
        self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status}

    def get_operation_name(self) -> str:
        return "custom"

    def parse_result(self, result: str):
        self.status = result == "true"

    def parse_check_parameters(self, check_operation_parameter: dict):
        self.name = check_operation_parameter.get("name", "")

    def get_request_json(self) -> dict:
        return {"name": self.name}
