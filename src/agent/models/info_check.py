import json
from agent.interfaces.checker_monitor import CheckerMonitor

class InfoCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.version = ""
        self.disks = []
        self.custom_checks = []
        self.status = False

    def get_operation_result(self) -> dict:
        return {
            "status": self.status,
            "version": self.version,
            "disks": self.disks,
            "custom_checks": self.custom_checks,
        }

    def get_operation_name(self) -> str:
        return "info"

    def parse_result(self, result: str):
        data = json.loads(result)
        self.version = data.get("version", "")
        self.disks = data.get("disks", [])
        self.custom_checks = data.get("custom_checks", [])
        self.status = True

    def parse_check_parameters(self, check_operation_parameter: dict):
        pass
