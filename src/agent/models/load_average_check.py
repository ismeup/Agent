from enum import Enum
from agent.interfaces.checker_monitor import CheckerMonitor

class LoadAverageType(Enum):
    LA_1 = 1
    LA_5 = 2
    LA_15 = 3

    @staticmethod
    def get_type_from_int(val: int) -> 'LoadAverageType':
        for t in LoadAverageType:
            if t.value == val:
                return t
        return LoadAverageType.LA_1

class LoadAverageCheck(CheckerMonitor):
    def __init__(self):
        super().__init__()
        self.load_average_type = LoadAverageType.LA_1
        self.limit = 0.0
        self.got_load_average = -1.0
        self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status, "loadavg": self.got_load_average}

    def get_operation_name(self) -> str:
        if self.load_average_type == LoadAverageType.LA_5:
            return "la_5"
        elif self.load_average_type == LoadAverageType.LA_15:
            return "la_15"
        return "la_1"

    def parse_result(self, result: str):
        self.got_load_average = float(result)
        self.status = 0 <= self.got_load_average <= self.limit

    def parse_check_parameters(self, check_operation_parameter: dict):
        type_int = int(check_operation_parameter.get("type", 1))
        self.load_average_type = LoadAverageType.get_type_from_int(type_int)
        self.limit = float(check_operation_parameter.get("limit", 0.0))
