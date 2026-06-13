from abc import ABC, abstractmethod
from typing import Dict, Any

class Checker(ABC):
    @abstractmethod
    def run_check(self, check_operation_parameter: Dict[str, Any]):
        pass

    @abstractmethod
    def get_operation_result(self) -> Dict[str, Any]:
        pass
