from agent.exceptions import OperationParseException
from agent.operation_controller.models import Operations

from agent.models.ping_check import PingCheck
from agent.models.load_time_check import LoadTimeCheck
from agent.models.port_check import PortCheck
from agent.models.cert_check import CertificateCheck
from agent.models.status_ok_check import StatusOkCheck
from agent.models.content_check import ContentCheck
from agent.models.memory_check import MemoryCheck
from agent.models.uptime_check import UptimeCheck
from agent.models.load_average_check import LoadAverageCheck
from agent.models.disk_usage_check import DiskUsageCheck

class OperationController:
    def start_check(self, json_object: dict) -> dict:
        try:
            op_type, checker = self.create_operation(json_object)
            data_params = json_object.get("data", {})
            checker.run_check(data_params)
            return checker.get_operation_result()
        except OperationParseException:
            return {"status": False}

    def create_operation(self, json_object: dict):
        operation = json_object.get("operation")
        
        mapping = {
            "ping": (Operations.PING, PingCheck),
            "load_time": (Operations.LOAD_TIME, LoadTimeCheck),
            "port_check": (Operations.PORT_OPEN, PortCheck),
            "cert_check": (Operations.CERTIFICATE_OK, CertificateCheck),
            "status_ok": (Operations.STATUS_OK, StatusOkCheck),
            "content_check": (Operations.CONTENT_CHECK, ContentCheck),
            "mem": (Operations.MEMORY, MemoryCheck),
            "uptime": (Operations.UPTIME, UptimeCheck),
            "loadavg": (Operations.LOAD_AVERAGE, LoadAverageCheck),
            "disk": (Operations.DISK_USAGE, DiskUsageCheck),
        }
        
        if operation not in mapping:
            raise OperationParseException()
            
        op_type, checker_class = mapping[operation]
        return op_type, checker_class()
