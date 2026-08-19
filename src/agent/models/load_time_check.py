import time
from agent.interfaces.checker import Checker
from agent.models.http_session import fetch_url

class LoadTimeCheck(Checker):
    def __init__(self):
        self.url = ""
        self.time_limit = 3.0
        self.status = False
        self.time_elapsed = -1.0

    def run_check(self, params: dict):
        self.url = params.get("url", "")
        self.time_limit = float(params.get("limit", 3.0))

        try:
            before = time.time()
            status_code, content = fetch_url(self.url, timeout=5.0)
            after = time.time()

            self.time_elapsed = after - before
            self.status = self.time_elapsed < self.time_limit
        except Exception:
            self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status, "time": self.time_elapsed}
