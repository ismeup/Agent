from agent.interfaces.checker import Checker
from agent.models.user_agent import get_headers
from agent.models.http_session import fetch_url

class StatusOkCheck(Checker):
    def __init__(self):
        self.url = ""
        self.status = False

    def run_check(self, params: dict):
        self.url = params.get("url", "")
        try:
            status_code, _ = fetch_url(self.url, timeout=5.0, headers=get_headers(), discard_body=True)
            self.status = (status_code == 200)
        except Exception:
            self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status}
