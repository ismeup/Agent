from agent.interfaces.checker import Checker
from agent.models.user_agent import get_headers
from agent.models.http_session import create_session

class StatusOkCheck(Checker):
    def __init__(self):
        self.url = ""
        self.status = False

    def run_check(self, params: dict):
        self.url = params.get("url", "")
        try:
            with create_session() as session:
                response = session.get(self.url, headers=get_headers(), timeout=5.0, verify=False)
                self.status = (response.status_code == 200)
        except Exception as e:
            print(e)
            self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status}
