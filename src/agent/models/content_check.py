from agent.interfaces.checker import Checker
from agent.models.user_agent import get_headers
from agent.models.http_session import create_session

class ContentCheck(Checker):
    def __init__(self):
        self.status = False

    def run_check(self, params: dict):
        url = params.get("url", "")
        text = params.get("text", "")
        must_contain = bool(params.get("must_contain", False))

        try:
            with create_session() as session:
                response = session.get(url, headers=get_headers(), timeout=5.0, verify=False)
                content = response.text

            if must_contain:
                self.status = (text in content)
            else:
                self.status = (text not in content)
        except Exception:
            self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status}
